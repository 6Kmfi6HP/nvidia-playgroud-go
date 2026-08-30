package captcha

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// backoff schedule on extract failure. Starts small, caps so a sustained
// captcha-block doesn't busy-loop or spam logs. Reset to zero on success.
const (
	backoffMin    = 1 * time.Second
	backoffMax    = 30 * time.Second
	backoffJitter = 250 * time.Millisecond // ±25% via Int63n below
	// log every N consecutive failures instead of each one, so a persistent
	// captcha outage does not flood logs.
	logEveryNth = 10
)

// ExtractFunc obtains one one-shot captcha token.
type ExtractFunc func(ctx context.Context) (string, error)

type entry struct {
	token string
	at    time.Time
	order uint64
}

// TokenLease holds a pooled token until the caller knows whether it was sent.
// A lease can be finalized once: Commit consumes the token, while Release
// returns a still-valid token to its original FIFO position.
type TokenLease struct {
	pool  *Pool
	entry entry
	once  sync.Once
	used  bool
}

// Token returns the leased one-shot token.
func (l *TokenLease) Token() string {
	return l.entry.token
}

// Commit consumes a token only if it is still fresh at the commit boundary.
func (l *TokenLease) Commit() bool {
	l.once.Do(func() {
		l.used = l.pool.finalizeLease(l.entry, false)
	})
	return l.used
}

// Release returns the token to the pool if it is still open and the original
// token timestamp is still within TTL.
func (l *TokenLease) Release() {
	l.once.Do(func() {
		l.pool.finalizeLease(l.entry, true)
	})
}

// Pool pre-warms one-shot captcha tokens so request handlers can Take without
// waiting on a full browser navigate.
// Tokens older than TTL are discarded on Take (hCaptcha tokens expire ~2–3 min).
//
// A background reaper discards stale buffered tokens during idle so workers are
// not stuck behind a full buffer of expired entries (the "chat, then wait,
// then request hangs" failure mode).
//
// Workers wait for buffer space *before* minting. Combined with a mutex-backed
// FIFO (not a channel drain/restore), a full fresh pool truly idles Chrome —
// see runs/hangbench-2026-07-22.md.
//
// With IdleTimeout set, the pool also stops itself after that long without a
// successful take: workers and reaper exit and buffered tokens are dropped,
// so an idle service pays zero solver cost (PoW solves / Chrome navigations)
// between requests. The next TakeLease restarts the pool on demand.
type Pool struct {
	extract     ExtractFunc
	size        int
	workers     int
	ttl         time.Duration
	idleTimeout time.Duration

	mu        sync.Mutex
	tokens    []entry
	reserved  int // workers currently minting for an available slot
	leased    int // tokens held by callers but still occupying capacity
	nextOrder uint64
	changed   chan struct{} // closed/replaced whenever queue capacity or data changes

	// Lifecycle state below is read/written under mu; start/stop transitions
	// additionally serialize on stateMu so a restart can never Add to the
	// WaitGroup while Close is Waiting on it.
	parent  context.Context // original constructor parent, used to regrow contexts
	stateMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	closed  bool
	genDone chan struct{} // closed when the current generation shuts down

	lastTake atomic.Int64 // unixNano of the last successful lease grant

	wg sync.WaitGroup

	fills   atomic.Uint64
	takes   atomic.Uint64
	errors  atomic.Uint64
	expired atomic.Uint64
}

// PoolConfig controls prewarm depth, parallelism, and idle shutdown.
type PoolConfig struct {
	Size        int           // buffered ready tokens (default 2)
	Workers     int           // concurrent extractors (default 1)
	TTL         time.Duration // max age before a pooled token is discarded (default 90s)
	IdleTimeout time.Duration // stop the pool after this long without a take (0 disables); the next take restarts it
}

// NewPool starts background workers that keep tokens filled up to Size.
// extract must be safe for concurrent use up to Workers (e.g. PowExtract()).
func NewPool(parent context.Context, extract ExtractFunc, cfg PoolConfig) *Pool {
	if cfg.Size < 1 {
		cfg.Size = 2
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 90 * time.Second
	}
	p := &Pool{
		extract:     extract,
		size:        cfg.Size,
		workers:     cfg.Workers,
		tokens:      make([]entry, 0, cfg.Size),
		changed:     make(chan struct{}),
		ttl:         cfg.TTL,
		idleTimeout: cfg.IdleTimeout,
		parent:      parent,
	}
	p.start() // construction only: no concurrent access yet
	return p
}

// start launches a fresh generation of workers, reaper, and (when configured)
// the idle watchdog. Callers must hold stateMu and mu so the channels/context
// it replaces are never swapped under a concurrent reader. Launched goroutines
// capture this generation's ctx, so an older generation always exits on its
// own cancellation even if the live generation has since been replaced.
func (p *Pool) start() {
	ctx, cancel := context.WithCancel(p.parent)
	p.ctx = ctx
	p.cancel = cancel
	p.changed = make(chan struct{})
	p.genDone = make(chan struct{})
	p.running = true
	p.lastTake.Store(time.Now().UnixNano())
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i, ctx)
	}
	p.wg.Add(1)
	go p.reaper(ctx)
	if p.idleTimeout > 0 {
		p.wg.Add(1)
		go p.idleMonitor(ctx)
	}
}

// shutdownLocked ends the current generation without waiting for its
// goroutines (they exit on the canceled generation ctx). p.mu must be held.
// With dropTokens (idle watchdog), buffered tokens are cleared: a restarted
// pool should mint fresh ones instead of inheriting near-TTL entries. Close
// keeps them so a closed pool never consumes a token it already handed out.
func (p *Pool) shutdownLocked(dropTokens bool) {
	p.cancel()
	p.running = false
	close(p.genDone)
	if dropTokens {
		p.tokens = p.tokens[:0]
		p.nextOrder = 0
	}
}

func (p *Pool) worker(id int, genCtx context.Context) {
	defer p.wg.Done()
	var consecFailures int
	for {
		if !p.reserveSlot(genCtx) {
			return
		}

		token, err := p.extract(genCtx)
		if err != nil {
			p.releaseReservation()
			p.errors.Add(1)
			consecFailures++
			if genCtx.Err() != nil {
				return
			}
			// Exponential backoff with jitter — a sustained captcha outage
			// must not busy-loop (fixed 2s did) nor drown the logs. Log the
			// first failure immediately (pool-empty hangs are otherwise silent),
			// then every Nth. Reset on success below.
			if consecFailures == 1 || consecFailures%logEveryNth == 0 {
				log.Printf("captcha pool worker %d: %v (consecutive failures=%d, backing off)",
					id, err, consecFailures)
			}
			backoff := backoffFor(consecFailures)
			select {
			case <-time.After(backoff):
			case <-genCtx.Done():
				return
			}
			continue
		}

		consecFailures = 0
		if !p.enqueue(token, genCtx) {
			return
		}
	}
}

// reserveSlot blocks until queue capacity is available, then claims it before
// extraction. The reservation prevents concurrent workers from over-minting.
func (p *Pool) reserveSlot(genCtx context.Context) bool {
	for {
		p.mu.Lock()
		if genCtx.Err() != nil || !p.running {
			p.mu.Unlock()
			return false
		}
		if len(p.tokens)+p.reserved+p.leased < p.size {
			p.reserved++
			p.mu.Unlock()
			return true
		}
		// This generation's channels: if the pool is shut down while we wait
		// (idle watchdog), genDone wakes us and we exit instead of waiting on
		// a channel that the next generation replaces.
		genDone := p.genDone
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-genCtx.Done():
			return false
		case <-genDone:
			return false
		case <-changed:
		}
	}
}

func (p *Pool) releaseReservation() {
	p.mu.Lock()
	p.reserved--
	p.notifyLocked()
	p.mu.Unlock()
}

func (p *Pool) enqueue(token string, genCtx context.Context) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved--
	if genCtx.Err() != nil || !p.running {
		p.notifyLocked()
		return false
	}
	p.tokens = append(p.tokens, entry{token: token, at: time.Now(), order: p.nextOrder})
	p.nextOrder++
	p.fills.Add(1)
	p.notifyLocked()
	return true
}

// notifyLocked wakes waiters without polling. p.mu must be held.
func (p *Pool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

// reaper drops expired FIFO-front entries during idle so workers can refill.
func (p *Pool) reaper(genCtx context.Context) {
	defer p.wg.Done()
	interval := p.ttl / 4
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastLog time.Time
	for {
		select {
		case <-genCtx.Done():
			return
		case <-t.C:
			n := p.discardStale()
			if n == 0 {
				continue
			}
			// Rate-limit: idle pools otherwise log every tick while workers refill.
			if time.Since(lastLog) < time.Minute && p.Ready() > 0 {
				continue
			}
			lastLog = time.Now()
			log.Printf("captcha pool: reaped %d stale token(s); ready=%d (workers refill)", n, p.Ready())
		}
	}
}

// discardStale drops only expired entries from the FIFO front without touching
// fresh tokens (inspect under mutex — no evacuate/restore race).
func (p *Pool) discardStale() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for len(p.tokens) > 0 && time.Since(p.tokens[0].at) > p.ttl {
		p.tokens = p.tokens[1:]
		p.expired.Add(1)
		n++
	}
	if n > 0 {
		p.notifyLocked()
	}
	return n
}

// idleMonitor stops the pool once IdleTimeout has passed without a successful
// take, so an idle service stops paying solver cost (PoW solves / Chrome
// navigations). The next TakeLease restarts it on demand. It only fires when
// nothing is in flight (no leases, no reservations), and re-checks under both
// locks so a racing take/restart cancels the shutdown.
func (p *Pool) idleMonitor(genCtx context.Context) {
	defer p.wg.Done()
	interval := p.idleTimeout / 4
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-genCtx.Done():
			return
		case <-t.C:
			last := time.Unix(0, p.lastTake.Load())
			if time.Since(last) < p.idleTimeout {
				continue // cheap filter; take may land any moment
			}
			p.stateMu.Lock()
			p.mu.Lock()
			active := !p.running || p.leased > 0 || p.reserved > 0 ||
				time.Since(time.Unix(0, p.lastTake.Load())) < p.idleTimeout
			if !active {
				log.Printf("captcha pool: no takes for %s; stopped %d worker(s), dropped %d buffered token(s) (restarts on next take)",
					p.idleTimeout, p.workers, len(p.tokens))
				p.shutdownLocked(true)
			}
			p.mu.Unlock()
			p.stateMu.Unlock()
		}
	}
}

// backoffFor computes 2^n * backoffMin capped at backoffMax, ±jitter.
// n=1 → ~1s, n=4 → ~8s, n≥5 → capped near 30s.
func backoffFor(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := backoffMin
	for i := 1; i < n; i++ {
		d *= 2
		if d >= backoffMax {
			d = backoffMax
			break
		}
	}
	jitter := time.Duration(rand.Int63n(int64(2*backoffJitter))) - backoffJitter
	d += jitter
	if d < 0 {
		d = 0
	}
	return d
}

// TakeLease returns a prewarmed token that remains pool capacity until its
// lease is committed or released. If the pool is stopped (idle watchdog) it is
// restarted on demand here, so callers never see "closed" between requests.
func (p *Pool) TakeLease(ctx context.Context) (*TokenLease, error) {
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if p.closed || p.parent.Err() != nil {
			p.mu.Unlock()
			return nil, fmt.Errorf("captcha pool closed")
		}
		if !p.running {
			// Pool was stopped by the idle watchdog. Restart before waiting so
			// an idle service pays zero solver cost between requests. stateMu
			// serializes this against Close's WaitGroup wait.
			p.mu.Unlock()
			p.stateMu.Lock()
			p.mu.Lock()
			if !p.closed && !p.running && p.parent.Err() == nil {
				p.start()
				log.Printf("captcha pool: restarted on demand")
			}
			p.mu.Unlock()
			p.stateMu.Unlock()
			continue
		}
		if len(p.tokens) > 0 {
			e := p.tokens[0]
			p.tokens = p.tokens[1:]
			if time.Since(e.at) > p.ttl {
				p.expired.Add(1)
				p.notifyLocked()
				p.mu.Unlock()
				continue
			}
			p.leased++
			p.lastTake.Store(time.Now().UnixNano())
			p.mu.Unlock()
			return &TokenLease{pool: p, entry: e}, nil
		}
		// This generation's channels only: if the pool is shut down while we
		// wait, genDone wakes this select and the loop re-evaluates (restart or
		// closed) instead of hanging on a channel the next generation replaced.
		genDone := p.genDone
		changed := p.changed
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-genDone:
		case <-changed:
		}
	}
}

// Take preserves the original consume-on-take API.
func (p *Pool) Take(ctx context.Context) (string, error) {
	for {
		lease, err := p.TakeLease(ctx)
		if err != nil {
			return "", err
		}
		token := lease.Token()
		if lease.Commit() {
			return token, nil
		}
	}
}

func (p *Pool) finalizeLease(e entry, release bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.leased--
	if !release {
		if time.Since(e.at) > p.ttl {
			p.expired.Add(1)
			p.notifyLocked()
			return false
		}
		p.takes.Add(1)
		p.notifyLocked()
		return true
	}
	if p.ctx.Err() != nil {
		p.notifyLocked()
		return false
	}
	if time.Since(e.at) > p.ttl {
		p.expired.Add(1)
		p.notifyLocked()
		return false
	}

	i := 0
	for i < len(p.tokens) && p.tokens[i].order < e.order {
		i++
	}
	p.tokens = append(p.tokens, entry{})
	copy(p.tokens[i+1:], p.tokens[i:])
	p.tokens[i] = e
	p.notifyLocked()
	return false
}

// Stats returns fill/take/error/expired counters for experiments.
func (p *Pool) Stats() (fills, takes, errors, expired uint64) {
	return p.fills.Load(), p.takes.Load(), p.errors.Load(), p.expired.Load()
}

// Ready returns how many tokens are currently buffered (may include soon-to-expire).
func (p *Pool) Ready() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tokens)
}

// Close permanently stops the pool. Takes after Close fail with
// "captcha pool closed" (no auto-restart). Idle Watchdog shutdowns do not go
// through Close, so a closed pool can never be restarted.
func (p *Pool) Close() {
	p.stateMu.Lock()
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		if p.running {
			p.shutdownLocked(false)
		}
	}
	p.mu.Unlock()
	// Wait outside mu (workers/reaper lock mu while draining); stateMu blocks
	// concurrent restarts from Adding to the WaitGroup during the wait.
	p.wg.Wait()
	p.stateMu.Unlock()
}
