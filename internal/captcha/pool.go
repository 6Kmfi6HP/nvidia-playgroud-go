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
type Pool struct {
	extract ExtractFunc
	size    int
	ttl     time.Duration

	mu        sync.Mutex
	tokens    []entry
	reserved  int // workers currently minting for an available slot
	leased    int // tokens held by callers but still occupying capacity
	nextOrder uint64
	changed   chan struct{} // closed/replaced whenever queue capacity or data changes

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	fills   atomic.Uint64
	takes   atomic.Uint64
	errors  atomic.Uint64
	expired atomic.Uint64
}

// PoolConfig controls prewarm depth and parallelism.
type PoolConfig struct {
	Size    int           // buffered ready tokens (default 2)
	Workers int           // concurrent extractors (default 1)
	TTL     time.Duration // max age before a pooled token is discarded (default 90s)
}

// NewPool starts background workers that keep tokens filled up to Size.
// extract must be safe for concurrent use up to Workers (e.g. Browser.Extract).
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
	ctx, cancel := context.WithCancel(parent)
	p := &Pool{
		extract: extract,
		size:    cfg.Size,
		tokens:  make([]entry, 0, cfg.Size),
		changed: make(chan struct{}),
		ttl:     cfg.TTL,
		ctx:     ctx,
		cancel:  cancel,
	}
	for i := 0; i < cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
	p.wg.Add(1)
	go p.reaper()
	return p
}

func (p *Pool) worker(id int) {
	defer p.wg.Done()
	var consecFailures int
	for {
		if !p.reserveSlot() {
			return
		}

		token, err := p.extract(p.ctx)
		if err != nil {
			p.releaseReservation()
			p.errors.Add(1)
			consecFailures++
			if p.ctx.Err() != nil {
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
			case <-p.ctx.Done():
				return
			}
			continue
		}

		consecFailures = 0
		if !p.enqueue(token) {
			return
		}
	}
}

// reserveSlot blocks until queue capacity is available, then claims it before
// extraction. The reservation prevents concurrent workers from over-minting.
func (p *Pool) reserveSlot() bool {
	for {
		p.mu.Lock()
		if p.ctx.Err() != nil {
			p.mu.Unlock()
			return false
		}
		if len(p.tokens)+p.reserved+p.leased < p.size {
			p.reserved++
			p.mu.Unlock()
			return true
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-p.ctx.Done():
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

func (p *Pool) enqueue(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserved--
	if p.ctx.Err() != nil {
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
func (p *Pool) reaper() {
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
		case <-p.ctx.Done():
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
// lease is committed or released.
func (p *Pool) TakeLease(ctx context.Context) (*TokenLease, error) {
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, fmt.Errorf("captcha pool closed")
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
			p.mu.Unlock()
			return &TokenLease{pool: p, entry: e}, nil
		}
		changed := p.changed
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.ctx.Done():
			return nil, fmt.Errorf("captcha pool closed")
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

// Close stops workers and drains the browser-facing extract loop.
func (p *Pool) Close() {
	p.cancel()
	p.wg.Wait()
}
