package captcha

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolTakeBlocksUntilFilled(t *testing.T) {
	var n atomic.Int32
	extract := func(ctx context.Context) (string, error) {
		i := n.Add(1)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
		return fmt.Sprintf("tok-%d", i), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewPool(ctx, extract, PoolConfig{Size: 2, Workers: 1})
	defer p.Close()

	takeCtx, takeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer takeCancel()

	tok, err := p.Take(takeCtx)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	fills, takes, errs, expired := p.Stats()
	if takes != 1 {
		t.Fatalf("takes=%d want 1", takes)
	}
	if fills < 1 {
		t.Fatalf("fills=%d want >=1", fills)
	}
	if errs != 0 {
		t.Fatalf("errors=%d", errs)
	}
	if expired != 0 {
		t.Fatalf("expired=%d", expired)
	}
}

func TestPoolDiscardsExpired(t *testing.T) {
	var n atomic.Int32
	extract := func(ctx context.Context) (string, error) {
		i := n.Add(1)
		return fmt.Sprintf("tok-%d", i), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewPool(ctx, extract, PoolConfig{Size: 1, Workers: 1, TTL: 30 * time.Millisecond})
	defer p.Close()

	// Wait until one token is buffered, then let it expire.
	deadline := time.Now().Add(2 * time.Second)
	for p.Ready() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Ready() < 1 {
		t.Fatal("pool never filled")
	}
	time.Sleep(40 * time.Millisecond)

	takeCtx, takeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer takeCancel()
	tok, err := p.Take(takeCtx)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	_, _, _, expired := p.Stats()
	if expired < 1 {
		t.Fatalf("expired=%d want >=1", expired)
	}
}

func TestPoolClosed(t *testing.T) {
	extract := func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := NewPool(ctx, extract, PoolConfig{Size: 1, Workers: 1})
	p.Close()
	cancel()

	_, err := p.Take(context.Background())
	if err == nil {
		t.Fatal("expected error after Close")
	}
}

// Idle: channel fills, tokens age past TTL, reaper drains them so workers
// can refill — without a Take. This is the "chat then wait" failure mode.
func TestPoolReapsStaleDuringIdle(t *testing.T) {
	var n atomic.Int32
	extract := func(ctx context.Context) (string, error) {
		return fmt.Sprintf("tok-%d", n.Add(1)), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewPool(ctx, extract, PoolConfig{Size: 2, Workers: 1, TTL: 200 * time.Millisecond})
	defer p.Close()

	deadline := time.Now().Add(2 * time.Second)
	for p.Ready() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p.Ready() < 2 {
		t.Fatal("pool never filled")
	}
	fillsBefore, _, _, _ := p.Stats()

	// Past hard TTL and several reaper ticks (ttl/4, min 100ms).
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fills, _, _, expired := p.Stats()
		if expired >= 1 && fills > fillsBefore {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fillsAfter, _, _, expired := p.Stats()
	t.Fatalf("idle reap did not refresh: fills %d→%d expired=%d ready=%d",
		fillsBefore, fillsAfter, expired, p.Ready())
}

// Fresh tokens must not be evacuated by the reaper — that races workers into
// idle mint churn (fills climbing while takes stay 0).
func TestPoolReaperNoChurnWhileFresh(t *testing.T) {
	var n atomic.Int32
	extract := func(ctx context.Context) (string, error) {
		return fmt.Sprintf("tok-%d", n.Add(1)), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewPool(ctx, extract, PoolConfig{Size: 2, Workers: 1, TTL: 5 * time.Second})
	defer p.Close()

	deadline := time.Now().Add(2 * time.Second)
	for p.Ready() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Ready() < 2 {
		t.Fatal("pool never filled")
	}
	fillsBefore, _, _, _ := p.Stats()

	// Several reaper ticks (ttl/4 = 1.25s, capped logic → 1.25s) while still fresh.
	time.Sleep(800 * time.Millisecond)
	_ = p.discardStale() // force one pass
	time.Sleep(200 * time.Millisecond)

	fillsAfter, takes, _, expired := p.Stats()
	if takes != 0 {
		t.Fatalf("takes=%d want 0", takes)
	}
	if expired != 0 {
		t.Fatalf("expired=%d want 0", expired)
	}
	if fillsAfter != fillsBefore {
		t.Fatalf("idle churn: fills %d→%d (reaper must not wake mint while fresh)", fillsBefore, fillsAfter)
	}
	if p.Ready() != 2 {
		t.Fatalf("ready=%d want 2", p.Ready())
	}
}

func TestPoolWorkersReserveCapacityBeforeExtract(t *testing.T) {
	var started atomic.Int32
	release := make(chan struct{})
	extract := func(ctx context.Context) (string, error) {
		n := started.Add(1)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return fmt.Sprintf("tok-%d", n), nil
		}
	}

	p := NewPool(context.Background(), extract, PoolConfig{Size: 1, Workers: 4})
	defer p.Close()
	deadline := time.Now().Add(time.Second)
	for started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// Give every worker a chance to race for the single slot.
	time.Sleep(30 * time.Millisecond)
	if got := started.Load(); got != 1 {
		t.Fatalf("extracts started=%d want 1 for one reserved slot", got)
	}
	close(release)
}

func TestPoolTakeWakesImmediatelyOnFill(t *testing.T) {
	release := make(chan struct{})
	extract := func(ctx context.Context) (string, error) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "tok", nil
		}
	}

	p := NewPool(context.Background(), extract, PoolConfig{Size: 1, Workers: 1})
	defer p.Close()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_, _ = p.Take(context.Background())
		done <- time.Since(start)
	}()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	close(release)
	select {
	case <-done:
		if delay := time.Since(start); delay > 50*time.Millisecond {
			t.Fatalf("Take wake delay=%s want <=50ms", delay)
		}
	case <-time.After(time.Second):
		t.Fatal("Take did not wake after fill")
	}
}

func TestPoolTakeCanceledDoesNotConsumeReadyToken(t *testing.T) {
	p := NewPool(context.Background(), func(context.Context) (string, error) {
		return "tok", nil
	}, PoolConfig{Size: 1, Workers: 1})
	defer p.Close()
	deadline := time.Now().Add(time.Second)
	for p.Ready() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Take(ctx); err == nil {
		t.Fatal("Take with canceled context succeeded")
	}
	if got := p.Ready(); got != 1 {
		t.Fatalf("ready=%d want 1 after canceled Take", got)
	}
}

func TestPoolTakeAfterCloseDoesNotConsumeReadyToken(t *testing.T) {
	p := NewPool(context.Background(), func(context.Context) (string, error) {
		return "tok", nil
	}, PoolConfig{Size: 1, Workers: 1})
	deadline := time.Now().Add(time.Second)
	for p.Ready() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	p.Close()
	if _, err := p.Take(context.Background()); err == nil {
		t.Fatal("Take after Close succeeded")
	}
	if got := p.Ready(); got != 1 {
		t.Fatalf("ready=%d want 1 after closed Take", got)
	}
}

func TestPoolTokenLease_ReleaseRestoresEntry(t *testing.T) {
	p := newStaticPool(t,
		entry{token: "oldest", at: time.Now().Add(-time.Second)},
		entry{token: "newest", at: time.Now()},
	)

	lease, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease: %v", err)
	}
	if got := lease.Token(); got != "oldest" {
		t.Fatalf("Token=%q want oldest", got)
	}
	if got := p.Ready(); got != 1 {
		t.Fatalf("ready=%d want 1 while leased", got)
	}

	lease.Release()
	if got := p.Ready(); got != 2 {
		t.Fatalf("ready=%d want 2 after release", got)
	}
	_, takes, _, _ := p.Stats()
	if takes != 0 {
		t.Fatalf("takes=%d want 0 after release", takes)
	}

	token, err := p.Take(context.Background())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if token != "oldest" {
		t.Fatalf("Take=%q want oldest (original FIFO order)", token)
	}
	_, takes, _, _ = p.Stats()
	if takes != 1 {
		t.Fatalf("takes=%d want 1 after Take commits lease", takes)
	}
}

func TestPoolTokenLease_CommitAllowsRefill(t *testing.T) {
	var calls atomic.Int32
	secondStarted := make(chan struct{})
	secondRelease := make(chan struct{})
	extract := func(ctx context.Context) (string, error) {
		call := calls.Add(1)
		if call == 1 {
			return "first", nil
		}
		close(secondStarted)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-secondRelease:
			return "second", nil
		}
	}

	p := NewPool(context.Background(), extract, PoolConfig{Size: 1, Workers: 1})
	defer p.Close()
	lease, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease: %v", err)
	}
	if got := p.Ready(); got != 0 {
		t.Fatalf("ready=%d want 0 while leased", got)
	}
	p.mu.Lock()
	leased := p.leased
	reserved := p.reserved
	p.mu.Unlock()
	if leased != 1 || reserved != 0 {
		t.Fatalf("leased=%d reserved=%d want 1,0", leased, reserved)
	}
	select {
	case <-secondStarted:
		t.Fatal("worker refilled before lease commit")
	default:
	}

	if !lease.Commit() {
		t.Fatal("Commit rejected fresh token")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not refill after lease commit")
	}
	close(secondRelease)
}

func TestPoolTokenLease_FinalizeOnce(t *testing.T) {
	tests := []struct {
		name     string
		finalize func(*TokenLease)
	}{
		{
			name: "commit then release",
			finalize: func(lease *TokenLease) {
				lease.Commit()
				lease.Release()
			},
		},
		{
			name: "release then commit",
			finalize: func(lease *TokenLease) {
				lease.Release()
				lease.Commit()
			},
		},
		{
			name: "concurrent commit and release",
			finalize: func(lease *TokenLease) {
				start := make(chan struct{})
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					lease.Commit()
				}()
				go func() {
					defer wg.Done()
					<-start
					lease.Release()
				}()
				close(start)
				wg.Wait()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newStaticPool(t, entry{token: "token", at: time.Now()})
			lease, err := p.TakeLease(context.Background())
			if err != nil {
				t.Fatalf("TakeLease: %v", err)
			}

			tt.finalize(lease)

			p.mu.Lock()
			leased := p.leased
			total := len(p.tokens) + p.reserved + p.leased
			p.mu.Unlock()
			if leased != 0 {
				t.Fatalf("leased=%d want 0", leased)
			}
			if total > p.size {
				t.Fatalf("capacity=%d exceeds size=%d", total, p.size)
			}
			_, takes, _, _ := p.Stats()
			if takes > 1 {
				t.Fatalf("takes=%d want <=1", takes)
			}
		})
	}
}

func TestPoolTokenLease_ExpiredReleaseIsDiscarded(t *testing.T) {
	p := newStaticPool(t, entry{token: "token", at: time.Now()})
	lease, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease: %v", err)
	}
	lease.entry.at = time.Now().Add(-2 * p.ttl)

	lease.Release()
	lease.Release()

	if got := p.Ready(); got != 0 {
		t.Fatalf("ready=%d want 0", got)
	}
	_, takes, _, expired := p.Stats()
	if takes != 0 {
		t.Fatalf("takes=%d want 0", takes)
	}
	if expired != 1 {
		t.Fatalf("expired=%d want 1", expired)
	}
}

func TestPoolTokenLease_CommitRejectsTokenExpiredWhileLeased(t *testing.T) {
	p := newStaticPool(t, entry{token: "expired", at: time.Now()})
	lease, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease: %v", err)
	}
	lease.entry.at = time.Now().Add(-2 * p.ttl)

	if lease.Commit() {
		t.Fatal("Commit succeeded for token expired while leased")
	}

	_, takes, _, expired := p.Stats()
	if takes != 0 {
		t.Fatalf("takes=%d want 0 for token expired before commit", takes)
	}
	if expired != 1 {
		t.Fatalf("expired=%d want 1", expired)
	}
}

func TestPoolTokenLease_ReleaseRestoresEqualTimestampFIFO(t *testing.T) {
	at := time.Now()
	p := newStaticPool(t,
		entry{token: "first", at: at},
		entry{token: "second", at: at},
	)
	p.tokens[0].order = 1
	p.tokens[1].order = 2
	first, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease first: %v", err)
	}
	second, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease second: %v", err)
	}

	second.Release()
	first.Release()

	for _, want := range []string{"first", "second"} {
		got, takeErr := p.Take(context.Background())
		if takeErr != nil {
			t.Fatalf("Take: %v", takeErr)
		}
		if got != want {
			t.Fatalf("Take=%q want %q (original FIFO order)", got, want)
		}
	}
}

func TestPoolTokenLease_ReleaseAfterCloseIsDiscarded(t *testing.T) {
	p := newStaticPool(t, entry{token: "token", at: time.Now()})
	lease, err := p.TakeLease(context.Background())
	if err != nil {
		t.Fatalf("TakeLease: %v", err)
	}
	p.Close()

	lease.Release()
	lease.Commit()

	if got := p.Ready(); got != 0 {
		t.Fatalf("ready=%d want 0", got)
	}
	p.mu.Lock()
	leased := p.leased
	p.mu.Unlock()
	if leased != 0 {
		t.Fatalf("leased=%d want 0", leased)
	}
}

func newStaticPool(t *testing.T, entries ...entry) *Pool {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for i := range entries {
		entries[i].order = uint64(i)
	}
	return &Pool{
		size:      len(entries),
		ttl:       time.Minute,
		tokens:    entries,
		nextOrder: uint64(len(entries)),
		changed:   make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}
