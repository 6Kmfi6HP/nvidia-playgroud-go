package captcha

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsHardExtractFailure(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("temporary glitch"), false},
		{fmt.Errorf("empty captcha token — headless Chrome may be blocked"), true},
		{fmt.Errorf("sticky execute failed (x); re-navigate failed: y"), true},
		{fmt.Errorf("hcaptcha global not ready (bot detection or page change?)"), true},
		{fmt.Errorf("chromedp navigate: timeout"), true},
		{fmt.Errorf("captcha token did not refresh after execute({async:true})"), true},
	}
	for _, tc := range cases {
		if got := isHardExtractFailure(tc.err); got != tc.want {
			t.Fatalf("isHardExtractFailure(%v)=%v want %v", tc.err, got, tc.want)
		}
	}
}

func TestBrowserGroupRecycle_CloseDuringFactory(t *testing.T) {
	// Given
	old, _ := newTrackedBrowser()
	candidate, candidateCloses := newTrackedBrowser()
	factoryStarted := make(chan struct{})
	allowFactory := make(chan struct{})
	g := &BrowserGroup{
		parent:   context.Background(),
		browsers: []*Browser{old},
		free:     make(chan *Browser, 1),
		done:     make(chan struct{}),
		browserFactory: func(context.Context, BrowserConfig) (*Browser, error) {
			close(factoryStarted)
			<-allowFactory
			return candidate, nil
		},
	}

	type recycleResult struct {
		browser *Browser
		err     error
	}
	recycleDone := make(chan recycleResult, 1)

	// When
	go func() {
		browser, err := g.recycle(old)
		recycleDone <- recycleResult{browser: browser, err: err}
	}()
	select {
	case <-factoryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("factory did not start")
	}

	closeDone := make(chan struct{})
	go func() {
		g.Close()
		close(closeDone)
	}()

	// Then
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked while browser factory was running")
	}
	close(allowFactory)

	select {
	case result := <-recycleDone:
		if result.browser != nil {
			t.Fatalf("recycle browser = %p, want nil", result.browser)
		}
		if result.err == nil || !strings.Contains(result.err.Error(), "captcha browser group closed") {
			t.Fatalf("recycle error = %v, want group closed", result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recycle did not return after factory completed")
	}
	if got := candidateCloses.Load(); got != 1 {
		t.Fatalf("candidate close count = %d, want 1", got)
	}
	if g.browsers[0] != old {
		t.Fatal("closed group committed candidate browser")
	}
}

func TestBrowserGroupRecycle_CloseOutsideLock(t *testing.T) {
	// Given
	closeStarted := make(chan struct{})
	allowClose := make(chan struct{})
	var oldCloses atomic.Int32
	old := &Browser{
		cancel: func() {
			oldCloses.Add(1)
			close(closeStarted)
			<-allowClose
		},
	}
	candidate, _ := newTrackedBrowser()
	g := &BrowserGroup{
		parent:   context.Background(),
		browsers: []*Browser{old},
		free:     make(chan *Browser, 1),
		done:     make(chan struct{}),
		browserFactory: func(context.Context, BrowserConfig) (*Browser, error) {
			return candidate, nil
		},
	}

	recycleDone := make(chan error, 1)

	// When
	go func() {
		_, err := g.recycle(old)
		recycleDone <- err
	}()
	select {
	case <-closeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("old browser Close did not start")
	}

	lenDone := make(chan int, 1)
	go func() {
		lenDone <- g.Len()
	}()

	// Then
	select {
	case got := <-lenDone:
		if got != 1 {
			t.Fatalf("Len() = %d, want 1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Len blocked while old browser Close was running")
	}
	close(allowClose)
	select {
	case err := <-recycleDone:
		if err != nil {
			t.Fatalf("recycle error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recycle did not return after old browser closed")
	}
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old browser close count = %d, want 1", got)
	}
}

func TestBrowserGroupRecycle_OnlyOneConcurrentCommit(t *testing.T) {
	// Given
	old, oldCloses := newTrackedBrowser()
	first, firstCloses := newTrackedBrowser()
	second, secondCloses := newTrackedBrowser()
	factoryStarted := make(chan struct{}, 2)
	allowFactory := make(chan struct{})
	var factoryCalls atomic.Int32
	g := &BrowserGroup{
		parent:   context.Background(),
		browsers: []*Browser{old},
		free:     make(chan *Browser, 1),
		done:     make(chan struct{}),
		browserFactory: func(context.Context, BrowserConfig) (*Browser, error) {
			call := factoryCalls.Add(1)
			factoryStarted <- struct{}{}
			<-allowFactory
			if call == 1 {
				return first, nil
			}
			return second, nil
		},
	}

	type recycleResult struct {
		browser *Browser
		err     error
	}
	results := make(chan recycleResult, 2)

	// When
	for range 2 {
		go func() {
			browser, err := g.recycle(old)
			results <- recycleResult{browser: browser, err: err}
		}()
	}
	for range 2 {
		select {
		case <-factoryStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("both browser factories did not start")
		}
	}
	close(allowFactory)

	// Then
	var success, stale int
	for range 2 {
		select {
		case result := <-results:
			if result.err == nil {
				success++
				if result.browser != first && result.browser != second {
					t.Fatalf("unexpected committed browser %p", result.browser)
				}
				continue
			}
			if !strings.Contains(result.err.Error(), "browser not in group") {
				t.Fatalf("recycle error = %v, want stale replacement error", result.err)
			}
			stale++
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent recycle did not return")
		}
	}
	if success != 1 || stale != 1 {
		t.Fatalf("recycle results: success=%d stale=%d, want 1 each", success, stale)
	}
	if got := oldCloses.Load(); got != 1 {
		t.Fatalf("old browser close count = %d, want 1", got)
	}
	if got := firstCloses.Load() + secondCloses.Load(); got != 1 {
		t.Fatalf("candidate close count = %d, want 1", got)
	}
	if g.browsers[0] != first && g.browsers[0] != second {
		t.Fatal("group does not contain a factory candidate")
	}
	if g.browsers[0].closed {
		t.Fatal("committed candidate was closed")
	}
}

func newTrackedBrowser() (*Browser, *atomic.Int32) {
	var closes atomic.Int32
	return &Browser{cancel: func() { closes.Add(1) }}, &closes
}
