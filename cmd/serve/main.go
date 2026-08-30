// cmd/serve — multi-format OpenAI/Claude/Responses gateway for NVIDIA playground.
//
// Embeds CLIProxyAPI with a custom nvidia ProviderExecutor. Upstream predict is
// already OpenAI Chat Completions shape; builtin translators expose:
//
//	POST /v1/chat/completions
//	POST /v1/responses
//	POST /v1/messages
//
// No inbound gateway API keys. Captcha via -auto pool, -captcha, or nv-captcha-token.
//
// Usage:
//
//	go run ./cmd/serve -auto
//	go run ./cmd/serve -auto -pool-size=2 -pool-workers=1 -coalesce-ms=0 -max-inflight=8
//	go run ./cmd/serve -captcha "P1_..."
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"glm52-nvidia/internal/captcha"
	"glm52-nvidia/internal/provider/nvidia"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
)

// Set via -ldflags "-X main.version=v1.2.3" at release build time.
var version = "dev"

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	captchaFlag := flag.String("captcha", "", "one-shot hCaptcha token (consumed on first use)")
	auto := flag.Bool("auto", false, "prewarm captcha tokens via shared Chrome + pool")
	poolSize := flag.Int("pool-size", 3, "ready captcha tokens to keep buffered (-auto)")
	poolWorkers := flag.Int("pool-workers", 1, "concurrent captcha extractors / Chrome processes (-auto); each worker owns one Chrome")
	maxInflight := flag.Int("max-inflight", 4, "max concurrent upstream streams (0=unlimited)")
	inflightWait := flag.Duration("inflight-wait", 500*time.Millisecond, "how long to wait for an in-flight slot before returning 503 (0=reject immediately)")
	coalesceMs := flag.Int("coalesce-ms", 16, "merge consecutive SSE content deltas within this window (0=off); first token always flushes immediately")
	warmTimeout := flag.Duration("warm-timeout", 3*time.Minute, "wait for at least one pooled captcha before serving (-auto); 0=skip")
	poolTTL := flag.Duration("pool-ttl", 90*time.Second, "discard pooled captcha tokens older than this (-auto)")
	captchaWait := flag.Duration("captcha-wait", 30*time.Second, "max wait for a pooled captcha token per request (0=block until ready); then 503")
	modelRefresh := flag.Duration("model-refresh", 6*time.Hour, "re-scrape build.nvidia.com for the playground model catalog on this interval (0=fetch once at startup; <0=keep the compiled-in snapshot)")
	chromeProxy := flag.String("chrome-proxy", "", "proxy for captcha Chrome and upstream API (e.g. socks5://host:port); falls back to CHROME_PROXY")
	flag.Parse()

	if !*auto && *captchaFlag == "" {
		log.Print("warning: no -auto/-captcha; each request must send nv-captcha-token")
	}

	proxyURL := strings.TrimSpace(*chromeProxy)
	if proxyURL == "" {
		proxyURL = strings.TrimSpace(os.Getenv("CHROME_PROXY"))
	}
	proxyFunc := http.ProxyFromEnvironment
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			log.Fatalf("chrome-proxy: invalid URL %q", proxyURL)
		}
		proxyFunc = http.ProxyURL(u)
		log.Printf("upstream + captcha proxy=%s", proxyURL)
	}

	transport := &http.Transport{
		Proxy: proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var (
		browser *captcha.BrowserGroup
		pool    *captcha.Pool
	)
	if *auto {
		var err error
		browser, err = captcha.NewBrowserGroup(ctx, *poolWorkers, captcha.BrowserConfig{
			Proxy: proxyURL,
		})
		if err != nil {
			log.Fatalf("captcha browser: %v", err)
		}
		pool = captcha.NewPool(ctx, browser.Extract, captcha.PoolConfig{
			Size:    *poolSize,
			Workers: *poolWorkers,
			TTL:     *poolTTL,
		})
		defer func() {
			pool.Close()
			browser.Close()
		}()
		log.Printf("captcha pool: size=%d workers=%d chromes=%d ttl=%s captcha-wait=%s",
			*poolSize, *poolWorkers, browser.Len(), *poolTTL, *captchaWait)

		if *warmTimeout > 0 {
			log.Printf("warming captcha pool (timeout=%s)…", *warmTimeout)
			if err := waitPoolReady(ctx, pool, 1, *warmTimeout); err != nil {
				log.Printf("warning: %v — first requests may block on captcha extract", err)
			} else {
				log.Printf("captcha pool ready=%d (TTFT path unblocked)", pool.Ready())
			}
		}
	}

	exec := nvidia.NewExecutor(nvidia.Options{
		Auto:         *auto,
		FlagCaptcha:  *captchaFlag,
		Coalesce:     time.Duration(*coalesceMs) * time.Millisecond,
		MaxInflight:  *maxInflight,
		InflightWait: *inflightWait,
		CaptchaWait:  *captchaWait,
		HTTPClient:   &http.Client{Timeout: 0, Transport: transport},
		Pool:         pool,
	})

	cfg, cfgPath, err := buildConfig(*addr)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	defer os.RemoveAll(cfg.AuthDir)

	tokenStore := sdkAuth.GetTokenStore()
	if dirSetter, ok := tokenStore.(interface{ SetBaseDir(string) }); ok {
		dirSetter.SetBaseDir(cfg.AuthDir)
	}

	catalog := newModelCatalog(nvidia.RegistryModels())
	models := catalog.get()
	authHook := &nvidiaAuthHook{exec: exec, catalog: catalog}
	core := coreauth.NewManager(tokenStore, nil, authHook)
	authHook.core = core
	core.RegisterExecutor(exec)
	// Do NOT Register auth before Run: coreManager.Load() resets from AuthDir.
	// Auth file is written in buildConfig so Load() picks up provider=nvidia.

	// Watcher replaces unknown providers with OpenAICompatExecutor and clears
	// models via UnregisterClient; hooks + reconciler put ours back.
	cliproxy.SetGlobalModelRegistryHook(&nvidiaModelHook{core: core, exec: exec, catalog: catalog})
	bindNvidiaRuntime(core, exec, models)

	hooks := cliproxy.Hooks{
		OnAfterStart: func(_ *cliproxy.Service) {
			ensureNvidiaAuth(core)
			n := bindNvidiaRuntime(core, exec, catalog.get())
			startNvidiaReconciler(ctx, core, exec, catalog)
			if *modelRefresh >= 0 {
				startModelRefresher(ctx, &http.Client{Timeout: 30 * time.Second, Transport: transport}, catalog, core, exec, *modelRefresh)
			}
			log.Printf("serve %s listening on http://localhost%s (models=%d auth=%d; chat/completions + responses + messages; coalesce=%s max-inflight=%d)",
				version, *addr, len(models), n, execCoalesce(*coalesceMs), *maxInflight)
		},
	}

	svc, err := cliproxy.NewBuilder().
		WithConfig(cfg).
		WithConfigPath(cfgPath).
		WithCoreAuthManager(core).
		WithServerOptions(
			// CLIProxyAPI already registers GET/HEAD /healthz; re-registering panics.
			// Install middleware before routes so we can enrich the response with pool stats.
			api.WithEngineConfigurator(func(engine *gin.Engine) {
				engine.Use(func(c *gin.Context) {
					if c.Request.URL.Path != "/healthz" {
						c.Next()
						return
					}
					switch c.Request.Method {
					case http.MethodHead:
						c.Status(http.StatusOK)
						c.Abort()
					case http.MethodGet:
						out := gin.H{"ok": true}
						if p := exec.Pool(); p != nil {
							fills, takes, errs, expired := p.Stats()
							out["pool"] = gin.H{
								"ready":   p.Ready(),
								"fills":   fills,
								"takes":   takes,
								"errors":  errs,
								"expired": expired,
							}
						}
						c.JSON(http.StatusOK, out)
						c.Abort()
					default:
						c.Next()
					}
				})
			}),
		).
		WithHooks(hooks).
		Build()
	if err != nil {
		log.Fatalf("build gateway: %v", err)
	}

	if err := svc.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func execCoalesce(ms int) time.Duration {
	return time.Duration(ms) * time.Millisecond
}

func waitPoolReady(ctx context.Context, pool *captcha.Pool, want int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		if pool.Ready() >= want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("captcha pool still empty after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
