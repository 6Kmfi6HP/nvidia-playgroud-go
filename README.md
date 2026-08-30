# nvidia-playgroud-go — NVIDIA Build Playground 多模型 Go 客户端 + 多格式网关

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Models](https://img.shields.io/badge/Models-11_build.nvidia.com-orange)](https://build.nvidia.com/models)
[![Captcha](https://img.shields.io/badge/Captcha-Pure_Go_hCaptcha_PoW-753B?logo=hCaptcha&logoColor=white)](#方式-2纯-go-hcaptcha-pow-求解默认无浏览器)
[![OpenAI Compatible](https://img.shields.io/badge/API-OpenAI_Compatible-412991?logo=openai&logoColor=white)](#方式-3多格式本地代理cliproxyapi)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white)](#docker-部署)
[![Status](https://img.shields.io/badge/Status-Reverse_Engineered-yellow)](#逆向分析报告)
![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

> **English:** A reverse-engineered Go client and multi-format reverse proxy for **NVIDIA Build Playground** (build.nvidia.com). It is **multi-model**: the registry seeds 11 anonymous playground models (DeepSeek, Kimi, MiniMax, Nemotron, …), refreshes the catalog at runtime by re-scraping the live SSR page, and routes every request to the matching predict endpoint with the per-model `nv-function-id`. hCaptcha credentials are minted by a **pure-Go PoW solver** (embedded V8, no browser), prewarmed into a token pool. The gateway embeds [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) to expose OpenAI Chat Completions, OpenAI Responses and Claude Messages, plus Docker deployments and SSE/latency benchmarks. Inbound gateway API keys are **not** enabled.
>
> 历史上的默认模型 `z-ai/glm-5.2` 已于 2026-08 被 NVIDIA 从匿名目录移除（后端 404），项目默认模型已切换为 `moonshotai/kimi-k3`；预测网关从 `api.ngc.nvidia.com` 迁移到 `buildapi.ngc.nvidia.com`。

**中文:** 逆向工程 NVIDIA Build Playground（build.nvidia.com）的 API 调用，实现 Go 语言本地调用其**匿名 playground 模型**。支持多模型：内置注册表种子了 11 个可匿名调用的模型（DeepSeek、Kimi、MiniMax、Nemotron、DiffusionGemma 等），并可在运行时定期抓取 `https://build.nvidia.com/models` 目录页自动刷新，按 `model` 路由到对应的 predict 端点并注入各自的 `nv-function-id`。验证码使用**纯 Go hCaptcha PoW 求解器**（v8go 内嵌 V8 跑官方 hsw.js，不需要 Chromium），维护预热 token 池。网关嵌入 CLIProxyAPI，对外提供 OpenAI Chat Completions / Responses 与 Claude Messages，含 Docker 部署与 SSE/延迟基准。**不**启用网关入站 api-keys 校验。

### 快速开始

```bash
# 一键启动多格式代理（纯 Go PoW 验证码池，无浏览器；启动时自动抓取最新模型目录）
go run ./cmd/serve -auto -addr :8080

# OpenAI Chat Completions（默认模型 moonshotai/kimi-k3）
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"Hi"}],"stream":true}'

# OpenAI Responses
curl http://localhost:8080/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{"model":"moonshotai/kimi-k3","input":"Hi","stream":true}'

# Claude Messages
curl http://localhost:8080/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"moonshotai/kimi-k3","max_tokens":256,"messages":[{"role":"user","content":"Hi"}],"stream":true}'

# 当前可路由的模型列表（来自注册表/最新抓取结果）
curl http://localhost:8080/v1/models
```

或直接跑已发布镜像（镜像内**不含** Chromium）：

```bash
docker run --rm -p 8080:8080 ghcr.io/6kmfi6hp/nvidia-playgroud-go:latest
```

---

## 逆向分析报告

### 抓包过程

1. 访问 https://build.nvidia.com/models 选择任意带 playground 的模型
2. 启用 agent-browser 的 HAR 网络抓包，在 Playground 中发送消息
3. 抓取实际发送给 predict API 的 HTTP 请求
4. 目录页与 playground 页的 SSR 内容用于提取模型三元组（slug / namespace / function id）

### 发现的 API 端点

| 类型 | 端点 |
|------|------|
| **预测 API** (逆向) | `POST https://buildapi.ngc.nvidia.com/v2/predict/models/{namespace}/{slug}` |
| **模型目录** (SSR) | `GET https://build.nvidia.com/models`（Next flight data 内嵌 resourceId） |
| **Playground 页** | `GET https://build.nvidia.com/{publisher}/{slug}/playground`（内嵌 `nvcfFunctionId`） |

> **2026-08 上游变更：** 旧的预测网关 `api.ngc.nvidia.com`（及 `qc69jvmznzxy/glm-5.2`）对匿名账号已返回 404；目录页旧的 `?pageSize=200&filters=...` URL 返回空 body。现在统一走 `buildapi.ngc.nvidia.com`，目录解析迁移到 `/models` 页面。

### 多模型支持

每个 build.nvidia.com Playground 模型都有独立的 `slug`（端点路径）与 `nv-function-id`；namespace `qc69jvmznzxy` 当前全模型共享。`internal/models` 持有注册表：编译期快照（`registry.go`）作为 bootstrap/回退，运行时由 `fetch.go` 抓取目录页 + 逐个探测 playground 页，把内联了 UUID 形 `nvcfFunctionId` 的模型导入注册表（`All()`/`Replace()` 原子交换，刷新对 in-flight 请求无感，抓取失败保留旧表）。

**当前内置快照：11 个可用模型**（2026-08-30 抓取，目录页共 24 个端点，其余 13 个如 qwen-image / riva-translate / vsr 等页面未内联 function id，被跳过）：

```
deepseek-ai/deepseek-v4-flash-0731    deepseek-ai/deepseek-v4-pro-0813
google/diffusiongemma-26b-a4b-it      meta/muse-glimmer-30b
minimaxai/minimax-m3                  moonshotai/kimi-k3          ← 默认模型
nvidia/ising-calibration-1.5-31b      nvidia/nemotron-3-nano-omni-30b-a3b-reasoning
nvidia/nemotron-3-ultra-550b-a55b     nvidia/nemotron-3.5-lightning-30b-a3b
poolside/laguna-xs-2.1
```

- **默认模型** `moonshotai/kimi-k3`（`z-ai/glm-5.2` 2026-08 起被上游从匿名目录移除，后端 404，**不要**再请求它）。
- 请求体指定任意注册表内模型即可路由到对应端点（serve 与 Go client 都按 `model` 查表拼 URL + 注入 `nv-function-id`；未知模型返回 400 `unknown model`）：

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-ai/deepseek-v4-pro-0813","messages":[{"role":"user","content":"Hi"}],"stream":true}'
```

- **运行时自动刷新**：serve 启动即拉一次目录，之后按 `-model-refresh` 间隔（默认 `6h`；`0` = 只启动时拉一次；`<0` = 关闭、只用编译期快照）热刷新注册表并重绑网关 `/v1/models`，失败只记日志、保留旧表。每次抓取成功会把最新注册表原子写入 JSON 缓存（默认 `models_cache.json`，`-model-cache` 改路径、`-model-cache=` 关闭）；启动时先加载缓存，未联网也能立刻列出上次成功抓到的模型，首次抓取失败不再退回空表/旧快照。
- 重新生成快照（手动）：

```bash
python3 scripts/scrape_playground_models.py > scripts/playground_models.json
# 按输出更新 internal/models/registry.go 的 Models map（也可直接用 $MODEL_LIVE=1 go test ./internal/models -run TestLiveFetchSmoke -v 验证实时抓取）
```

- 未纳入的模型（function id 只在真实页面运行时解析、静态抓不到）**不要**给它们 pin 第三方来源的 function-id——实测会被上游以 `"Cannot parse function_id with value None"` 拒绝。

### 认证机制

Playground **不**使用 API Key 认证，而是使用 **hCaptcha token** 机制：

1. 每个请求携带 `nv-captcha-token`（`P1_` 开头、JWT 格式载荷）和 `nv-function-id` 两个头
2. token 由 hCaptcha 签发，针对（sitekey, host）对有效：sitekey `0c6a1e45-75d7-43cc-b836-a0c9d886b8ee`，host `build.nvidia.com`
3. 本项目用**纯 Go PoW 求解**直接合成 token（见下），不再需要浏览器

#### 请求签名

```
POST https://buildapi.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/kimi-k3
Content-Type: application/json
Accept: text/event-stream
nv-function-id: 1586112a-925c-48af-8631-7c815dbd749c
nv-captcha-token: P1_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Origin: https://build.nvidia.com
Referer: https://build.nvidia.com/
```

**注意:** 不需要 Cookie 或 Authorization 头！认证完全依赖 `nv-captcha-token` 和 Origin 检查。

### Token 生命周期

- Token 由 hCaptcha PoW 生成，**单次有效**，有效期约 2-3 分钟（serve 池默认 **90s TTL** 即丢弃）
- 每次求解（checksiteconfig → PoW → hsw → getcaptcha）约 1s，全部在 Go 内完成，无浏览器

### 请求体格式

上游即 OpenAI Chat Completions 格式。网关额外处理：

- `stream_options.continuous_usage_stats` 统一关闭（省流量），`include_usage` 默认开启
- 思维链参数按**模型**归一化（`internal/provider/nvidia/reasoning.go`），不是所有模型都接受 `chat_template_kwargs.enable_thinking`——多数 2026-08 目录模型（如 kimi-k3）对 thinking kwargs 直接 400，网关对未知模型会**剥离**该类参数：

| 模型 | 思维链控制方式 |
|------|----------------|
| `deepseek-ai/deepseek-v4-*` | `chat_template_kwargs.reasoning_effort` ∈ {none, high, max}（默认 high） |
| `nvidia/nemotron-3-ultra-550b-a55b` | `reasoning_effort` ∈ {none, medium, high}（默认 high） |
| `google/diffusiongemma-26b-a4b-it` | `enable_thinking` 开关 |
| `minimaxai/minimax-m3` | `thinking_mode` ∈ {enabled, disabled} |
| 其他（kimi-k3 等） | 不接受 thinking kwargs，统一剥离 |

开启推理链时，上游在 SSE `delta` / 非流式 `message` 中先返回 `reasoning_content`，再返回 `content`。

### 响应体格式

标准 SSE 流：

```
data: {"id":"chatcmpl-xxx","choices":[{"index":0,"delta":{"reasoning_content":"...","role":"assistant"},"finish_reason":null}],...}
data: {"id":"chatcmpl-xxx","choices":[{"index":0,"delta":{"content":"你好","role":"assistant"},"finish_reason":null}],...}
data: [DONE]
```

## Go 客户端使用

### 安装

本仓库 Go module 名为 `glm52-nvidia`（非标准域名路径），源码库内直接导入即可：

```go
import glm52 "glm52-nvidia"   // 客户端
import "glm52-nvidia/internal/captcha"   // PoW 提取 / token 池
```

### 方式 1：Captcha Token 模式（逆向）

从浏览器控制台或 `cmd/captchapow` 获取一次性 token（Playground 页面 `document.querySelector('[data-hcaptcha-widget-id]').dataset.hcaptchaResponse`），然后：

```bash
go run ./cmd/example -captcha "P1_eyJ..."
```

或在代码中：

```go
client := glm52.New(glm52.WithCaptchaToken("P1_eyJ..."))   // 默认模型 moonshotai/kimi-k3
resp, err := client.Chat(ctx, messages)

// 指定其他注册表模型：
client = glm52.New(glm52.WithCaptchaToken("P1_eyJ..."), glm52.WithModel("deepseek-ai/deepseek-v4-pro-0813"))
// 客户端默认只在模型声明支持 Thinking 时注入 chat_template_kwargs
```

### 方式 2：纯 Go hCaptcha PoW 求解（默认，无浏览器）

v8go 内嵌 V8 运行官方 hsw.js 完成 PoW，产出 `P1_...` token（详见 `runs/hcaptcha-pow-go.md`）。这是 **serve 网关的默认（也是唯一）验证码方案**，Docker 镜像不包含 Chromium。

```bash
# 一键求解（默认 build.nvidia.com / NVIDIA sitekey）
go run ./cmd/captchapow

# 详细诊断：每阶段日志 + 明文变体响应
go run ./cmd/captchapow -v

# 自定义站点
go run ./cmd/captchapow -sitekey <sitekey> -host <host>
```

在代码中使用：

```go
import "glm52-nvidia/internal/captcha"
token, err := captcha.PowExtract()(ctx) // = hcaptcha.CaptchaToken(ctx, captcha.PlaygroundSitekey, captcha.PlaygroundHost)
```

各阶段（checksiteconfig → 指纹+挖矿 → hsw 求 n → 加密提交 getcaptcha → P1 token）全链路约 1s。实现分布在 `internal/hcaptchapow`（纯 Go 算法）、`internal/hsw`（v8go 运行器）、`internal/hcaptcha`（编排）。已知边界：当前入侵参数未含 motionData；个别站点可能要求动态校验脚本，此时需回退浏览器方案。

> 历史遗留：`internal/captcha` 仍保留 chromedp 浏览器提取（`Extract`/`BrowserGroup`），仅用于旧实验 CLI（`cmd/example -auto`、`cmd/hangbench`、`cmd/cacheprobe`、`cmd/captchaopt`），需要本地 Chrome。网关与 Docker 镜像已不使用它。

### 方式 3：多格式本地代理（CLIProxyAPI）

`serve` 嵌入 CLIProxyAPI 网关：内置翻译器把 Claude `/v1/messages` 与 OpenAI `/v1/responses` 转成 openai chat，再由 nvidia ProviderExecutor 注入 captcha / `nv-function-id` 并调用 predict。**不**配置网关 `api-keys`（入站无 Key 校验）。**每个 captcha token 只能用于一次上游请求。**

```bash
# 纯 Go PoW 池后台填充（启动默认：pool=3 workers=1 coalesce=16ms；首请求可能等待求解）
go run ./cmd/serve -auto -addr :8080

# 纯 Go PoW 求解（checksiteconfig / hsw.js / getcaptcha）、模型目录抓取与 WAF token 走代理
# （也可设环境变量 CHROME_PROXY）；predict API（buildapi.ngc.nvidia.com）延迟敏感，
# 始终绕过代理直连，其余流量才走代理
go run ./cmd/serve -auto -proxy socks5://100.74.21.88:7890

# 模型目录：默认请求带 filters 的 NIM 预览列表（更多模型，40 候选）。该 URL
# 在 AWS WAF 挑战后；serve 会用内置纯 Go 求解器自动解出 aws-waf-token
# （内嵌 V8 执行 challenge.js 解混淆 + AES-GCM + PoW，无需浏览器、无需填写 token），
# 失败时再自动回退无过滤页面（24 候选）。也可手动指定 token 跳过求解：
go run ./cmd/serve -auto -catalog-cookie "aws-waf-token=<从浏览器 DevTools 复制>"

# 覆盖默认（实验脚本 scripts/ttft_sweep.sh）
go run ./cmd/serve -auto -pool-size=2 -pool-workers=2 -coalesce-ms=0 -max-inflight=8

# 无请求时自动停池：默认 3 分钟没有任何 take 就停止求解（-pool-idle=3m），
# 下次请求到达时按需重启；-pool-idle=0 关闭此行为（始终后台填充）

# OpenAI Chat Completions
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"moonshotai/kimi-k3","messages":[{"role":"user","content":"Which is larger, 9.11 or 9.8?"}],"stream":true}'

# OpenAI Responses
curl http://localhost:8080/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{"model":"moonshotai/kimi-k3","input":"Hi","stream":true}'

# Claude Messages
curl http://localhost:8080/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"moonshotai/kimi-k3","max_tokens":256,"messages":[{"role":"user","content":"Hi"}],"stream":true}'

# 池水位（ready/fills/takes/errors/expired）；模型列表见 /v1/models
curl -s http://localhost:8080/healthz
```

- 验证码来源优先级：请求头 `nv-captcha-token` > `-captcha` 一次性 flag（首请求消费后失效）> `-auto` 池（默认 PoW 求解，池空时最多等 `-captcha-wait` 默认 30s 后返回 503）。
- 上游返回 captcha 形状的 4xx（`Token is invalid` / `hcaptcha` 字样）时自动换新 token 重试，最多 3 次尝试（2 次换新）；池内 token 默认 90s TTL 过期丢弃。
- 流式优化：关闭 `continuous_usage_stats`、可选 content coalesce（`-coalesce-ms`）；`-max-inflight` 限制并发上游流（默认 4，超限等待 `-inflight-wait` 500ms 后 503）。
- 模型目录热刷新：`-model-refresh`（默认 6h；`0` 只启动拉一次；`<0` 关闭）。目录抓取使用 **tls-client 模拟 Chrome 131 的 TLS/HTTP2 指纹**（JA3/JA4 + HTTP/2 SETTINGS），并经代理走固定出口；优先 filtered 列表 URL（40 个候选），被 AWS WAF 挑战时由 **internal/waftoken** 自动求解（挑战页 → challenge.js → V8 解混淆提取 AES 密钥 → 浏览器信号 AES-256-GCM 加密 → 解 PoW（NetworkBandwidth/scrypt/SHA-2）→ POST 换 `aws-waf-token`，纯 Go 无浏览器无 Node），仍失败才回退 unfiltered 页面（24 候选）。Akamai `ak_bmsc`/`bm_mi` 等会话 cookie 由内置 jar 自动吸收并重放。抓取成功后注册表自动持久化到 `-model-cache` JSON（默认 `models_cache.json`，已加入 .gitignore），启动时优先加载，失败/离线也能立即出模型。
- 所有 flag 见 `go run ./cmd/serve -h`。

流式时序 / 并发实验：

```bash
go run ./cmd/streambench -auto -prompt "Count from 1 to 20."
go run ./cmd/streambench -proxy http://localhost:8080
go run ./cmd/streambench -proxy http://localhost:8080 -concurrency 4 -max-tokens 64
```

## Docker 部署

镜像内置纯 Go PoW 求解器，默认以 `-auto` 启动预热池；**不需要 Chromium，也不需要额外 shm**。

```bash
# 本地构建并运行
docker compose up --build

# 或直接跑已发布镜像（GHCR）
docker run --rm -p 8080:8080 ghcr.io/6kmfi6hp/nvidia-playgroud-go:latest
```

健康检查：`GET /healthz`（容器 HEALTHCHECK 亦探活该路径）。反向代理流式接口时请关闭 buffering，并拉长 read timeout（建议 ≥120s；空 captcha 池时 serve 最多等 `-captcha-wait`，默认 30s 后返回 503，过短的代理超时会表现为客户端 504）。

环境变量：

| 变量 | 作用 |
|------|------|
| `CHROME_PROXY` | PoW 求解、模型目录抓取与 WAF token 共用代理（等同 `-proxy`），如 `socks5://host:port`；predict API 始终直连 |
| `HTTP_PROXY` / `HTTPS_PROXY` | 标准 Go 代理环境变量，同样作用于全部出站请求 |

> 旧版文档中的 `CHROME_PATH` / `CHROMEDP_NO_SANDBOX` / `--shm-size=2g` 仅对已移除的 Chromium 方案有意义，镜像中已无浏览器，无需再设置。

## 发版与镜像

推送 semver tag 后，GitHub Actions 会自动：

1. 构建多平台 `serve` 二进制并创建 GitHub Release
2. 推送多架构镜像到 `ghcr.io/6kmfi6hp/nvidia-playgroud-go`（`v*` + `latest`）

```bash
git tag v0.1.0
git push origin v0.1.0
```

也可在 Actions 里用 `workflow_dispatch` 手动指定 tag。首次拉取私有/受限 GHCR 包时，在仓库 Settings → Packages 中确认可见性。

## 项目结构

```
nvidia-playgroud-go/
├── types.go              # 类型定义（ChatRequest、Message、Chunk 等，OpenAI-compatible）
├── client.go             # 客户端实现（hCaptcha token + SSE 流式，按 model 查表路由）
├── internal/captcha/     # token 预热池、纯 Go PoW 提取（pow.go）+ 遗留 chromedp 提取
├── internal/hcaptchapow/ # 纯 Go hCaptcha PoW 算法（JWT/stamp/CRC32/XXH64，零依赖）
├── internal/hsw/         # v8go 内嵌 V8：运行官方 hsw.js 求 n / 加解密
├── internal/hcaptcha/    # 无浏览器编排：指纹→n→getcaptcha→P1 token
├── internal/models/      # Playground 模型注册表：registry.go（快照）+ fetch.go（实时抓取）
├── cmd/captchapow/       # 纯 Go PoW 求解 CLI（无浏览器）
├── cmd/example/          # 命令行示例（-captcha / -auto / -smooth-ms 打字机输出）
├── cmd/serve/            # 多格式网关（chat/completions + responses + messages；模型热刷新）
├── cmd/streambench/      # SSE 时序 + 并发实验（-concurrency）
├── cmd/hangbench/        # 空闲/突发 token 池行为实验
├── cmd/cacheprobe/       # 流式时序探针
├── cmd/captchaopt/       # 浏览器 captcha 提取调优实验（需本地 Chrome）
├── scripts/scrape_playground_models.py  # 爬取 playground 模型 + function-id（离线快照用）
├── scripts/playground_models.json       # 最近一次抓取结果（11/24）
├── runs/                 # 历史实验记录（CAPTCHA PoW、TTFT、hangbench 等）
├── Dockerfile            # 纯 Go PoW + serve 多阶段构建（无 Chromium）
└── docker-compose.yml    # 本地一键启动
```

## 测试

```bash
go build ./... && go vet ./... && go test ./...
# 实时抓取冒烟（可选，需要外网）：
MODEL_LIVE=1 go test ./internal/models -run TestLiveFetchSmoke -v
```

## 历史实验记录（runs/）

- `runs/hcaptcha-pow-go.md` — 纯 Go hCaptcha PoW 求解实现记录
- `runs/ttft-experiment-2026-07-21.md`、`runs/captcha-opt-2026-07-21.md` — 2026-07 浏览器 captcha/token 池实验（历史方案）
- `runs/hangbench-2026-07-22.md`、`runs/captcha-sticky-2026-07-22.md` — 池水位与粘性实验（历史方案）
- `runs/crawlex-pipeline.md` — Playground 抓包分析（历史）
