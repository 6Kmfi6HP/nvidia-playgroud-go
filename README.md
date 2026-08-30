# GLM-5.2 NVIDIA NIM Go Client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![GLM-5.2](https://img.shields.io/badge/Model-GLM--5.2-753B-orange)](https://build.nvidia.com/z-ai/glm-5.2/playground)
[![OpenAI Compatible](https://img.shields.io/badge/API-OpenAI_Compatible-412991?logo=openai&logoColor=white)](#方式-3openai-兼容本地代理)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white)](#docker-部署方案-achromium--serve)
[![Status](https://img.shields.io/badge/Status-Reverse_Engineered-yellow)](#逆向分析报告)
![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

> **English:** A reverse-engineered Go client and multi-format reverse proxy for **NVIDIA Playground's [GLM-5.2](https://build.nvidia.com/z-ai/glm-5.2/playground)** LLM (753B MoE, 1M context, thinking/tool-calling/streaming). It automates one-shot **hCaptcha** credentials with headless Chromium (chromedp), runs a prewarmed captcha token pool, embeds [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) to expose OpenAI Chat Completions, OpenAI Responses, and Claude Messages, and ships with Docker deployment and SSE/latency benchmarks. Inbound gateway API keys are **not** enabled.

**中文:** 逆向工程 NVIDIA Playground 的 API 调用，实现 Go 语言本地调用 [GLM-5.2](https://build.nvidia.com/z-ai/glm-5.2/playground)（753B MoE、1M 上下文、思维链/工具调用/流式输出）。通过 headless Chromium（chromedp）自动化 hCaptcha 凭证，维护预热 token 池，嵌入 CLIProxyAPI 对外提供 OpenAI Chat Completions / Responses 与 Claude Messages，含 Docker 部署与 SSE/延迟基准。**不**启用网关入站 api-keys 校验。

### 快速开始

```bash
# 一键启动多格式代理（内置 Chromium + captcha 预热池；依赖 CLIProxyAPI 内置翻译器）
go run ./cmd/serve -auto -addr :8080

# OpenAI Chat Completions
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"Hi"}],"stream":true}'

# OpenAI Responses
curl http://localhost:8080/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{"model":"z-ai/glm-5.2","input":"Hi","stream":true}'

# Claude Messages
curl http://localhost:8080/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"z-ai/glm-5.2","max_tokens":256,"messages":[{"role":"user","content":"Hi"}],"stream":true}'
```

或直接跑已发布镜像：

```bash
docker run --rm -p 8080:8080 --shm-size=2g ghcr.io/6kmfi6hp/glm52-nvidia-go:latest
```

---

## 逆向分析报告

### 抓包过程

1. 访问 https://build.nvidia.com/z-ai/glm-5.2/playground
2. 启用 agent-browser 的 HAR 网络抓包
3. 在 Playground 中发送消息
4. 抓取实际发送给 API 的 HTTP 请求

### 发现的 API 端点

| 类型 | 端点 |
|------|------|
| **预测 API** (逆向) | `POST https://api.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/glm-5.2` |
| **队列检查** | `GET https://api.ngc.nvidia.com/v2/predict/queues/models/qc69jvmznzxy/glm-5.2` |
| **API 文档** | https://docs.api.nvidia.com/nim/reference/z-ai-glm-5-2 |

### 多模型支持

每个 build.nvidia.com Playground 模型都有独立的 `slug`（端点路径）与 `nv-function-id`，namespace `qc69jvmznzxy` 全模型共享。`internal/models` 持有一份已爬取的注册表（52 个 chat playground 模型，含 `z-ai/glm-5.2`、`deepseek-ai/deepseek-v4-pro`、`nvidia/nemotron-*`、`openai/gpt-oss-*`、`qwen/qwen3.5-*` 等，已用真实 captcha token 端到端验证）。

注册表由 `scripts/scrape_playground_models.py` 生成：拉取 `https://integrate.api.nvidia.com/v1/models` 的全量 id 列表，逐个抓 `/{id}/playground` 页面，解析 SSR 内联的 `nvcfFunctionId`+`namespace`。刷新：

```bash
python3 scripts/scrape_playground_models.py > scripts/playground_models.json
# 然后按 scripts/playground_models.json 更新 internal/models/registry.go 的 Models map
```

请求体里指定任意注册表内模型即可路由到对应端点（serve 与 Go client 都按 `model` 查表拼 URL + 注入对应 `nv-function-id`；未知模型返回 400）：

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-ai/deepseek-v4-pro","messages":[{"role":"user","content":"Hi"}],"stream":true}'
```

未纳入的模型（如 `ibm/granite-*-code-instruct`、`nv-mistralai/mistral-nemo-12b`、`moonshotai/kimi-k2.6`）其 `/playground` 页把 `nvcfFunctionId` 渲染为 `"None"`——function-id 只在真实页面运行时解析，静态抓取拿不到。**不要**给这些模型 pin 第三方来源的 function-id（实测会被上游以 `"Cannot parse function_id with value None"` 拒绝）；要让它们可用，需要在真实浏览器里驱动页面拿到运行时 function-id 后再加进注册表。

### 认证机制

Playground **不**使用 API Key 认证，而是使用 **hCaptcha token** 机制：

1. 页面加载时渲染 hCaptcha 不可见 widget
2. 调用 `hcaptcha.execute(widgetId)` 生成 token
3. token 存储在 widget 的 `data-hcaptcha-response` 属性中
4. token 以 `P1_` 开头，包含 JWT 格式的加密载荷
5. 每次请求携带 `nv-captcha-token` 和 `nv-function-id` 头

#### 请求签名

```
POST https://api.ngc.nvidia.com/v2/predict/models/qc69jvmznzxy/glm-5.2
Content-Type: application/json
Accept: text/event-stream
nv-function-id: 3b9748d8-1d85-40e8-8573-0eeaa63a4b63
nv-captcha-token: P1_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Origin: https://build.nvidia.com
Referer: https://build.nvidia.com/
```

**注意:** 不需要 Cookie 或 Authorization 头！认证完全依赖 `nv-captcha-token` 和 Origin 检查。

### Token 生命周期

- Token 由 hCaptcha 生成，单次有效
- 每次调用 `hcaptcha.execute(widgetId)` 可生成新 token
- Token 有效期约 2-3 分钟
- 使用后立即失效

### 请求体格式

兼容 OpenAI Chat Completions 格式。Playground 开启 Thinking 时额外携带 `chat_template_kwargs`：

```json
{
  "model": "z-ai/glm-5.2",
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 1.0,
  "top_p": 1.0,
  "max_tokens": 16384,
  "seed": 42,
  "stream": true,
  "stream_options": {
    "include_usage": true,
    "continuous_usage_stats": true
  },
  "chat_template_kwargs": {
    "enable_thinking": true,
    "clear_thinking": false
  }
}
```

`enable_thinking: true` 时上游在 SSE `delta` / 非流式 `message` 中返回 `reasoning_content`（思维链），再返回 `content`（最终回答）。`clear_thinking: false` 表示多轮对话保留历史思考内容。

### 响应体格式

标准 SSE 流：

```
data: {"id":"chatcmpl-xxx","choices":[{"index":0,"delta":{"reasoning_content":"...","role":"assistant"},"finish_reason":null}],...}
data: {"id":"chatcmpl-xxx","choices":[{"index":0,"delta":{"content":"你好","role":"assistant"},"finish_reason":null}],...}
data: [DONE]
```

开启 Thinking 时先出现 `reasoning_content`，再出现 `content`。

## Go 客户端使用

### 安装

```bash
go get github.com/chromedp/chromedp  # 仅自动提取 token 时需要
```

### 方式 1：Captcha Token 模式（逆向）

从浏览器获取 token：

```bash
# 1. 打开浏览器访问 Playground
# 2. 打开开发者控制台，执行：
#    hcaptcha.execute("xxx")
# 3. 获取 token：
#    document.querySelector('[data-hcaptcha-widget-id]')
#      .dataset.hcaptchaResponse

# 4. 使用 Go 客户端
go run ./cmd/example -captcha "P1_eyJ..."
```

或在代码中：

```go
client := glm52.New(glm52.WithCaptchaToken("P1_eyJ..."))
resp, err := client.Chat(ctx, messages)
```

### 方式 2：自动提取 Token（chromedp）

```go
// cmd/example/auto.go 中提供了完整实现
token, err := ExtractCaptchaToken(ctx)
client := glm52.New(glm52.WithCaptchaToken(token))
```

### 方式 3：纯 Go hCaptcha PoW 求解（内嵌 V8，无浏览器，实验）

实验性的浏览器无关路径：v8go 内嵌 V8 运行官方 hsw.js 完成 PoW，产出 `P1_...` token（详见 `runs/hcaptcha-pow-go.md`）。

```bash
# 一键求解（默认 build.nvidia.com / NVIDIA sitekey）
go run ./cmd/captchapow

# 详细诊断：每阶段日志 + 明文变体响应
go run ./cmd/captchapow -v

# 自定义站点
go run ./cmd/captchapow -sitekey <sitekey> -host <host>
```

各阶段（checksiteconfig → 指纹+挖矿 → hsw 求 n → 加密提交 getcaptcha → P1 token）全链路约 1s。
新增包：`internal/hcaptchapow`（纯 Go 算法）、`internal/hsw`（v8go 运行器）、`internal/hcaptcha`（编排）。
已知边界：当前入侵参数未含 motionData；上游 predict 还需刷新 `scripts/playground_models.json` 的 function-id 绑定。

## 模型信息

| 属性 | 值 |
|------|-----|
| 架构 | MoE, DSA + IndexShare 稀疏注意力 |
| 参数 | 753B |
| 上下文 | 1M tokens |
| 支持 | 推理链 (thinking)、工具调用、流式输出 |
| API 兼容 | OpenAI Chat Completions 格式 |
| 部署 | Docker NIM: `nvcr.io/nim/zai-org/glm-5.2:latest` |

### 方式 3：多格式本地代理（CLIProxyAPI）

上游 predict API 本身就是 Chat Completions 格式。`serve` 嵌入 CLIProxyAPI 网关：内置翻译器把 Claude `/v1/messages` 与 OpenAI `/v1/responses` 转成 openai chat，再由 nvidia ProviderExecutor 注入 captcha / `nv-function-id` 并调用 predict。**不**配置网关 `api-keys`（入站无 Key 校验）。**每个 captcha token 只能用于一次上游请求。**

```bash
# 共享 Chrome + captcha 预热池（启动默认：pool=3 workers=1 coalesce=16ms，先预热再接流量）
go run ./cmd/serve -auto -addr :8080

# captcha Chrome + 上游 API 走同一 SOCKS5（也可设环境变量 CHROME_PROXY）
go run ./cmd/serve -auto -chrome-proxy socks5://100.74.21.88:7890

# 覆盖默认（实验脚本 scripts/ttft_sweep.sh）
go run ./cmd/serve -auto -pool-size=2 -pool-workers=2 -coalesce-ms=0 -max-inflight=8

# 跳过启动预热（不推荐：首请求 TTFT 会含整段 captcha 提取）
go run ./cmd/serve -auto -warm-timeout=0

# OpenAI Chat Completions（serve 默认注入 enable_thinking，与 Playground 一致）
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"Which is larger, 9.11 or 9.8?"}],"stream":true}'

# OpenAI Responses
curl http://localhost:8080/v1/responses \
  -H 'Content-Type: application/json' \
  -d '{"model":"z-ai/glm-5.2","input":"Hi","stream":true}'

# Claude Messages
curl http://localhost:8080/v1/messages \
  -H 'Content-Type: application/json' \
  -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"z-ai/glm-5.2","max_tokens":256,"messages":[{"role":"user","content":"Hi"}],"stream":true}'

# 显式关闭思维链（Chat Completions）
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"Hi"}],"stream":true,"chat_template_kwargs":{"enable_thinking":false}}'

# 池水位（fills/takes/ready）
curl -s http://localhost:8080/healthz
```

也可在请求头携带 `nv-captcha-token` 提供一次性 token。流式优化：关闭 `continuous_usage_stats`、可选 content coalesce；`-auto` 时后台预热 token，请求路径只从池中取。池内 token 默认 **90s TTL**，过期丢弃；上游返回 `Token is invalid` 时自动换新 token 最多重试 2 次。端到端调用仍需 `-auto` / `-captcha` / 请求头 captcha（与现网一致）。

流式时序 / 并发实验：

```bash
go run ./cmd/streambench -auto -prompt "Count from 1 to 20."
go run ./cmd/streambench -proxy http://localhost:8080
go run ./cmd/streambench -proxy http://localhost:8080 -concurrency 4 -max-tokens 64
```

## Docker 部署（方案 A：Chromium + serve）

镜像内置 Chromium，默认以 `-auto` 启动 captcha 预热池。

```bash
# 本地构建并运行（需要 2GB shm，供 headless Chrome 使用）
docker compose up --build

# 或直接跑已发布镜像（GHCR，需先发版）
docker run --rm -p 8080:8080 --shm-size=2g \
  ghcr.io/6kmfi6hp/glm52-nvidia-go:latest
```

健康检查：`GET /healthz`。反向代理流式接口时请关闭 buffering，并拉长 read timeout（建议 ≥120s；空 captcha 池时 serve 最多等 `-captcha-wait`，默认 30s 后返回 503，过短的代理超时会表现为客户端 504）。

环境变量：

| 变量 | 作用 |
|------|------|
| `CHROME_PATH` | Chromium 可执行文件路径（镜像内默认 `/usr/bin/chromium`） |
| `CHROMEDP_NO_SANDBOX` | 设为 `1` 时启用 `--no-sandbox` / `--disable-dev-shm-usage`（镜像默认开启） |
| `CHROME_PROXY` | captcha Chrome 与上游 API 共用代理，如 `socks5://host:port`（等同 `-chrome-proxy`） |
| `CHROME_PROXY_REMOTE_DNS` | 设为 `1` 时强制 DNS 也走 SOCKS（部分代理不支持，默认关闭） |

## 发版与镜像

推送 semver tag 后，GitHub Actions 会自动：

1. 构建多平台 `serve` 二进制并创建 GitHub Release
2. 推送多架构镜像到 `ghcr.io/6kmfi6hp/glm52-nvidia-go`（`v*` + `latest`）

```bash
git tag v0.1.0
git push origin v0.1.0
```

也可在 Actions 里用 `workflow_dispatch` 手动指定 tag。首次拉取私有/受限 GHCR 包时，在仓库 Settings → Packages 中确认可见性。

## 项目结构

```
glm52-nvidia-go/
├── types.go              # 类型定义（ChatRequest、Message、Chunk 等）
├── client.go             # 客户端实现（hCaptcha token + SSE 流式，按 model 路由）
├── internal/captcha/     # 共享 Chrome、token 预热池、一次性提取
├── internal/hcaptchapow/ # 纯 Go hCaptcha PoW 算法（JWT/stamp/CRC32/XXH64，零依赖）
├── internal/hsw/         # v8go 内嵌 V8：运行官方 hsw.js 求 n / 加解密
├── internal/hcaptcha/    # 无浏览器编排：指纹→n→getcaptcha→P1 token
├── cmd/captchapow/       # 纯 Go PoW 求解 CLI（无浏览器）
├── internal/models/      # Playground 模型注册表（slug/namespace/function-id）
├── internal/provider/nvidia/  # CLIProxyAPI ProviderExecutor（captcha + predict）
├── cmd/example/          # 命令行示例（-smooth-ms 打字机输出）
├── cmd/serve/            # 多格式网关（CLIProxyAPI：chat/completions + responses + messages）
├── cmd/streambench/      # SSE 时序 + 并发实验（-concurrency）
├── scripts/scrape_playground_models.py  # 爬取 playground 模型 + function-id
├── Dockerfile            # Chromium + serve 多阶段构建
└── docker-compose.yml    # 本地一键启动（shm_size=2g）
```
