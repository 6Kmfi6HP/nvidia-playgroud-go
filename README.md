# nvidia-playgroud-go

NVIDIA Build Playground 的 Go 客户端和本地代理。支持多模型路由、hCaptcha PoW token 池，以及 OpenAI Chat Completions、OpenAI Responses 和 Claude Messages 接口。

默认模型为 `moonshotai/kimi-k3_1-pro`。项目依赖上游匿名 Playground 接口，上游调整可能导致模型或接口不可用。

## 快速开始

需要 Go 1.26。启动本地代理：

```bash
go run ./cmd/serve -auto -addr :8080
```

调用 OpenAI Chat Completions：

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"moonshotai/kimi-k3_1-pro","messages":[{"role":"user","content":"Hi"}],"stream":true}'
```

可用端点：

| 端点 | 用途 |
|------|------|
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/responses` | OpenAI Responses |
| `POST /v1/messages` | Claude Messages，需要 `anthropic-version` 请求头 |
| `GET /v1/models` | 当前模型列表 |
| `GET /healthz` | 健康检查和 token 池状态 |

代理默认不校验入站 API key，请仅监听可信网络，不要直接暴露到公网。

## 模型

- 默认模型：`moonshotai/kimi-k3_1-pro`。
- `z-ai/glm-5.2` 和 `moonshotai/kimi-k3` 已被上游移除，不要再作为默认模型使用。
- 请求体中的 `model` 用于选择注册表中的模型；未知模型返回 `unknown model`。
- 启动时加载本地缓存和编译期快照，然后刷新模型目录。默认每 6 小时刷新一次，失败时保留现有注册表。
- 刷新成功后写入 `models_cache.json`，下次启动可离线加载上次成功的目录。

查看当前模型：

```bash
curl http://localhost:8080/v1/models
```

常用模型参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-model-refresh` | `6h` | 目录刷新间隔；`0` 仅启动时刷新，负数关闭刷新 |
| `-model-cache` | `models_cache.json` | 模型目录缓存路径，空值关闭缓存 |
| `-catalog-cookie` | 空 | 可选的目录页 Cookie，例如已有的 `aws-waf-token` |

重新抓取模型快照：

```bash
python3 scripts/scrape_playground_models.py > scripts/playground_models.json
```

抓取后按输出更新 `internal/models/registry.go`。可用以下命令验证实时抓取：

```bash
MODEL_LIVE=1 go test ./internal/models -run TestLiveFetchSmoke -v
```

## 验证码

验证码由纯 Go hCaptcha PoW 求解器生成，使用 v8go 运行上游脚本，不需要 Chromium。请求走 Chrome 指纹的 uTLS 传输（ALPN 固定 HTTP/1.1），按浏览器 widget 流程提交 checksiteconfig challenge，并动态读取当前 `api.js` 版本。

- token 单次有效，池中 token 默认 90 秒后丢弃。
- token 来源优先级：请求头 `nv-captcha-token`、`-captcha` 一次性参数、`-auto` token 池。
- 池为空时，请求最多等待 `-captcha-wait`（默认 30 秒），随后返回 503。
- 上游返回 captcha 相关错误时，代理会更换 token 重试，最多尝试 3 次。
- 无请求 3 分钟后停止后台求解，下次请求到达时重新启动；`-pool-idle=0` 可关闭此行为。

单独获取 token：

```bash
go run ./cmd/captchapow
go run ./cmd/captchapow -v
```

## 命令行工具

| 命令 | 用途 |
|------|------|
| `cmd/serve` | 本地多格式代理 |
| `cmd/predict` | 单发预测请求，可指定 function-id |
| `cmd/captchapow` | 生成 hCaptcha token |
| `cmd/streambench` | SSE 时序和并发测试 |
| `cmd/example` | Go 客户端示例 |

```bash
go run ./cmd/predict -prompt "ping"
go run ./cmd/predict -list
go run ./cmd/predict -model minimaxai/minimax-m3 -v
go run ./cmd/streambench -auto -prompt "Count from 1 to 20."
```

需要指定注册表外的 NVCF function 时，可使用 `-function-id` 和 `-slug`：

```bash
go run ./cmd/predict -model acme/new-llm -slug new-llm -function-id <uuid>
```

## 配置

常用 serve 参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-addr` | `:8080` | 监听地址 |
| `-auto` | `false` | 启用验证码 token 池 |
| `-pool-size` | `3` | 池中保留的可用 token 数 |
| `-pool-workers` | `1` | 并发求解器数量 |
| `-captcha-wait` | `30s` | 等待 token 的最长时间，超时返回 503 |
| `-max-inflight` | `8` | 最大并发上游流，`0` 表示不限制 |
| `-coalesce-ms` | `16` | SSE 内容合并窗口，`0` 关闭 |
| `-proxy` | 空 | PoW、模型目录和 WAF token 使用的代理 |

完整参数见 `go run ./cmd/serve -h`。

环境变量：

| 变量 | 作用 |
|------|------|
| `CHROME_PROXY` | PoW 求解、模型目录抓取和 WAF token 使用的代理，等同于 `-proxy` |
| `HTTP_PROXY` / `HTTPS_PROXY` | 标准 Go 代理环境变量 |

predict API 始终直连；`-proxy` 和 `CHROME_PROXY` 只作用于 PoW 求解、模型目录抓取和 WAF token 获取。

## Go 客户端

仓库 module 名为 `nvidia-playgroud-go`。在仓库内使用：

```go
import nvidia "nvidia-playgroud-go"

client := nvidia.New(
    nvidia.WithCaptchaToken("P1_..."),
    nvidia.WithModel("moonshotai/kimi-k3_1-pro"),
)
resp, err := client.Chat(ctx, messages)
```

token 单次有效。需要指定其他模型时，使用 `nvidia.WithModel("publisher/slug")`；需要固定 NVCF 调用目标时，使用 `WithModelInfo`。

## Docker

```bash
docker compose up --build
```

或使用已发布镜像：

```bash
docker run --rm -p 8080:8080 ghcr.io/6kmfi6hp/nvidia-playgroud-go:latest
```

镜像不包含 Chromium。健康检查路径为 `GET /healthz`。反向代理流式接口时请关闭 buffering，并将 read timeout 设置为至少 120 秒。

## 项目结构

```text
cmd/serve/            本地代理
cmd/predict/          单发 predict 请求
cmd/captchapow/       hCaptcha PoW token 工具
cmd/streambench/      SSE 和并发测试
internal/captcha/     token 池
internal/captchatls/  uTLS Chrome 指纹传输
internal/hcaptcha/    hCaptcha 请求编排
internal/hcaptchapow/ PoW 算法
internal/hsw/         v8go 运行器
internal/models/      模型注册表和目录刷新
internal/provider/    上游请求与响应适配
scripts/              模型目录抓取和实验脚本
runs/                 历史实验记录
```

## 开发

```bash
go build ./...
go vet ./...
go test ./...
```

可选的实时目录冒烟测试：

```bash
MODEL_LIVE=1 go test ./internal/models -run TestLiveFetchSmoke -v
```

推送 `v*` tag 会触发二进制和 Docker 镜像发布。支持 linux/amd64、linux/arm64 和 darwin/arm64；v8go 的预编译库限制了其他平台的发布。

历史实验记录见 `runs/`。
