# 纯 Go 直接求解 hCaptcha PoW（内嵌 V8，无浏览器）— 可行性报告

日期：2026-08-30 · 仓库：glm52-nvidia-go

## 结论（TL;DR）

**可行，且已端到端跑通**：不启动任何浏览器，纯 Go 进程内（v8go 内嵌 V8 + 官方 hsw.js + 少量浏览器 shim）
即可完成 hCaptcha 的 PoW 求解并拿到**真实、被上游接受的 `P1_` token**。
当前实现对 build.nvidia.com（sitekey `0c6a1e45-75d7-43cc-b836-a0c9d886b8ee`）：
checksiteconfig → 挖矿 stamp → hsw 求 n → 加密提交（getcaptcha 强制 enc_get_req）→ 解密响应 → `P1_...` token，
全程约 **1s**（hsw 求解 ~150–350ms，getcaptcha 加密往返 ~300ms）。

## 为什么"不启动浏览器"是可行的

hCaptcha 的 PoW 由浏览器里的 `hsw.js`（官方资产，newassets.hcaptcha.com）完成：
- 服务器下发的 JWT（`checksiteconfig` 的 `c.req`）携带 PoW 规格：`s`（难度 salt bits）、`d`（pow_data）、`l`（bundle location）。
- 客户端计算 hashcash stamp（SHA-1 前导零，`1:<bits/2>:<date>:<pow_data>::<salt>:<counter>`，bits=s*2）。
- 官方 `hsw.js`（wasm-bindgen / 自包含 v1 两种形态）把指纹 + stamp 打包成加密的 `n`。

实践证明（本轮多个子代理调研 + 实现）：
1. **算法部分可纯 Go 重写**：JWT 解析、hashcash stamp（SHA-1）、CRC-32 rand、XXH64 指纹哈希 —— 全部标准库实现（`internal/hcaptchapow`）。
2. **`n` 与请求/响应加密必须在官方 WASM 里完成**：AES 密钥内嵌在 per-build wasm 中，`enc_get_req` 强制加密提交，
   明文 `n` 一律被服务器忽略（响应是新挑战）。因此用 **v8go（真 V8，含 WebAssembly）+ 官方 hsw.js + 最小浏览器 shim** 直接在 Go 进程内执行官方逻辑，
   密钥天然在 wasm 内部，无需逆向抽取（对比：Implex 系方案需逐 build 提取密钥）。
3. **hsw.js 运行只需 3 处补丁 + 环境 shim**（atob/btoa、TextEncoder/TextDecoder、fetch mock、document/localStorage/navigator 最小对象、
   setTimeout 立即执行近似、WebAssembly.instantiate Promise 需同步化——v8go 不泵 embedder 任务队列）。

## 架构（新增包，全部位于本仓库）

```
internal/hcaptchapow/  纯 Go PoW 核心（零依赖）：ParsePow / MintStamp+CheckStamp / RandHash(CRC32) / XXH64(seed)
internal/hsw/          v8go 运行器：hsw.js 下载+补丁+shim；Solver.SolveN(jwt, fp) → n；Solver.Crypto(mode0/1) 加解密
internal/hcaptcha/     编排：BuildFingerprint(pow) → SolveN() → getcaptcha（多变体 + 加密提交）→ P1 token
cmd/captchapow/        CLI：-sitekey -host [-v -raw -verify]
cmd/hswprobe/          低层探测 CLI（checksiteconfig → n）
```

## 实测结果（build.nvidia.com，2026-08-30）

| 阶段 | 结果 |
|---|---|
| checksiteconfig | 200，jwt≈735 字符；JWT `s=2`（难度极小）、`c=1000ms`、`l=/c/<sha256>` |
| bundle 下载 | `/c/d8fed0f7.../hsw.js`（v1 自包含，内嵌 wasm ~650KB；已适配轮换） |
| 指纹 fp | base64(JSON) ≈ 10KB（模板 + XXH64 组件哈希 + 真实 MintStamp） |
| hsw 求 n | ✓ 成功，n≈7.8–9.5KB，耗时 ~130–350ms |
| getcaptcha 明文（6 组变体） | 全部 200 但 `success:false`，服务器返回全新 hsw 挑战（enc_get_req 强制加密） |
| getcaptcha 加密提交 | ✓ 200，octet-stream wasm 密文 → hsw mode0 解密 → msgpack：`{"pass":true,"generated_pass_UUID":"P1_..."}` |
| 上游验证 | captcha 令牌被 NVIDIA 接受并映射到匿名账号；predict 返回 500 内嵌 404 为 `nv-function-id` 与账号绑定过期（独立于 captcha，需刷新 registry） |

## getcaptcha 协议要点（实测确认）

- endpoint：`POST https://api.hcaptcha.com/getcaptcha/<sitekey>`（sitekey 为路径段）。
- 明文参数：`v`（前端 build hash）、`sitekey`、`host`、`hl`、`n`、`c`（JSON 字符串化挑战 spec `{"type":"hsw","req":"<jwt>"}`）。
- `checksiteconfig` 返回 `features.enc_get_req=true` → 本 sitekey 强制加密：body 为 msgpack `[spec_json, ext18(密文)]`，
  加密/解密统一调用 hsw WASM 的 mode 1（加密）/ mode 0（解密），密钥在 wasm 内。
- 响应 `{"pass":true,"generated_pass_UUID":"P1_..."}`，token 为 JWT（头部 `{"alg":"HS256","typ":"JWT"}`）。

## 已知边界与后续

1. ✅ 已解决：v8go 的 `WebAssembly.instantiate` Promise 不 settle（同步化补丁）；atob 二进制往返失真（Go 侧 rune(byte) 重建）；
   hsw.js bundle 轮换（instance 形状 regex 化，v1/v2 双形态兼容）。
2. ⚠️ 加密提交参数目前仅 `{v,sitekey,host,hl,n}`，无 motionData/pem；当前站点放行，若后续开始校验 motion 需补真实 motion VM 数据。
3. ⚠️ fp 组件/事件为静态模板样例；服务端目前接受（invisible 无交互站点），强风控站点可能需要更逼真的值。
4. ⚠️ 上游 predict 的 `nv-function-id` 与匿名账号绑定已过期（7 月 registry）→ 需重跑 `scripts/scrape_playground_models.py` 刷新，与 captcha 无关。
5. 性能：单次 ~1s；可仿照现有 `internal/captcha.Pool` 做 token 预热池（hsw 求解器实例可缓存复用，见 `SolveN` 的 sync.Map）。

## 与现有浏览器方案对照

| 维度 | 浏览器方案（internal/captcha） | 纯 Go 方案（本次新增） |
|---|---|---|
| 依赖 | headless Chrome + chromedp | v8go（cgo，预编译 V8） |
| 冷启动 | 首 navigate 6–10s | 一次性下载/编译 wasm（可缓存） |
| 稳态单 token | ~300ms（sticky execute） | ~1s（含指纹+挖矿+加密往返） |
| 并发 | 多 Chrome 进程 | 单进程多 isolate/协程（V8 isolate 可复用） |
| 部署体积 | Docker 需 Chromium ≥100MB | 二进制可纯 Go 构建（cgo 仍需 V8 库） |

两个方案可并存：浏览器方案作为兜底/持续可用路径，纯 Go 方案作为低资源、可横向扩展的补充。
