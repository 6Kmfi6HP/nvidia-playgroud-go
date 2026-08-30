# Contributing / 贡献指南

Contributions are welcome. This project reverse-engineers the NVIDIA Build Playground API
(build.nvidia.com anonymous multi-model predict + hCaptcha PoW); keep that
context in mind when opening issues or pull requests.

## English

- **Issues:** Use issues for bugs, captcha/Upstream-API changes, or feature requests.
  Include the upstream API response (status code + body) and the serve command you ran.
- **Pull requests:** Keep changes focused. New CLI tools belong under `cmd/`, library
  code under the package root or `internal/`. Run `go build ./...` and `go vet ./...`
  before submitting.
- **Upstream drift:** NVIDIA may change endpoints, headers, or the captcha flow.
  If the API breaks, open an issue with the captured request/response (redact tokens).

## 中文

- **Issue：** 用于反馈 bug、captcha/上游 API 变更或功能请求。请附上上游响应
  （状态码 + body）和你运行的 serve 命令。
- **PR：** 改动请保持聚焦。新 CLI 工具放在 `cmd/` 下，库代码放在包根或 `internal/`。
  提交前运行 `go build ./...` 和 `go vet ./...`。
- **上游漂移：** NVIDIA 可能修改端点、请求头或 captcha 流程。若 API 失效，请开
  issue 并附上抓到的请求/响应（token 请打码）。
