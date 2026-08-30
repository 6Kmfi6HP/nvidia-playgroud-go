# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
	-ldflags="-s -w -X main.version=${VERSION}" \
	-o /out/serve ./cmd/serve

FROM debian:bookworm-slim

# 不需要 Chromium：验证码由纯 Go 的 hCaptcha PoW 求解器解决，不依赖任何
# 浏览器。仅保留 HTTPS 证书与探活工具。
# - ca-certificates: 信任系统根证书，支持 https 上游请求
# - wget: 供下方 HEALTHCHECK 探活使用
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	wget \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /out/serve /usr/local/bin/serve

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 \
	CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["serve"]
CMD ["-auto", "-addr", ":8080"]
