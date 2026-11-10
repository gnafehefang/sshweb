# ---------- build ----------
FROM golang:1.25-alpine AS build
WORKDIR /src
# 国内构建可取消下一行注释换用代理
# ENV GOPROXY=https://mirrors.tencent.com/go,https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sshweb .

# ---------- run ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && addgroup -S sshweb && adduser -S sshweb -G sshweb
ENV TZ=Asia/Shanghai
WORKDIR /app
COPY --from=build /out/sshweb /app/sshweb
RUN mkdir -p /data && chown sshweb:sshweb /data
USER sshweb
VOLUME ["/data"]
# 45678 公开口（农场/探针），45679 管理口（只应映射到宿主机回环地址，经私有网关访问）
EXPOSE 45678 45679
# 默认探针版：不开启网页 SSH，不加载任何 SSH 凭据
ENV SSHWEB_ENABLE_SSH=0
ENTRYPOINT ["/app/sshweb"]
# 容器内必须监听 0.0.0.0，访问范围由宿主机侧端口映射（127.0.0.1:...）限制
CMD ["-listen", "0.0.0.0:45678", "-admin-listen", "0.0.0.0:45679", "-data", "/data"]
