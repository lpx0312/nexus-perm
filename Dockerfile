# ============================================================================
# Nexus 权限管理平台 - 单镜像（Go 后端 + 内嵌前端）
#
# 多阶段构建：builder 用 golang:1.26-alpine 交叉编译纯 Go 二进制
# （modernc.org/sqlite 为纯 Go 驱动，无需 CGO），运行阶段用 alpine。
# 数据目录 /data 需挂载卷持久化（SQLite + 密钥）。
# ============================================================================

FROM golang:1.26-alpine AS builder

WORKDIR /app

# 先拷贝依赖清单，利用层缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o /out/nexus-perm .

# ---------------- 运行阶段 ----------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata wget

COPY --from=builder /out/nexus-perm /usr/local/bin/nexus-perm

# 数据目录：nexus-perm.db + secret.key + jwt.key + 初始密码文件
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

ENTRYPOINT ["nexus-perm"]
CMD ["-addr", "0.0.0.0:8080", "-data", "/data"]
