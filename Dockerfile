# syntax=docker/dockerfile:1
FROM golang:1.26 AS builder

# Build-time date/version injected into config.date / config.version (override
# the "unknown"/"dev" defaults in config/version.go). Pass via
# --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) --build-arg BUILD_VERSION=<ver>.
ARG BUILD_DATE=unknown
ARG BUILD_VERSION=dev

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/vgate-project/vgate-server/config.date=${BUILD_DATE} -X github.com/vgate-project/vgate-server/config.version=${BUILD_VERSION}" \
    -o /out/vgate .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates netcat-openbsd
WORKDIR /app
COPY --from=builder /out/vgate /app/vgate

# The proxy listens on the port delivered by the manager's node config (not this
# file). Set LISTEN_PORT to match that port so the healthcheck probes the right port.
ENV LISTEN_PORT=10086
EXPOSE 10086

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD nc -z -w 2 localhost "$LISTEN_PORT" || exit 1

ENTRYPOINT ["/app/vgate"]
CMD ["--config", "/app/config.yml"]
