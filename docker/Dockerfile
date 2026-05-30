# Multi-stage Dockerfile for Ottergate Go Rewrite
FROM golang:1.22-alpine AS build

WORKDIR /app

# Copy Go module manifest and source files
COPY go.mod ./
COPY main.go ./
COPY pkg/ ./pkg/

# Build static, optimized binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ottergate main.go

# Production runtime stage
FROM alpine:latest AS runtime

WORKDIR /app

# Copy compiled binary from build stage
COPY --from=build /app/ottergate ./ottergate

# Expose zero-trust DNS and proxy ports:
# - 53/udp & 53/tcp: DNS resolving boundaries
# - 80/tcp: HTTP L7 router
# - 443/tcp: SNI transparent proxy
# - 853/tcp: DNS-over-TLS (DoT)
# - 8080/tcp: Control Plane TCP bind
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 853/tcp 8080/tcp

# Run as a non-privileged system user for robust process isolation
RUN addgroup -S ottergate && adduser -S ottergate -G ottergate
USER ottergate

# Define clean startup command structure
ENTRYPOINT ["/app/ottergate"]
CMD ["start"]
