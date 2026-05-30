#!/bin/bash
set -e

echo "[dind-entrypoint] Starting nested Docker daemon..."
# Start the Docker daemon in the background using the official entrypoint
dockerd-entrypoint.sh &

# Wait for the Docker daemon to be fully ready
echo "[dind-entrypoint] Waiting for Docker daemon to initialize..."
timeout=30
while ! docker info >/dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ "$timeout" -le 0 ]; then
        echo "[dind-entrypoint] ERROR: Docker daemon failed to start within 30 seconds."
        exit 1
    fi
    sleep 1
done
echo "[dind-entrypoint] Docker daemon is up and running!"

# Run any extra diagnostic checks on runtimes
echo "[dind-entrypoint] Verifying available Docker runtimes:"
docker info | grep -E "Runtimes|runsc|crun" || true

# Generate TLS certificates for testing if they do not exist
if [ ! -f /app/config/ca.crt ]; then
    echo "[dind-entrypoint] Generating test TLS certificates..."
    openssl req -x509 -new -nodes -keyout /app/config/ca.key -sha256 -days 365 -out /app/config/ca.crt -subj "/CN=Test CA"
    openssl req -new -nodes -keyout /app/config/server.key -out /app/config/server.csr -subj "/CN=ottergate.loop"
    openssl x509 -req -in /app/config/server.csr -CA /app/config/ca.crt -CAkey /app/config/ca.key -CAcreateserial -out /app/config/server.crt -days 365 -sha256 -extfile <(printf "subjectAltName=DNS:ottergate.loop,DNS:*.ottergate.loop,IP:172.21.0.100")
    openssl req -new -nodes -keyout /app/config/client.key -out /app/config/client.csr -subj "/CN=client.test.local"
    openssl x509 -req -in /app/config/client.csr -CA /app/config/ca.crt -CAkey /app/config/ca.key -CAcreateserial -out /app/config/client.crt -days 365 -sha256 -extfile <(printf "subjectAltName=DNS:client.test.local")
fi

# Spin up the inner docker compose setup with project name forced to "app" to avoid renaming subnet conflicts
echo "[dind-entrypoint] Starting Ottergate and sandbox clients via inner Docker Compose..."
docker compose -p app -f /app/docker/docker-compose.inner.yml up -d --build

echo "[dind-entrypoint] System initialized successfully. Streaming inner logs:"
# Tail logs from the inner services to keep container running and output logs
docker compose -p app -f /app/docker/docker-compose.inner.yml logs -f
