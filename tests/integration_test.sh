#!/bin/bash
# tests/integration_test.sh - End-to-end test for tlscap
# Requires: root, nginx, openssl, curl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TLSCAP="$PROJECT_DIR/tlscap"
TMPDIR=$(mktemp -d)
CAPTURE_FILE="$TMPDIR/capture.txt"
NGINX_CONF="$TMPDIR/nginx.conf"
NGINX_PID=""

cleanup() {
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        kill "$NGINX_PID" 2>/dev/null || true
    fi
    if [ -n "${TLSCAP_PID:-}" ] && kill -0 "$TLSCAP_PID" 2>/dev/null; then
        kill "$TLSCAP_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== tlscap integration test ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: requires root"
    exit 0
fi

if ! command -v nginx &>/dev/null; then
    echo "SKIP: nginx not installed"
    exit 0
fi

if [ ! -x "$TLSCAP" ]; then
    echo "FAIL: tlscap binary not found. Run 'make' first."
    exit 1
fi

openssl req -x509 -newkey rsa:2048 -keyout "$TMPDIR/key.pem" \
    -out "$TMPDIR/cert.pem" -days 1 -nodes \
    -subj "/CN=localhost" 2>/dev/null

cat > "$NGINX_CONF" <<CONF
worker_processes 1;
pid $TMPDIR/nginx.pid;
error_log $TMPDIR/error.log;

events { worker_connections 16; }

http {
    access_log $TMPDIR/access.log;
    server {
        listen 18443 ssl;
        ssl_certificate     $TMPDIR/cert.pem;
        ssl_certificate_key $TMPDIR/key.pem;
        location / {
            return 200 '{"status":"ok"}';
            add_header Content-Type application/json;
        }
    }
}
CONF

nginx -c "$NGINX_CONF"
NGINX_PID=$(cat "$TMPDIR/nginx.pid")
echo "nginx started (PID: $NGINX_PID) on port 18443"

# Don't use -p filtering: nginx master PID != worker PID where SSL ops happen
$TLSCAP > "$CAPTURE_FILE" 2>/dev/null &
TLSCAP_PID=$!
sleep 1

curl -sk https://localhost:18443/test-endpoint > /dev/null 2>&1
sleep 1

kill "$TLSCAP_PID" 2>/dev/null || true
wait "$TLSCAP_PID" 2>/dev/null || true

echo "--- Captured output ---"
cat "$CAPTURE_FILE"
echo "--- End ---"

PASS=true

if ! grep -q "GET /test-endpoint" "$CAPTURE_FILE"; then
    echo "FAIL: request not captured"
    PASS=false
fi

if ! grep -q '"status":"ok"' "$CAPTURE_FILE"; then
    echo "FAIL: response not captured"
    PASS=false
fi

if ! grep -q "READ" "$CAPTURE_FILE"; then
    echo "FAIL: READ direction not shown"
    PASS=false
fi

if ! grep -q "WRITE" "$CAPTURE_FILE"; then
    echo "FAIL: WRITE direction not shown"
    PASS=false
fi

if [ "$PASS" = true ]; then
    echo "PASS: all checks passed"
    exit 0
else
    echo "FAIL: some checks failed"
    exit 1
fi
