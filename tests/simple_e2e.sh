#!/bin/bash
# EdgeLink Simple E2E Test
# Test Controller -> Server -> Client connection flow

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

# Paths
BUILD_DIR="/home/claude/edgelink/edgelink/build"
CONFIG_DIR="/home/claude/edgelink/edgelink/config"
TEST_DIR="/tmp/edgelink-test-$$"

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

cleanup() {
    log "Cleaning up..."
    pkill -f "edgelink-controller" 2>/dev/null || true
    pkill -f "edgelink-server" 2>/dev/null || true
    pkill -f "edgelink-client" 2>/dev/null || true
    ip link del wss-test 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "========================================"
echo "  EdgeLink End-to-End Test"
echo "========================================"
echo ""

# =====================================================
# Phase 1: Controller
# =====================================================
log "Phase 1: Starting Controller..."

cat > controller.json << 'EOF'
{
    "http": {
        "address": "0.0.0.0",
        "port": 18080
    },
    "database": {
        "path": "./test.db"
    },
    "jwt": {
        "secret": "test-secret-key-for-e2e-testing-only"
    }
}
EOF

$BUILD_DIR/edgelink-controller -c controller.json > controller.log 2>&1 &
CONTROLLER_PID=$!
sleep 2

if ! kill -0 $CONTROLLER_PID 2>/dev/null; then
    err "Controller failed to start"
    cat controller.log
    exit 1
fi

# Test health
HEALTH=$(curl -s http://127.0.0.1:18080/health)
if [ "$HEALTH" = '{"status":"ok"}' ]; then
    ok "Controller health check passed"
else
    err "Controller health check failed: $HEALTH"
    exit 1
fi

# Check default network
NETWORKS=$(curl -s http://127.0.0.1:18080/api/v1/networks)
ok "Networks: $NETWORKS"

# =====================================================
# Phase 2: Register Node via API
# =====================================================
log "Phase 2: Registering test node..."

# Generate a test machine key (base64 encoded random bytes)
MACHINE_KEY_PUB=$(openssl rand -base64 32 | tr -d '\n')
MACHINE_KEY_PRIV=$(openssl rand -base64 32 | tr -d '\n')

log "Machine Key (pub): $MACHINE_KEY_PUB"

# Register node
NODE_RESP=$(curl -s -X POST http://127.0.0.1:18080/api/v1/nodes \
    -H "Content-Type: application/json" \
    -d "{
        \"network_id\": 1,
        \"name\": \"test-node-1\",
        \"machine_key\": \"$MACHINE_KEY_PUB\"
    }")

log "Node registration response: $NODE_RESP"

# Try to get node info
NODES=$(curl -s http://127.0.0.1:18080/api/v1/nodes)
ok "Nodes: $NODES"

# =====================================================
# Phase 3: Relay Server
# =====================================================
log "Phase 3: Starting Relay Server..."

cat > server.json << EOF
{
    "name": "test-relay",
    "controller": {
        "url": "ws://127.0.0.1:18080/ws/server",
        "token": "test-token"
    },
    "relay": {
        "listen_address": "0.0.0.0",
        "listen_port": 18081,
        "external_url": "ws://127.0.0.1:18081",
        "region": "local"
    },
    "stun": {
        "listen_address": "0.0.0.0",
        "listen_port": 13478,
        "external_ip": "127.0.0.1",
        "external_port": 13478
    }
}
EOF

$BUILD_DIR/edgelink-server -c server.json > server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 $SERVER_PID 2>/dev/null; then
    err "Server failed to start"
    cat server.log
    exit 1
fi

# Check relay port
if nc -z 127.0.0.1 18081 2>/dev/null; then
    ok "Relay Server listening on 18081"
else
    warn "Relay port 18081 not responding (may be normal)"
fi

# =====================================================
# Phase 4: Client (partial - needs root for TUN)
# =====================================================
log "Phase 4: Testing Client startup..."

cat > client.json << EOF
{
    "controller": {
        "url": "ws://127.0.0.1:18080/ws/control"
    },
    "identity": {
        "machine_key_pub": "$MACHINE_KEY_PUB",
        "machine_key_priv": "$MACHINE_KEY_PRIV"
    },
    "tun": {
        "name": "wss-test",
        "mtu": 1400
    }
}
EOF

# Test client with timeout (it will fail TUN creation in container but we test startup)
timeout 3 $BUILD_DIR/edgelink-client -c client.json -l debug > client.log 2>&1 || true

log "Client log:"
cat client.log

# =====================================================
# Phase 5: Check logs and status
# =====================================================
echo ""
log "=== Controller Log (last 15 lines) ==="
tail -15 controller.log

echo ""
log "=== Server Log (last 15 lines) ==="
tail -15 server.log

# =====================================================
# Summary
# =====================================================
echo ""
echo "========================================"
log "Test Summary"
echo "========================================"

# Check what's still running
echo ""
log "Running processes:"
ps aux | grep -E "edgelink" | grep -v grep || echo "(none)"

echo ""
log "Port status:"
netstat -tlnp 2>/dev/null | grep -E "1808[0-1]|13478" || ss -tlnp | grep -E "1808[0-1]|13478" || echo "(ports check failed)"

echo ""
ok "Test completed - check logs above for details"
echo ""
log "Test directory: $TEST_DIR"
log "Press Enter to cleanup and exit..."
read -r
