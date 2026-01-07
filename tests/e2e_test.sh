#!/bin/bash
# EdgeLink End-to-End Test Script
# Tests: Controller -> Relay Server -> 2 Clients communication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
TEST_DIR="/tmp/edgelink-e2e-test"

CONTROLLER_BIN="$BUILD_DIR/edgelink-controller"
SERVER_BIN="$BUILD_DIR/edgelink-server"
CLIENT_BIN="$BUILD_DIR/edgelink-client"

# Test configuration
CONTROLLER_PORT=18080
CONTROLLER_WS_PORT=18081
RELAY_PORT=19000
RELAY_ID=1

NETWORK_CIDR="10.200.0.0/16"
CLIENT1_IP="10.200.0.1"
CLIENT2_IP="10.200.0.2"

# PIDs for cleanup
CONTROLLER_PID=""
RELAY_PID=""
CLIENT1_PID=""
CLIENT2_PID=""

cleanup() {
    log_info "Cleaning up..."
    
    # Kill processes
    [ -n "$CLIENT2_PID" ] && kill $CLIENT2_PID 2>/dev/null || true
    [ -n "$CLIENT1_PID" ] && kill $CLIENT1_PID 2>/dev/null || true
    [ -n "$RELAY_PID" ] && kill $RELAY_PID 2>/dev/null || true
    [ -n "$CONTROLLER_PID" ] && kill $CONTROLLER_PID 2>/dev/null || true
    
    # Remove TUN devices
    ip link del wss-test1 2>/dev/null || true
    ip link del wss-test2 2>/dev/null || true
    
    # Wait for processes to die
    sleep 1
    
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Check binaries exist
check_binaries() {
    log_info "Checking binaries..."
    
    for bin in "$CONTROLLER_BIN" "$SERVER_BIN" "$CLIENT_BIN"; do
        if [ ! -x "$bin" ]; then
            log_error "Binary not found or not executable: $bin"
            exit 1
        fi
    done
    
    log_ok "All binaries found"
}

# Create test directory and configs
setup_test_env() {
    log_info "Setting up test environment..."
    
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"/{controller,relay,client1,client2}
    
    # Generate test keys using openssl (Ed25519 for machine keys)
    log_info "Generating test keys..."
    
    # For simplicity, use fixed test keys (base64 encoded 32-byte random)
    # In production, use proper key generation
    MACHINE_KEY1_PUB=$(openssl rand -base64 32)
    MACHINE_KEY1_PRIV=$(openssl rand -base64 32)
    MACHINE_KEY2_PUB=$(openssl rand -base64 32)
    MACHINE_KEY2_PRIV=$(openssl rand -base64 32)
    RELAY_KEY=$(openssl rand -base64 32)
    
    # Controller config
    cat > "$TEST_DIR/controller/config.json" << EOF
{
  "http": {
    "address": "0.0.0.0",
    "port": $CONTROLLER_PORT
  },
  "websocket": {
    "address": "0.0.0.0",
    "port": $CONTROLLER_WS_PORT
  },
  "database": {
    "path": "$TEST_DIR/controller/edgelink.db"
  },
  "auth": {
    "jwt_secret": "test-jwt-secret-key-12345678901234567890"
  },
  "logging": {
    "level": "debug"
  }
}
EOF

    # Relay server config
    cat > "$TEST_DIR/relay/config.json" << EOF
{
  "server": {
    "address": "0.0.0.0",
    "port": $RELAY_PORT,
    "relay_id": $RELAY_ID
  },
  "controller": {
    "url": "ws://127.0.0.1:$CONTROLLER_WS_PORT/ws/relay"
  },
  "auth": {
    "relay_key": "$RELAY_KEY"
  },
  "logging": {
    "level": "debug"
  }
}
EOF

    # Client 1 config
    cat > "$TEST_DIR/client1/config.json" << EOF
{
  "controller": {
    "url": "ws://127.0.0.1:$CONTROLLER_WS_PORT/ws/control"
  },
  "auth": {
    "machine_key_pub": "$MACHINE_KEY1_PUB",
    "machine_key_priv": "$MACHINE_KEY1_PRIV"
  },
  "network": {
    "tun_name": "wss-test1",
    "mtu": 1400
  },
  "logging": {
    "level": "debug"
  }
}
EOF

    # Client 2 config
    cat > "$TEST_DIR/client2/config.json" << EOF
{
  "controller": {
    "url": "ws://127.0.0.1:$CONTROLLER_WS_PORT/ws/control"
  },
  "auth": {
    "machine_key_pub": "$MACHINE_KEY2_PUB",
    "machine_key_priv": "$MACHINE_KEY2_PRIV"
  },
  "network": {
    "tun_name": "wss-test2",
    "mtu": 1400
  },
  "logging": {
    "level": "debug"
  }
}
EOF

    log_ok "Test environment ready at $TEST_DIR"
}

# Start Controller
start_controller() {
    log_info "Starting Controller..."
    
    cd "$TEST_DIR/controller"
    $CONTROLLER_BIN -c config.json > controller.log 2>&1 &
    CONTROLLER_PID=$!
    
    # Wait for controller to start
    sleep 2
    
    if ! kill -0 $CONTROLLER_PID 2>/dev/null; then
        log_error "Controller failed to start"
        cat controller.log
        exit 1
    fi
    
    # Check if HTTP port is listening
    if ! nc -z 127.0.0.1 $CONTROLLER_PORT 2>/dev/null; then
        log_error "Controller HTTP port not listening"
        cat controller.log
        exit 1
    fi
    
    log_ok "Controller started (PID: $CONTROLLER_PID)"
}

# Initialize network and nodes via API
setup_network() {
    log_info "Setting up network via Controller API..."
    
    # Create network
    NETWORK_RESP=$(curl -s -X POST "http://127.0.0.1:$CONTROLLER_PORT/api/v1/networks" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"test-network\",
            \"cidr\": \"$NETWORK_CIDR\",
            \"description\": \"E2E test network\"
        }" 2>/dev/null || echo '{"error":"curl failed"}')
    
    log_info "Network creation response: $NETWORK_RESP"
    
    NETWORK_ID=$(echo "$NETWORK_RESP" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
    
    if [ -z "$NETWORK_ID" ] || [ "$NETWORK_ID" = "null" ]; then
        log_warn "Could not create network, trying to get existing..."
        NETWORK_ID=1
    fi
    
    log_ok "Network ID: $NETWORK_ID"
    
    # Register relay server
    RELAY_RESP=$(curl -s -X POST "http://127.0.0.1:$CONTROLLER_PORT/api/v1/relays" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"test-relay\",
            \"region\": \"local\",
            \"address\": \"127.0.0.1\",
            \"port\": $RELAY_PORT,
            \"public_key\": \"$(cat "$TEST_DIR/relay/config.json" | grep relay_key | cut -d'"' -f4)\"
        }" 2>/dev/null || echo '{"error":"curl failed"}')
    
    log_info "Relay registration response: $RELAY_RESP"
    
    # Register client nodes (pre-auth)
    # In real usage, clients register themselves; for testing we pre-create them
    
    NODE1_RESP=$(curl -s -X POST "http://127.0.0.1:$CONTROLLER_PORT/api/v1/nodes" \
        -H "Content-Type: application/json" \
        -d "{
            \"network_id\": $NETWORK_ID,
            \"name\": \"test-client-1\",
            \"machine_key\": \"$(cat "$TEST_DIR/client1/config.json" | grep machine_key_pub | cut -d'"' -f4)\",
            \"virtual_ip\": \"$CLIENT1_IP\"
        }" 2>/dev/null || echo '{"error":"curl failed"}')
    
    log_info "Node 1 registration response: $NODE1_RESP"
    
    NODE2_RESP=$(curl -s -X POST "http://127.0.0.1:$CONTROLLER_PORT/api/v1/nodes" \
        -H "Content-Type: application/json" \
        -d "{
            \"network_id\": $NETWORK_ID,
            \"name\": \"test-client-2\",
            \"machine_key\": \"$(cat "$TEST_DIR/client2/config.json" | grep machine_key_pub | cut -d'"' -f4)\",
            \"virtual_ip\": \"$CLIENT2_IP\"
        }" 2>/dev/null || echo '{"error":"curl failed"}')
    
    log_info "Node 2 registration response: $NODE2_RESP"
    
    log_ok "Network setup complete"
}

# Start Relay Server
start_relay() {
    log_info "Starting Relay Server..."
    
    cd "$TEST_DIR/relay"
    $SERVER_BIN -c config.json > relay.log 2>&1 &
    RELAY_PID=$!
    
    sleep 2
    
    if ! kill -0 $RELAY_PID 2>/dev/null; then
        log_error "Relay server failed to start"
        cat relay.log
        exit 1
    fi
    
    # Check if relay port is listening
    if ! nc -z 127.0.0.1 $RELAY_PORT 2>/dev/null; then
        log_warn "Relay port not listening yet, waiting..."
        sleep 2
    fi
    
    log_ok "Relay Server started (PID: $RELAY_PID)"
}

# Start Clients
start_clients() {
    log_info "Starting Client 1..."
    
    cd "$TEST_DIR/client1"
    $CLIENT_BIN -c config.json > client1.log 2>&1 &
    CLIENT1_PID=$!
    
    sleep 2
    
    log_info "Starting Client 2..."
    
    cd "$TEST_DIR/client2"
    $CLIENT_BIN -c config.json > client2.log 2>&1 &
    CLIENT2_PID=$!
    
    sleep 3
    
    # Check if clients are running
    if ! kill -0 $CLIENT1_PID 2>/dev/null; then
        log_error "Client 1 failed to start"
        cat "$TEST_DIR/client1/client1.log"
        exit 1
    fi
    
    if ! kill -0 $CLIENT2_PID 2>/dev/null; then
        log_error "Client 2 failed to start"
        cat "$TEST_DIR/client2/client2.log"
        exit 1
    fi
    
    log_ok "Both clients started"
}

# Verify TUN devices
check_tun_devices() {
    log_info "Checking TUN devices..."
    
    sleep 2
    
    if ip link show wss-test1 >/dev/null 2>&1; then
        log_ok "TUN device wss-test1 exists"
        ip addr show wss-test1
    else
        log_warn "TUN device wss-test1 not found (may need root)"
    fi
    
    if ip link show wss-test2 >/dev/null 2>&1; then
        log_ok "TUN device wss-test2 exists"
        ip addr show wss-test2
    else
        log_warn "TUN device wss-test2 not found (may need root)"
    fi
}

# Test connectivity
test_connectivity() {
    log_info "Testing connectivity..."
    
    # Wait for connections to establish
    sleep 3
    
    # Try ping from client1 to client2
    if ping -c 3 -W 2 -I wss-test1 $CLIENT2_IP >/dev/null 2>&1; then
        log_ok "Ping from Client 1 to Client 2 successful!"
    else
        log_warn "Ping failed (may be expected if clients not fully connected)"
    fi
    
    # Try ping from client2 to client1
    if ping -c 3 -W 2 -I wss-test2 $CLIENT1_IP >/dev/null 2>&1; then
        log_ok "Ping from Client 2 to Client 1 successful!"
    else
        log_warn "Ping failed (may be expected if clients not fully connected)"
    fi
}

# Show logs summary
show_logs() {
    log_info "=== Controller Log (last 20 lines) ==="
    tail -20 "$TEST_DIR/controller/controller.log" 2>/dev/null || echo "(no log)"
    
    echo ""
    log_info "=== Relay Log (last 20 lines) ==="
    tail -20 "$TEST_DIR/relay/relay.log" 2>/dev/null || echo "(no log)"
    
    echo ""
    log_info "=== Client 1 Log (last 20 lines) ==="
    tail -20 "$TEST_DIR/client1/client1.log" 2>/dev/null || echo "(no log)"
    
    echo ""
    log_info "=== Client 2 Log (last 20 lines) ==="
    tail -20 "$TEST_DIR/client2/client2.log" 2>/dev/null || echo "(no log)"
}

# Check API endpoints
test_api() {
    log_info "Testing Controller API..."
    
    # Health check
    HEALTH=$(curl -s "http://127.0.0.1:$CONTROLLER_PORT/health" 2>/dev/null)
    if [ -n "$HEALTH" ]; then
        log_ok "Health endpoint: $HEALTH"
    else
        log_warn "Health endpoint not responding"
    fi
    
    # List networks
    NETWORKS=$(curl -s "http://127.0.0.1:$CONTROLLER_PORT/api/v1/networks" 2>/dev/null)
    log_info "Networks: $NETWORKS"
    
    # List nodes
    NODES=$(curl -s "http://127.0.0.1:$CONTROLLER_PORT/api/v1/nodes" 2>/dev/null)
    log_info "Nodes: $NODES"
    
    # List relays
    RELAYS=$(curl -s "http://127.0.0.1:$CONTROLLER_PORT/api/v1/relays" 2>/dev/null)
    log_info "Relays: $RELAYS"
}

# Main test flow
main() {
    echo "==========================================="
    echo "  EdgeLink End-to-End Test"
    echo "==========================================="
    echo ""
    
    check_binaries
    setup_test_env
    start_controller
    
    # Give controller time to initialize
    sleep 1
    
    test_api
    setup_network
    
    start_relay
    
    # Give relay time to register
    sleep 2
    
    start_clients
    check_tun_devices
    
    # Wait for mesh to stabilize
    log_info "Waiting for mesh network to stabilize..."
    sleep 5
    
    test_connectivity
    
    echo ""
    echo "==========================================="
    log_info "Test Summary"
    echo "==========================================="
    
    # Show process status
    echo ""
    log_info "Process Status:"
    ps aux | grep -E "edgelink-(controller|server|client)" | grep -v grep || echo "(processes may have exited)"
    
    echo ""
    show_logs
    
    echo ""
    log_info "Test environment: $TEST_DIR"
    log_info "Press Ctrl+C to stop all services and cleanup"
    
    # Keep running for manual testing
    read -p "Press Enter to cleanup and exit..."
}

# Run main
main
