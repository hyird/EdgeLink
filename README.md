# EdgeLink

A high-performance mesh networking solution built with modern C++20.

## Features

- **Mesh Networking**: Direct peer-to-peer connections with automatic NAT traversal
- **Relay Servers**: WebSocket-based relay infrastructure for fallback connectivity
- **CDN Support**: Works through CDN proxies like Cloudflare
- **End-to-End Encryption**: ChaCha20-Poly1305 encryption with X25519 key exchange
- **Low Latency**: Real-time RTT measurement with optimized path selection
- **Cross-Platform**: Supports Linux (with TUN interface)

## Architecture

```
┌────────────────────┐
│    Controller      │  Control Plane:
│                    │  - Path calculation
│                    │  - Node discovery
│                    │  - JWT authentication
└────────┬───────────┘
         │
    ┌────┴────┐
    │         │
┌───┴───┐ ┌───┴───┐
│Relay-1│═│Relay-2│  ← WSS Mesh (Data Plane)
└───┬───┘ └───┬───┘
    │         │
 Node A    Node B
```

## Building

### Prerequisites

- CMake >= 3.16
- C++20 compatible compiler (GCC 11+, Clang 14+)
- Boost >= 1.81 (Beast, JSON, ASIO)
- OpenSSL >= 1.1
- libsodium >= 1.0.18

### Build Commands

```bash
mkdir build && cd build
cmake .. -DBUILD_SERVER=ON -DBUILD_CONTROLLER=ON -DBUILD_CLIENT=ON
make -j$(nproc)
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_CONTROLLER` | ON | Build the controller server |
| `BUILD_SERVER` | ON | Build the relay/STUN server |
| `BUILD_CLIENT` | ON | Build the client |
| `BUILD_TESTS` | ON | Build unit tests |

## Components

### Controller (`edgelink-controller`)

Central coordination server that handles:
- Node registration and authentication
- Path calculation based on latency data
- Relay list distribution
- Token blacklist management

### Relay Server (`edgelink-server`)

Relay server that handles:
- Node-to-Relay WSS connections
- Relay-to-Relay mesh connections
- STUN server for NAT detection
- Data forwarding

### Client (`edgelink-client`)

Node client that handles:
- TUN interface management
- Multiple relay connections
- P2P connection establishment
- End-to-end encryption

## Configuration

### Relay Server (server.json)

```json
{
  "name": "relay-asia-1",
  "controller": {
    "url": "wss://controller.example.com/ws/server",
    "token": "your-server-token"
  },
  "relay": {
    "listen_address": "0.0.0.0",
    "listen_port": 443,
    "external_url": "wss://relay-asia.example.com:443"
  },
  "mesh": {
    "peers": [
      "wss://relay-us.example.com/ws/mesh",
      "wss://relay-eu.example.com/ws/mesh"
    ],
    "auto_connect": true
  }
}
```

## Documentation

- [Design Document](docs/edgelink-design.md)
- [Relay Mesh Status](docs/RELAY_MESH_STATUS.md)

## License

MIT License
