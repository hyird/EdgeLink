// Type-safe event definitions for async service communication
// Uses std::variant of distinct structs — compile-time exhaustive matching via std::visit.
// Replaces the per-event channel pattern with unified variant event channels.

#pragma once

#include "common/types.hpp"
#include "common/message.hpp"

#include <boost/asio.hpp>
#include <boost/cobalt/channel.hpp>

#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

namespace edgelink::events {

// ============================================================================
// Control Channel Events
// ============================================================================
namespace ctrl {

struct Connected {
    NodeId node_id;
    IPv4Address virtual_ip;
    uint8_t subnet_mask;
    std::vector<uint8_t> relay_token;
};

struct Disconnected {
    std::string reason;
};

struct ConfigReceived {
    Config config;
};

struct ConfigUpdateReceived {
    ConfigUpdate update;
};

struct RouteUpdateReceived {
    RouteUpdate route_update;
};

struct PeerRoutingUpdateReceived {
    PeerRoutingUpdate update;
};

struct P2PEndpointReceived {
    P2PEndpointMsg endpoint;
};

struct Error {
    uint16_t code;
    std::string message;
};

using Event = std::variant<
    Connected,
    Disconnected,
    ConfigReceived,
    ConfigUpdateReceived,
    RouteUpdateReceived,
    PeerRoutingUpdateReceived,
    P2PEndpointReceived,
    Error
>;

} // namespace ctrl

// ============================================================================
// Relay Channel Events
// ============================================================================
namespace relay {

struct Connected {};

struct Disconnected {
    std::string reason;
};

struct DataReceived {
    NodeId src_node;
    std::vector<uint8_t> plaintext;
};

struct Pong {
    uint16_t rtt_ms;
};

using Event = std::variant<Connected, Disconnected, DataReceived, Pong>;

} // namespace relay

// ============================================================================
// P2P Manager Events
// ============================================================================
namespace p2p {

struct EndpointsReady {
    std::vector<Endpoint> endpoints;
};

struct InitNeeded {
    P2PInit init;
};

struct StatusChanged {
    P2PStatusMsg status;
};

struct DataReceived {
    NodeId peer_id;
    std::vector<uint8_t> plaintext;
};

using Event = std::variant<EndpointsReady, InitNeeded, StatusChanged, DataReceived>;

} // namespace p2p

// ============================================================================
// Typed Event Channel aliases
// ============================================================================

using CtrlEventChannel = cobalt::channel<ctrl::Event>;
using RelayEventChannel = cobalt::channel<relay::Event>;
using P2PEventChannel = cobalt::channel<p2p::Event>;

} // namespace edgelink::events
