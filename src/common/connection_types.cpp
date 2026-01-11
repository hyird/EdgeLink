#include "common/connection_types.hpp"

namespace edgelink {

const char* client_session_state_name(ClientSessionState state) {
    switch (state) {
        case ClientSessionState::DISCONNECTED: return "DISCONNECTED";
        case ClientSessionState::AUTHENTICATING: return "AUTHENTICATING";
        case ClientSessionState::AUTHENTICATED: return "AUTHENTICATED";
        case ClientSessionState::CONFIGURING: return "CONFIGURING";
        case ClientSessionState::ONLINE: return "ONLINE";
        case ClientSessionState::DEGRADED: return "DEGRADED";
        default: return "UNKNOWN";
    }
}

const char* relay_session_state_name(RelaySessionState state) {
    switch (state) {
        case RelaySessionState::DISCONNECTED: return "DISCONNECTED";
        case RelaySessionState::AUTHENTICATING: return "AUTHENTICATING";
        case RelaySessionState::CONNECTED: return "CONNECTED";
        case RelaySessionState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* p2p_negotiation_phase_name(P2PNegotiationPhase phase) {
    switch (phase) {
        case P2PNegotiationPhase::NONE: return "NONE";
        case P2PNegotiationPhase::INITIATED: return "INITIATED";
        case P2PNegotiationPhase::ENDPOINTS_SENT: return "ENDPOINTS_SENT";
        case P2PNegotiationPhase::ESTABLISHED: return "ESTABLISHED";
        case P2PNegotiationPhase::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

const char* endpoint_state_name(EndpointState state) {
    switch (state) {
        case EndpointState::UNKNOWN: return "UNKNOWN";
        case EndpointState::PENDING: return "PENDING";
        case EndpointState::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

const char* route_state_name(RouteState state) {
    switch (state) {
        case RouteState::NONE: return "NONE";
        case RouteState::ANNOUNCED: return "ANNOUNCED";
        case RouteState::WITHDRAWN: return "WITHDRAWN";
        default: return "UNKNOWN";
    }
}

const char* session_event_name(SessionEvent event) {
    switch (event) {
        case SessionEvent::CONTROL_CONNECT: return "CONTROL_CONNECT";
        case SessionEvent::CONTROL_DISCONNECT: return "CONTROL_DISCONNECT";
        case SessionEvent::RELAY_CONNECT: return "RELAY_CONNECT";
        case SessionEvent::RELAY_DISCONNECT: return "RELAY_DISCONNECT";
        case SessionEvent::AUTH_REQUEST: return "AUTH_REQUEST";
        case SessionEvent::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case SessionEvent::AUTH_FAILED: return "AUTH_FAILED";
        case SessionEvent::CONFIG_SENT: return "CONFIG_SENT";
        case SessionEvent::CONFIG_ACK: return "CONFIG_ACK";
        case SessionEvent::ENDPOINT_UPDATE: return "ENDPOINT_UPDATE";
        case SessionEvent::ENDPOINT_ACK_SENT: return "ENDPOINT_ACK_SENT";
        case SessionEvent::P2P_INIT_RECEIVED: return "P2P_INIT_RECEIVED";
        case SessionEvent::P2P_ENDPOINT_SENT: return "P2P_ENDPOINT_SENT";
        case SessionEvent::P2P_STATUS_RECEIVED: return "P2P_STATUS_RECEIVED";
        case SessionEvent::ROUTE_ANNOUNCE: return "ROUTE_ANNOUNCE";
        case SessionEvent::ROUTE_WITHDRAW: return "ROUTE_WITHDRAW";
        case SessionEvent::PING_RECEIVED: return "PING_RECEIVED";
        case SessionEvent::PONG_SENT: return "PONG_SENT";
        case SessionEvent::HEARTBEAT_TIMEOUT: return "HEARTBEAT_TIMEOUT";
        default: return "UNKNOWN";
    }
}

} // namespace edgelink
