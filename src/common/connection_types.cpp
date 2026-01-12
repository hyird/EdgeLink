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

const char* control_plane_state_name(ControlPlaneState state) {
    switch (state) {
        case ControlPlaneState::DISCONNECTED: return "DISCONNECTED";
        case ControlPlaneState::CONNECTING: return "CONNECTING";
        case ControlPlaneState::AUTHENTICATING: return "AUTHENTICATING";
        case ControlPlaneState::CONFIGURING: return "CONFIGURING";
        case ControlPlaneState::READY: return "READY";
        case ControlPlaneState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* data_plane_state_name(DataPlaneState state) {
    switch (state) {
        case DataPlaneState::OFFLINE: return "OFFLINE";
        case DataPlaneState::RELAY_ONLY: return "RELAY_ONLY";
        case DataPlaneState::HYBRID: return "HYBRID";
        case DataPlaneState::DEGRADED: return "DEGRADED";
        default: return "UNKNOWN";
    }
}

const char* connection_phase_name(ConnectionPhase phase) {
    switch (phase) {
        case ConnectionPhase::OFFLINE: return "OFFLINE";
        case ConnectionPhase::AUTHENTICATING: return "AUTHENTICATING";
        case ConnectionPhase::CONFIGURING: return "CONFIGURING";
        case ConnectionPhase::ESTABLISHING: return "ESTABLISHING";
        case ConnectionPhase::ONLINE: return "ONLINE";
        case ConnectionPhase::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* client_endpoint_sync_state_name(ClientEndpointSyncState state) {
    switch (state) {
        case ClientEndpointSyncState::NOT_READY: return "NOT_READY";
        case ClientEndpointSyncState::DISCOVERING: return "DISCOVERING";
        case ClientEndpointSyncState::READY: return "READY";
        case ClientEndpointSyncState::UPLOADING: return "UPLOADING";
        case ClientEndpointSyncState::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

const char* route_sync_state_name(RouteSyncState state) {
    switch (state) {
        case RouteSyncState::DISABLED: return "DISABLED";
        case RouteSyncState::PENDING: return "PENDING";
        case RouteSyncState::SYNCING: return "SYNCING";
        case RouteSyncState::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

const char* peer_data_path_name(PeerDataPath path) {
    switch (path) {
        case PeerDataPath::UNKNOWN: return "UNKNOWN";
        case PeerDataPath::RELAY: return "RELAY";
        case PeerDataPath::P2P: return "P2P";
        case PeerDataPath::UNREACHABLE: return "UNREACHABLE";
        default: return "UNKNOWN";
    }
}

const char* p2p_connection_state_name(P2PConnectionState state) {
    switch (state) {
        case P2PConnectionState::NONE: return "NONE";
        case P2PConnectionState::INITIATING: return "INITIATING";
        case P2PConnectionState::WAITING_ENDPOINT: return "WAITING_ENDPOINT";
        case P2PConnectionState::PUNCHING: return "PUNCHING";
        case P2PConnectionState::CONNECTED: return "CONNECTED";
        case P2PConnectionState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}


const char* relay_connection_state_name(RelayConnectionState state) {
    switch (state) {
        case RelayConnectionState::DISCONNECTED: return "DISCONNECTED";
        case RelayConnectionState::CONNECTING: return "CONNECTING";
        case RelayConnectionState::AUTHENTICATING: return "AUTHENTICATING";
        case RelayConnectionState::CONNECTED: return "CONNECTED";
        case RelayConnectionState::RECONNECTING: return "RECONNECTING";
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
