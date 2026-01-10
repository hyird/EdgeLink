#pragma once

#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/channel.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <functional>
#include <memory>
#include <string>

namespace asio = boost::asio;
namespace ssl = asio::ssl;

namespace edgelink::client {

// Client configuration
struct ClientConfig {
    std::string controller_url = "wss://localhost:8443/api/v1/control";
    std::string authkey;
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{30};
};

// Client state
enum class ClientState {
    STOPPED,
    STARTING,
    AUTHENTICATING,
    CONNECTING_RELAY,
    RUNNING,
    RECONNECTING,
};

const char* client_state_name(ClientState state);

// Callbacks
struct ClientCallbacks {
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;
    std::function<void(NodeId peer_id, std::span<const uint8_t> data)> on_data_received;
    std::function<void(uint16_t code, const std::string& msg)> on_error;
};

// Main client coordinator
class Client : public std::enable_shared_from_this<Client> {
public:
    Client(asio::io_context& ioc, const ClientConfig& config);
    ~Client();

    // Start the client (authenticate and connect to relay)
    asio::awaitable<bool> start();

    // Stop the client
    asio::awaitable<void> stop();

    // Send data to a peer
    asio::awaitable<bool> send_to_peer(NodeId peer_id, std::span<const uint8_t> data);

    // Send data to a peer by virtual IP
    asio::awaitable<bool> send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data);

    // Set callbacks
    void set_callbacks(ClientCallbacks callbacks);

    // Accessors
    ClientState state() const { return state_; }
    bool is_running() const { return state_ == ClientState::RUNNING; }

    NodeId node_id() const { return crypto_.node_id(); }
    IPv4Address virtual_ip() const { return control_ ? control_->virtual_ip() : IPv4Address{}; }
    NetworkId network_id() const { return control_ ? control_->network_id() : 0; }

    CryptoEngine& crypto() { return crypto_; }
    PeerManager& peers() { return peers_; }

private:
    void setup_callbacks();

    // Keepalive timer
    asio::awaitable<void> keepalive_loop();

    // Reconnection logic
    asio::awaitable<void> reconnect();

    asio::io_context& ioc_;
    ssl::context ssl_ctx_;
    ClientConfig config_;
    ClientState state_ = ClientState::STOPPED;

    CryptoEngine crypto_;
    PeerManager peers_;

    std::shared_ptr<ControlChannel> control_;
    std::shared_ptr<RelayChannel> relay_;

    asio::steady_timer keepalive_timer_;
    asio::steady_timer reconnect_timer_;

    ClientCallbacks callbacks_;
};

} // namespace edgelink::client
