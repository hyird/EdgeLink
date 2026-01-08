#include "controller_client.hpp"
#include "grpc_relay_server.hpp"
#include "common/log.hpp"
#include "common/config.hpp"

#include <regex>

namespace edgelink {

// ============================================================================
// ControllerClient Implementation (gRPC version)
// ============================================================================

ControllerClient::ControllerClient(GrpcRelayServer& server, const ServerConfig& config)
    : server_(server)
    , config_(config) {

    LOG_INFO("ControllerClient initialized for {}", config_.controller.url);
}

ControllerClient::~ControllerClient() {
    disconnect();
}

void ControllerClient::connect() {
    if (running_) {
        LOG_WARN("Already connecting or connected to controller");
        return;
    }

    running_ = true;
    reconnect_attempts_ = 0;

    LOG_INFO("Connecting to controller at {}", config_.controller.url);

    // Start connection thread
    connection_thread_ = std::make_unique<std::thread>([this]() {
        run_connection();
    });
}

void ControllerClient::disconnect() {
    if (!running_) {
        return;
    }

    running_ = false;
    connected_ = false;
    registered_ = false;

    // Cancel the gRPC context
    if (context_) {
        context_->TryCancel();
    }

    // Wait for threads to finish
    if (connection_thread_ && connection_thread_->joinable()) {
        connection_thread_->join();
    }
    if (heartbeat_thread_ && heartbeat_thread_->joinable()) {
        heartbeat_thread_->join();
    }

    stream_.reset();
    context_.reset();
    stub_.reset();
    channel_.reset();

    LOG_INFO("Disconnected from controller");
}

void ControllerClient::run_connection() {
    while (running_) {
        // Parse controller URL
        std::regex url_regex(R"(^(grpcs?):\/\/([^:\/]+)(?::(\d+))?(\/.*)?$)");
        std::smatch match;

        std::string target;
        bool use_tls = false;

        if (std::regex_match(config_.controller.url, match, url_regex)) {
            std::string scheme = match[1];
            std::string host = match[2];
            std::string port = match[3].matched ? match[3].str() : (scheme == "grpcs" ? "443" : "50051");
            use_tls = (scheme == "grpcs");
            target = host + ":" + port;
        } else {
            LOG_ERROR("Invalid controller URL: {}", config_.controller.url);
            schedule_reconnect();
            continue;
        }

        // Create gRPC channel
        if (use_tls) {
            auto creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
            channel_ = grpc::CreateChannel(target, creds);
        } else {
            channel_ = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
        }

        // Wait for channel to connect
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(10);
        if (!channel_->WaitForConnected(deadline)) {
            LOG_ERROR("Failed to connect to controller");
            schedule_reconnect();
            continue;
        }

        // Create stub
        stub_ = edgelink::ServerService::NewStub(channel_);

        // Create context and stream
        context_ = std::make_unique<grpc::ClientContext>();
        context_->AddMetadata("authorization", "Bearer " + config_.controller.token);

        stream_ = stub_->ServerChannel(context_.get());

        if (!stream_) {
            LOG_ERROR("Failed to create server channel stream");
            schedule_reconnect();
            continue;
        }

        connected_ = true;
        reconnect_attempts_ = 0;

        LOG_INFO("Connected to controller");

        if (connect_callback_) {
            connect_callback_(true, "");
        }

        // Register with controller
        do_register();

        // Start heartbeat
        start_heartbeat();

        // Read messages
        edgelink::ServerMessage msg;
        while (running_ && stream_->Read(&msg)) {
            process_message(msg);
        }

        // Connection lost
        connected_ = false;
        registered_ = false;

        if (disconnect_callback_ && running_) {
            disconnect_callback_("Connection lost");
        }

        if (running_) {
            schedule_reconnect();
        }
    }
}

void ControllerClient::do_register() {
    LOG_INFO("Registering with controller...");

    edgelink::ServerMessage msg;
    auto* reg = msg.mutable_server_register();

    reg->set_server_token(config_.controller.token);
    reg->set_name(config_.name);
    reg->set_region(config_.relay.region);

    // Construct relay URL
    std::string relay_url = config_.relay.external_url;
    if (relay_url.empty()) {
        std::string scheme = config_.relay.tls.enabled ? "grpcs" : "grpc";
        relay_url = scheme + "://" + config_.relay.listen_address + ":" +
                    std::to_string(config_.relay.listen_port);
    }
    reg->set_relay_url(relay_url);

    if (config_.stun.enabled) {
        reg->set_stun_port(config_.stun.external_port);
        if (!config_.stun.external_ip.empty()) {
            reg->set_stun_ip(config_.stun.external_ip);
        }
        if (!config_.stun.external_ip2.empty()) {
            reg->set_stun_ip2(config_.stun.external_ip2);
        }
    }

    stream_->Write(msg);
}

void ControllerClient::process_message(const edgelink::ServerMessage& msg) {
    switch (msg.message_case()) {
        case edgelink::ServerMessage::kServerRegisterResponse:
            if (msg.server_register_response().success()) {
                server_id_ = msg.server_register_response().server_id();
                server_.set_server_id(server_id_);
                registered_ = true;
                LOG_INFO("Registered with controller as server ID {}", server_id_);
            } else {
                LOG_ERROR("Registration failed: {}", msg.server_register_response().error_message());
            }
            break;

        case edgelink::ServerMessage::kServerNodeLoc:
            handle_server_node_loc(msg.server_node_loc());
            break;

        case edgelink::ServerMessage::kServerRelayList:
            handle_server_relay_list(msg.server_relay_list());
            break;

        case edgelink::ServerMessage::kPong:
            // Pong response - just ignore
            break;

        case edgelink::ServerMessage::kError:
            LOG_ERROR("Error from controller: {} - {}",
                      static_cast<int>(msg.error().code()),
                      msg.error().message());
            break;

        default:
            LOG_DEBUG("Unhandled message type from controller");
            if (message_callback_) {
                message_callback_(msg);
            }
            break;
    }
}

void ControllerClient::handle_server_node_loc(const edgelink::ServerNodeLoc& locs) {
    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> locations;

    for (const auto& loc : locs.nodes()) {
        std::vector<uint32_t> relay_ids(loc.connected_relay_ids().begin(),
                                         loc.connected_relay_ids().end());
        locations.emplace_back(loc.node_id(), std::move(relay_ids));
    }

    server_.session_manager()->update_node_locations(locations);
    LOG_DEBUG("Updated node locations: {} entries", locations.size());
}

void ControllerClient::handle_server_relay_list(const edgelink::ServerRelayList& list) {
    LOG_INFO("Received relay list from controller: {} relays", list.relays_size());

    // Note: Mesh functionality via gRPC is handled directly by relay-to-relay connections
    // We just log this for now - the relay server will use this list when needed
    for (const auto& relay : list.relays()) {
        if (relay.server_id() != server_id_) {
            LOG_DEBUG("  Relay {}: {} ({})", relay.server_id(), relay.url(), relay.region());
        }
    }
}

void ControllerClient::handle_ping(const edgelink::Ping& ping) {
    edgelink::ServerMessage msg;
    msg.mutable_pong()->set_timestamp(ping.timestamp());
    stream_->Write(msg);
}

void ControllerClient::send(const edgelink::ServerMessage& msg) {
    if (!connected_ || !stream_) {
        LOG_WARN("Cannot send - not connected to controller");
        return;
    }

    stream_->Write(msg);
}

void ControllerClient::send_latency_report(
    const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries) {

    if (!registered_) {
        return;
    }

    edgelink::ServerMessage msg;
    auto* report = msg.mutable_server_latency_report();
    report->set_server_id(server_id_);

    for (const auto& [peer_url, latency_ms, jitter_ms] : entries) {
        // Extract target server ID from peer_url if possible, otherwise skip
        // For now, just log - the proto uses target_server_id and rtt_ms
        (void)peer_url;
        (void)latency_ms;
        (void)jitter_ms;
    }

    send(msg);
}

void ControllerClient::schedule_reconnect() {
    if (!running_) {
        return;
    }

    if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("Max reconnection attempts reached");
        if (disconnect_callback_) {
            disconnect_callback_("Max reconnection attempts reached");
        }
        running_ = false;
        return;
    }

    reconnect_attempts_++;

    // Exponential backoff
    int delay_ms = std::min(
        BASE_RECONNECT_DELAY_MS * (1 << reconnect_attempts_),
        MAX_RECONNECT_DELAY_MS);

    LOG_INFO("Scheduling reconnect attempt {} in {} ms", reconnect_attempts_, delay_ms);

    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
}

void ControllerClient::start_heartbeat() {
    if (heartbeat_thread_ && heartbeat_thread_->joinable()) {
        // Already running
        return;
    }

    heartbeat_thread_ = std::make_unique<std::thread>([this]() {
        while (running_ && connected_) {
            std::this_thread::sleep_for(std::chrono::seconds(30));

            if (!running_ || !connected_) break;

            // Send heartbeat
            edgelink::ServerMessage msg;
            auto* hb = msg.mutable_server_heartbeat();
            hb->set_server_id(server_id_);
            hb->set_timestamp(static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()));
            hb->set_connected_clients(static_cast<uint32_t>(server_.session_manager()->client_count()));

            send(msg);
        }
    });
}

} // namespace edgelink
