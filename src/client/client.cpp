#include "client.hpp"
#include "common/log.hpp"
#include "common/crypto/ed25519.hpp"
#include "common/crypto/x25519.hpp"
#include <spdlog/spdlog.h>
#include <sodium.h>
#include <fstream>
#include <regex>
#include "common/platform_net.hpp"
#include <nlohmann/json.hpp>

namespace edgelink::client {

// ============================================================================
// Base64 Utilities
// ============================================================================

static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        
        result += base64_chars[(n >> 18) & 0x3F];
        result += base64_chars[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[n & 0x3F] : '=';
    }
    return result;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    
    std::vector<uint8_t> result;
    int val = 0, bits = -8;
    
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

// ============================================================================
// Configuration Loading
// ============================================================================

ClientConfig load_client_config(const std::string& config_file) {
    ClientConfig config;
    
    std::ifstream file(config_file);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + config_file);
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    nlohmann::json j = nlohmann::json::parse(content);
    
    if (j.contains("controller_url")) {
        config.controller_url = j["controller_url"].get<std::string>();
    }
    if (j.contains("machine_key_pub")) {
        config.machine_key_pub = j["machine_key_pub"].get<std::string>();
    }
    if (j.contains("machine_key_priv")) {
        config.machine_key_priv = j["machine_key_priv"].get<std::string>();
    }
    if (j.contains("auth_key")) {
        config.auth_key = j["auth_key"].get<std::string>();
    }
    if (j.contains("tun_name")) {
        config.tun_name = j["tun_name"].get<std::string>();
    }
    if (j.contains("mtu")) {
        config.mtu = j["mtu"].get<int>();
    }
    if (j.contains("log_level")) {
        config.log_level = j["log_level"].get<std::string>();
    }
    
    config.config_file = config_file;
    return config;
}

// ============================================================================
// Client Implementation
// ============================================================================

Client::Client(const ClientConfig& config)
    : config_(config)
    , work_guard_(boost::asio::make_work_guard(ioc_))
    , callback_strand_(net::make_strand(ioc_))
    , ssl_ctx_(ssl::context::tlsv12_client)
    , latency_report_timer_(ioc_)
    , monitor_timer_(ioc_)
{
    stats_.start_time = std::chrono::steady_clock::now();
}

Client::~Client() {
    stop();
}

std::string Client::get_state_string() const {
    switch (state_.load()) {
        case ClientState::STOPPED: return "stopped";
        case ClientState::STARTING: return "starting";
        case ClientState::CONNECTING_CONTROLLER: return "connecting_controller";
        case ClientState::WAITING_CONFIG: return "waiting_config";
        case ClientState::SETTING_UP_TUN: return "setting_up_tun";
        case ClientState::CONNECTING_RELAYS: return "connecting_relays";
        case ClientState::RUNNING: return "running";
        case ClientState::RECONNECTING: return "reconnecting";
        case ClientState::STOPPING: return "stopping";
        default: return "unknown";
    }
}

void Client::set_state(ClientState new_state) {
    auto old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        LOG_INFO("Client state: {} -> {}", 
                 static_cast<int>(old_state), 
                 static_cast<int>(new_state));
    }
}

bool Client::start() {
    if (state_ != ClientState::STOPPED) {
        LOG_WARN("Client already started");
        return false;
    }
    
    set_state(ClientState::STARTING);
    LOG_INFO("WSS Mesh Client starting...");
    
    // 初始化libsodium
    if (sodium_init() < 0) {
        LOG_ERROR("Failed to initialize libsodium");
        set_state(ClientState::STOPPED);
        return false;
    }
    
    // 初始化SSL上下文
    if (!init_ssl_context()) {
        LOG_ERROR("Failed to initialize SSL context");
        set_state(ClientState::STOPPED);
        return false;
    }
    
    // 启动IO线程
    unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());
    for (unsigned int i = 0; i < num_threads; i++) {
        io_threads_.emplace_back([this]() {
            ioc_.run();
        });
    }
    
    // 初始化ControlChannel
    if (!init_control_channel()) {
        LOG_ERROR("Failed to initialize control channel");
        stop();
        return false;
    }

    // 启动 IPC 服务器 (用于 CLI 通信)
    ipc_server_ = std::make_unique<IPCServer>(ioc_, this);
    if (!ipc_server_->start()) {
        LOG_WARN("Failed to start IPC server (CLI commands will not work)");
        // Not fatal - continue without IPC
    }

    // 连接Controller
    set_state(ClientState::CONNECTING_CONTROLLER);
    control_channel_->connect();

    return true;
}

void Client::stop() {
    if (state_ == ClientState::STOPPED || state_ == ClientState::STOPPING) {
        return;
    }
    
    set_state(ClientState::STOPPING);
    LOG_INFO("Client stopping...");

    // 重置初始化标志
    initialized_ = false;

    // 停止定时器
    latency_report_timer_.cancel();
    monitor_timer_.cancel();
    if (relay_manager_) {
        relay_manager_->stop_latency_measurements();
    }
    
    // 停止 IPC 服务器
    if (ipc_server_) {
        ipc_server_->stop();
        ipc_server_.reset();
    }

    // 停止组件
    if (control_channel_) {
        control_channel_->disconnect();
    }

    if (relay_manager_) {
        relay_manager_->disconnect_all();
    }

    if (tun_device_) {
        tun_device_->stop_reading();
        tun_device_->close();
    }
    
    // 停止IO
    work_guard_.reset();
    ioc_.stop();
    
    for (auto& t : io_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    io_threads_.clear();
    
    set_state(ClientState::STOPPED);
    LOG_INFO("Client stopped");
}

void Client::run() {
    // 阻塞直到停止
    while (state_ != ClientState::STOPPED && state_ != ClientState::STOPPING) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

Client::Stats Client::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ============================================================================
// Initialization
// ============================================================================

bool Client::init_ssl_context() {
    try {
        ssl_ctx_.set_default_verify_paths();
        ssl_ctx_.set_verify_mode(ssl::verify_peer);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("SSL context init failed: {}", e.what());
        return false;
    }
}

bool Client::init_control_channel() {
    try {
        // Debug: verify auth_key is being passed
        if (!config_.auth_key.empty()) {
            LOG_INFO("init_control_channel: auth_key present ({}...)", 
                     config_.auth_key.substr(0, std::min(size_t(8), config_.auth_key.size())));
        } else {
            LOG_WARN("init_control_channel: No auth_key in config");
        }
        
        // Decode Ed25519 keys from Base64
        auto machine_pub = edgelink::crypto::Ed25519::public_key_from_base64(config_.machine_key_pub);
        auto machine_priv = edgelink::crypto::Ed25519::private_key_from_base64(config_.machine_key_priv);
        
        if (!machine_pub || !machine_priv) {
            LOG_ERROR("init_control_channel: Failed to decode machine keys");
            return false;
        }
        
        // Generate or decode X25519 keys
        wire::X25519PublicKey node_pub;
        wire::X25519PrivateKey node_priv;
        
        if (!config_.node_key_pub.empty() && !config_.node_key_priv.empty()) {
            // Decode existing X25519 keys
            auto pub_result = edgelink::crypto::X25519::public_key_from_base64(config_.node_key_pub);
            auto priv_result = edgelink::crypto::X25519::private_key_from_base64(config_.node_key_priv);
            
            if (!pub_result || !priv_result) {
                LOG_ERROR("init_control_channel: Failed to decode node keys");
                return false;
            }
            
            node_pub = *pub_result;
            node_priv = *priv_result;
        } else {
            // Generate new X25519 keypair
            auto [pub, priv] = edgelink::crypto::X25519::generate_keypair();
            node_pub = pub;
            node_priv = priv;
            
            // Save to config
            config_.node_key_pub = edgelink::crypto::X25519::public_key_to_base64(pub);
            config_.node_key_priv = edgelink::crypto::X25519::private_key_to_base64(priv);
            LOG_INFO("init_control_channel: Generated new X25519 keypair");
        }
        
        control_channel_ = std::make_shared<ControlChannel>(
            ioc_,
            config_.controller_url,
            *machine_pub,
            *machine_priv,
            node_pub,
            node_priv,
            config_.auth_key
        );
        
        ControlCallbacks callbacks;
        
        // Wrap all callbacks with strand to serialize execution
        // This prevents race conditions when multiple threads process messages
        callbacks.on_config_update = [this](const ConfigUpdate& config) {
            net::post(callback_strand_, [this, config]() {
                on_config_received(config);
            });
        };
        
        callbacks.on_connected = [this]() {
            net::post(callback_strand_, [this]() {
                on_connected();
            });
        };
        
        callbacks.on_disconnected = [this](ErrorCode ec) {
            net::post(callback_strand_, [this, ec]() {
                on_disconnected(ec);
            });
        };
        
        callbacks.on_peer_online = [this](uint32_t node_id, const PeerInfo& peer) {
            net::post(callback_strand_, [this, node_id, peer]() {
                on_peer_online(node_id, peer);
            });
        };
        
        callbacks.on_peer_offline = [this](uint32_t node_id) {
            net::post(callback_strand_, [this, node_id]() {
                on_peer_offline(node_id);
            });
        };
        
        callbacks.on_token_refresh = [this](const std::string& auth, const std::string& relay) {
            net::post(callback_strand_, [this, auth, relay]() {
                on_token_refresh(auth, relay);
            });
        };

        callbacks.on_ip_change = [this](const std::string& old_ip, const std::string& new_ip,
                                        const std::string& reason) {
            net::post(callback_strand_, [this, old_ip, new_ip, reason]() {
                on_ip_change(old_ip, new_ip, reason);
            });
        };

        control_channel_->set_control_callbacks(callbacks);
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Control channel init failed: {}", e.what());
        return false;
    }
}

bool Client::init_relay_manager() {
    try {
        relay_manager_ = std::make_shared<WsRelayManager>(
            ioc_, node_id_, relay_token_
        );

        WsRelayManagerCallbacks callbacks;

        callbacks.on_data_received = [this](uint32_t from_node_id,
                                            const std::vector<uint8_t>& data) {
            on_relay_data_received(from_node_id, data);
        };

        callbacks.on_relay_state_changed = [this](uint32_t relay_id,
                                                  WsRelayConnection::State state) {
            on_relay_state_changed(relay_id, state);
        };

        callbacks.on_latency_measured = [this](uint32_t relay_id, uint32_t peer_id,
                                               uint32_t latency_ms) {
            on_latency_measured(relay_id, latency_ms, peer_id);
        };

        relay_manager_->set_callbacks(callbacks);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("Relay manager init failed: {}", e.what());
        return false;
    }
}

bool Client::init_crypto_engine() {
    try {
        crypto_engine_ = std::make_shared<CryptoEngine>(node_id_);
        
        // Generate X25519 key pair for end-to-end encryption
        // Note: This is separate from the Ed25519 machine key used for authentication
        std::array<uint8_t, 32> node_priv, node_pub;
        
        // Generate random X25519 key pair using libsodium
        if (crypto_box_keypair(node_pub.data(), node_priv.data()) != 0) {
            LOG_ERROR("CryptoEngine: Failed to generate X25519 key pair");
            return false;
        }
        
        // Set the local keys in the crypto engine
        crypto_engine_->set_local_keys(node_priv, node_pub);
        
        LOG_INFO("CryptoEngine: Generated and set local X25519 keys for node {}", node_id_);
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Crypto engine init failed: {}", e.what());
        return false;
    }
}

bool Client::init_tun_device() {
    try {
        tun_device_ = std::make_shared<TunDevice>(ioc_, config_.tun_name);
        
        auto result = tun_device_->open();
        if (!result) {
            LOG_ERROR("Failed to open TUN device");
            return false;
        }
        
        tun_device_->set_packet_callback([this](const std::vector<uint8_t>& packet) {
            on_tun_packet(packet);
        });
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("TUN device init failed: {}", e.what());
        return false;
    }
}

bool Client::init_route_manager() {
    try {
        route_manager_ = std::make_shared<RouteManager>(config_.tun_name);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Route manager init failed: {}", e.what());
        return false;
    }
}

bool Client::init_endpoint_manager() {
    try {
        endpoint_manager_ = std::make_shared<EndpointManager>(ioc_, config_.endpoint_config);
        
        // EndpointManager通过其他方式通知endpoints变化
        // endpoint_manager_->start() 会开始端点发现
        
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Endpoint manager init failed: {}", e.what());
        return false;
    }
}

bool Client::init_p2p_manager() {
    try {
        if (!endpoint_manager_) {
            LOG_ERROR("P2P manager requires endpoint manager");
            return false;
        }
        
        p2p_manager_ = std::make_shared<P2PManager>(
            ioc_, endpoint_manager_, crypto_engine_, node_id_
        );
        
        P2PCallbacks callbacks;
        
        callbacks.on_data_received = [this](uint32_t peer_id, 
                                            const std::vector<uint8_t>& data) {
            on_p2p_data_received(peer_id, data);
        };
        
        callbacks.on_state_changed = [this](uint32_t peer_id, P2PState state) {
            on_p2p_state_changed(peer_id, state);
        };
        
        callbacks.on_punch_request = [this](uint32_t peer_id) {
            on_p2p_punch_request(peer_id);
        };
        
        callbacks.on_connected = [this](uint32_t peer_id, uint32_t rtt_ms) {
            on_p2p_connected(peer_id, rtt_ms);
        };
        
        callbacks.on_disconnected = [this](uint32_t peer_id) {
            on_p2p_disconnected(peer_id);
        };
        
        p2p_manager_->set_callbacks(callbacks);
        
        LOG_INFO("P2P manager initialized");
        return true;
        
    } catch (const std::exception& e) {
        LOG_ERROR("P2P manager init failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// ControlChannel Callbacks
// ============================================================================

void Client::on_config_received(const ConfigUpdate& config) {
    // 区分初始配置和增量更新
    bool is_initial = !initialized_;
    
    if (is_initial) {
        LOG_INFO("Received initial config from controller");
    } else {
        LOG_DEBUG("Received config update from controller");
    }
    
    // 保存节点信息
    node_id_ = control_channel_->node_id();
    virtual_ip_ = control_channel_->virtual_ip();
    auth_token_ = config.auth_token;
    relay_token_ = config.relay_token;
    
    if (is_initial) {
        LOG_INFO("Node ID: {}, Virtual IP: {}", node_id_, virtual_ip_);
    }
    
    // 初始化其他组件（如果尚未初始化）
    if (!crypto_engine_) {
        if (!init_crypto_engine()) {
            handle_fatal_error("Failed to init crypto engine");
            return;
        }
    }
    
    if (!relay_manager_) {
        if (!init_relay_manager()) {
            handle_fatal_error("Failed to init relay manager");
            return;
        }
    }
    
    if (!tun_device_) {
        set_state(ClientState::SETTING_UP_TUN);
        if (!init_tun_device()) {
            handle_fatal_error("Failed to init TUN device");
            return;
        }
        
        // 配置TUN设备IP
        std::regex cidr_regex(R"((\d+\.\d+\.\d+\.\d+)/(\d+))");
        std::smatch match;
        std::string cidr = config.network.cidr;
        
        uint8_t prefix = 24;
        if (std::regex_match(cidr, match, cidr_regex)) {
            prefix = static_cast<uint8_t>(std::stoi(match[2].str()));
        }
        
        auto result = tun_device_->set_address(virtual_ip_, prefix);
        if (!result) {
            LOG_ERROR("Failed to set TUN address");
        }
        
        (void)tun_device_->set_mtu(static_cast<uint16_t>(config_.mtu));
        (void)tun_device_->bring_up();
    }
    
    if (!route_manager_) {
        if (!init_route_manager()) {
            handle_fatal_error("Failed to init route manager");
            return;
        }
        
        route_manager_->set_network_cidr(config.network.cidr);
        route_manager_->set_local_ip(virtual_ip_);
    }
    
    if (!endpoint_manager_) {
        init_endpoint_manager();
    }
    
    // 初始化P2P管理器（需要node_id）
    if (!p2p_manager_ && endpoint_manager_ && crypto_engine_) {
        if (init_p2p_manager()) {
            // 启动端点发现和P2P管理
            endpoint_manager_->start();
            p2p_manager_->start();
            LOG_INFO("P2P and Endpoint managers started");
        }
    }
    
    // 更新peer列表（初始和增量都需要）
    for (const auto& peer : config.peers) {
        (void)crypto_engine_->add_peer(peer.node_id, peer.node_key_pub);
        route_manager_->add_peer(peer.node_id, peer.virtual_ip);
        
        if (peer.online) {
            route_manager_->set_peer_reachable(peer.node_id, true);
            
            // 如果peer有P2P端点信息，尝试建立P2P连接
            if (p2p_manager_ && !peer.endpoints.empty()) {
                // 转换端点格式
                std::vector<Endpoint> endpoints;
                for (const auto& ep_str : peer.endpoints) {
                    // 解析 "ip:port" 格式
                    auto colon_pos = ep_str.find(':');
                    if (colon_pos != std::string::npos) {
                        Endpoint ep;
                        ep.address = ep_str.substr(0, colon_pos);
                        ep.port = static_cast<uint16_t>(
                            std::stoi(ep_str.substr(colon_pos + 1)));
                        ep.type = EndpointType::WAN;
                        ep.priority = 5;
                        endpoints.push_back(ep);
                    }
                }
                
                if (!endpoints.empty()) {
                    // 假设peer的NAT类型未知，让P2PManager决定
                    p2p_manager_->handle_peer_endpoints(
                        peer.node_id, endpoints, NatType::UNKNOWN);
                }
            }
        } else {
            route_manager_->set_peer_reachable(peer.node_id, false);
        }
    }
    
    // 只在初始配置时连接relay和设置状态
    if (is_initial) {
        set_state(ClientState::CONNECTING_RELAYS);

        // 转换relay信息格式 (使用 WebSocket URL)
        std::vector<RelayServerInfo> relay_infos;
        for (const auto& relay : config.relays) {
            RelayServerInfo info;
            info.id = relay.id;
            info.name = relay.name;
            info.region = relay.region;
            info.url = relay.url;  // WebSocket URL: ws://host:port or wss://host:port
            relay_infos.push_back(info);
        }

        relay_manager_->update_relays(relay_infos);
        relay_manager_->connect_all();
    }
    
    // 更新子网路由（初始和增量都需要）
    if (route_manager_ && !config.subnet_routes.empty()) {
        std::vector<RouteEntry> routes;
        for (const auto& sr : config.subnet_routes) {
            RouteEntry entry;
            
            // Parse CIDR to get network and prefix
            auto slash_pos = sr.cidr.find('/');
            if (slash_pos != std::string::npos) {
                entry.network = sr.cidr.substr(0, slash_pos);
                entry.prefix_len = static_cast<uint8_t>(
                    std::stoi(sr.cidr.substr(slash_pos + 1)));
            } else {
                entry.network = sr.cidr;
                entry.prefix_len = 32;  // Single host route
            }
            
            entry.via_node_id = sr.via_node_id;
            entry.priority = sr.priority;
            entry.weight = sr.weight;
            entry.metric = 0;
            entry.active = true;
            
            routes.push_back(entry);
        }
        
        route_manager_->update_subnet_routes(routes);
        if (is_initial) {
            LOG_INFO("Updated {} subnet routes from controller", routes.size());
        }
    }
    
    // 只在初始配置时完成启动流程
    if (is_initial) {
        // 开始接收TUN数据
        tun_device_->start_reading();
        
        // 应用路由
        (void)route_manager_->apply_routes();
        
        set_state(ClientState::RUNNING);
        LOG_INFO("Client is now running");
        
        // 启动延迟上报定时器
        start_latency_report_timer();

        // 启动线程池监控定时器
        start_monitor_timer();

        // 标记已初始化
        initialized_ = true;
    }
    
    // 启动延迟测量（如果relay已连接）
    if (is_initial && relay_manager_) {
        relay_manager_->start_latency_measurements();
    }
}

void Client::on_connected() {
    LOG_INFO("Connected to controller");
    set_state(ClientState::WAITING_CONFIG);
}

void Client::on_disconnected(ErrorCode ec) {
    LOG_WARN("Disconnected from controller: {}", error_code_to_string(ec));
    
    if (state_ != ClientState::STOPPING && state_ != ClientState::STOPPED) {
        set_state(ClientState::RECONNECTING);
        // ControlChannel会自动重连
    }
}

void Client::on_peer_online(uint32_t node_id, const PeerInfo& peer) {
    LOG_INFO("Peer {} ({}) came online", node_id, peer.virtual_ip);
    
    if (crypto_engine_) {
        (void)crypto_engine_->add_peer(node_id, peer.node_key_pub);
    }
    
    if (route_manager_) {
        route_manager_->add_peer(node_id, peer.virtual_ip);
        route_manager_->set_peer_reachable(node_id, true);
    }
}

void Client::on_peer_offline(uint32_t node_id) {
    LOG_INFO("Peer {} went offline", node_id);
    
    if (route_manager_) {
        route_manager_->set_peer_reachable(node_id, false);
    }
}

void Client::on_token_refresh(const std::string& auth_token, const std::string& relay_token) {
    LOG_DEBUG("Tokens refreshed");
    auth_token_ = auth_token;
    relay_token_ = relay_token;

    if (relay_manager_) {
        relay_manager_->update_token(relay_token);
    }
}

void Client::on_ip_change(const std::string& old_ip, const std::string& new_ip,
                          const std::string& reason) {
    LOG_INFO("Virtual IP changed: {} -> {} (reason: {})", old_ip, new_ip, reason);

    // Update local state
    virtual_ip_ = new_ip;
    config_.virtual_ip = new_ip;

    // Update TUN device IP address
    if (tun_device_ && tun_device_->is_open()) {
        // Calculate prefix length from network CIDR
        int prefix_len = 24;  // Default
        auto pos = config_.network_cidr.find('/');
        if (pos != std::string::npos) {
            prefix_len = std::stoi(config_.network_cidr.substr(pos + 1));
        }

        if (tun_device_->set_address(new_ip, prefix_len)) {
            LOG_INFO("TUN device IP updated to {}/{}", new_ip, prefix_len);
        } else {
            LOG_ERROR("Failed to update TUN device IP");
        }
    }

    // Update route manager with new local IP
    if (route_manager_) {
        route_manager_->set_local_ip(new_ip);
    }
}

// ============================================================================
// RelayManager Callbacks
// ============================================================================

void Client::on_relay_data_received(uint32_t from_node_id, const std::vector<uint8_t>& data) {
    process_inbound_packet(from_node_id, data);
}

void Client::on_relay_state_changed(uint32_t relay_id, WsRelayConnection::State state) {
    LOG_DEBUG("Relay {} state changed to {}", relay_id, static_cast<int>(state));
}

void Client::on_latency_measured(uint32_t relay_id, uint32_t peer_id, uint32_t latency_ms) {
    LOG_DEBUG("Latency to peer {} via relay {}: {}ms", peer_id, relay_id, latency_ms);
    
    // 缓存延迟数据，批量上报
    {
        std::lock_guard<std::mutex> lock(latency_mutex_);
        ControlChannel::LatencyMeasurement m;
        m.dst_type = peer_id > 0 ? "node" : "relay";
        m.dst_id = peer_id > 0 ? peer_id : relay_id;
        m.rtt_ms = latency_ms;
        pending_latency_reports_.push_back(m);
    }
}

void Client::start_latency_report_timer() {
    latency_report_timer_.expires_after(LATENCY_REPORT_INTERVAL);
    latency_report_timer_.async_wait([self = shared_from_this()](boost::system::error_code ec) {
        if (!ec && self->state_ == ClientState::RUNNING) {
            self->on_latency_report_timer();
        }
    });
}

void Client::on_latency_report_timer() {
    // 收集所有 relay 的延迟数据
    std::vector<ControlChannel::LatencyMeasurement> measurements;
    
    // 从 pending 报告中收集
    {
        std::lock_guard<std::mutex> lock(latency_mutex_);
        measurements = std::move(pending_latency_reports_);
        pending_latency_reports_.clear();
    }
    
    // 另外，主动测量每个已连接 relay 的延迟
    if (relay_manager_) {
        auto connected_relays = relay_manager_->get_connected_relays();
        for (uint32_t relay_id : connected_relays) {
            // 获取到该 relay 的 RTT（最后一次心跳测量）
            auto state = relay_manager_->get_relay_state(relay_id);
            if (state == WsRelayConnection::State::CONNECTED) {
                // RelayManager 内部已经在 heartbeat 中测量了延迟
                // 这里我们获取其缓存的延迟值
                uint32_t latency = relay_manager_->get_latency(0, relay_id);  // peer_id=0 表示到 relay 本身
                if (latency > 0 && latency < UINT32_MAX) {
                    ControlChannel::LatencyMeasurement m;
                    m.dst_type = "relay";
                    m.dst_id = relay_id;
                    m.rtt_ms = latency;
                    measurements.push_back(m);
                }
            }
        }
    }
    
    // 批量上报
    if (control_channel_ && !measurements.empty()) {
        LOG_DEBUG("Reporting {} latency measurements to controller", measurements.size());
        control_channel_->report_latency_batch(measurements);
    }
    
    // 重新调度
    start_latency_report_timer();
}

// ============================================================================
// TUN Callback
// ============================================================================

void Client::on_tun_packet(const std::vector<uint8_t>& packet) {
    process_outbound_packet(packet);
}

// ============================================================================
// EndpointManager Callback
// ============================================================================

void Client::on_endpoints_changed(const std::vector<Endpoint>& endpoints) {
    LOG_DEBUG("Endpoints changed, {} endpoints discovered", endpoints.size());

    // 转换为 wire::Endpoint 格式上报
    std::vector<wire::Endpoint> wire_endpoints;
    for (const auto& ep : endpoints) {
        wire::Endpoint wire_ep;
        wire_ep.ip = ep.address;
        wire_ep.port = ep.port;
        wire_ep.type = static_cast<wire::EndpointType>(ep.type);
        wire_ep.priority = ep.priority;
        wire_endpoints.push_back(wire_ep);
    }

    if (control_channel_) {
        control_channel_->report_endpoints(wire_endpoints);
    }
}

// ============================================================================
// P2PManager Callbacks
// ============================================================================

void Client::on_p2p_data_received(uint32_t peer_id, const std::vector<uint8_t>& data) {
    // P2P数据和Relay数据使用相同的处理流程
    process_inbound_packet(peer_id, data);
}

void Client::on_p2p_state_changed(uint32_t peer_id, P2PState state) {
    LOG_DEBUG("P2P state for peer {}: {}", peer_id, p2p_state_to_string(state));
    
    // 更新P2P优先标志
    if (state == P2PState::CONNECTED) {
        peer_p2p_preferred_[peer_id] = true;
    } else if (state == P2PState::FAILED || state == P2PState::DISCONNECTED) {
        peer_p2p_preferred_[peer_id] = false;
    }
}

void Client::on_p2p_punch_request(uint32_t peer_id) {
    LOG_DEBUG("P2P punch request for peer {}", peer_id);
    
    // 向Controller请求P2P打洞
    // TODO: 通过ControlChannel发送P2P请求
    // 当前简化实现：等待Controller推送peer的端点信息
}

void Client::on_p2p_connected(uint32_t peer_id, uint32_t rtt_ms) {
    LOG_INFO("P2P connected to peer {}, RTT: {} ms", peer_id, rtt_ms);
    
    // 标记优先使用P2P
    peer_p2p_preferred_[peer_id] = true;
    
    // 如果P2P RTT比Relay好，可以考虑切换
    // 但保留Relay连接作为备份
}

void Client::on_p2p_disconnected(uint32_t peer_id) {
    LOG_INFO("P2P disconnected from peer {}", peer_id);
    
    // 回退到Relay
    peer_p2p_preferred_[peer_id] = false;
    
    // 可以考虑后台重试P2P
}

// ============================================================================
// Data Processing
// ============================================================================

void Client::process_outbound_packet(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) {
        return;  // 太短，无效IP包
    }
    
    // 解析目标IP
    auto header_result = IPv4Header::parse(packet);
    if (!header_result) {
        return;
    }
    
    auto& header = *header_result;
    uint32_t dst_ip = header.dst_addr;
    
    // 查找路由
    uint32_t dst_node_id = route_manager_->lookup(dst_ip);
    if (dst_node_id == 0) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.route_misses++;
        return;
    }
    
    // 加密
    auto encrypted = crypto_engine_->encrypt_with_header(dst_node_id, packet);
    if (!encrypted) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.encrypt_errors++;
        return;
    }
    
    // 尝试P2P发送（如果可用且优先）
    bool sent = false;
    if (p2p_manager_) {
        auto it = peer_p2p_preferred_.find(dst_node_id);
        if (it != peer_p2p_preferred_.end() && it->second) {
            if (p2p_manager_->is_connected(dst_node_id)) {
                sent = p2p_manager_->send_to_peer(dst_node_id, *encrypted);
            }
        }
    }
    
    // 如果P2P未发送，使用Relay
    if (!sent && relay_manager_) {
        auto result = relay_manager_->send_to_peer(dst_node_id, *encrypted);
        sent = result.has_value();
    }
    
    if (sent) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_sent++;
        stats_.bytes_sent += packet.size();
    }
}

void Client::process_inbound_packet(uint32_t from_node_id, const std::vector<uint8_t>& data) {
    // 解密
    auto decrypted = crypto_engine_->decrypt_with_header(data);
    if (!decrypted) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.decrypt_errors++;
        return;
    }
    
    // 验证来源
    if (decrypted->src_node_id != from_node_id) {
        LOG_WARN("Source node mismatch: expected {}, got {}", 
                 from_node_id, decrypted->src_node_id);
        return;
    }
    
    // 写入TUN
    auto result = tun_device_->write_packet(decrypted->plaintext);
    if (result) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.packets_received++;
        stats_.bytes_received += decrypted->plaintext.size();
    }
}

// ============================================================================
// Error Handling
// ============================================================================

void Client::handle_fatal_error(const std::string& error) {
    LOG_ERROR("Fatal error: {}", error);
    stop();
}

// ============================================================================
// Thread Pool Monitoring
// ============================================================================

void Client::start_monitor_timer() {
    monitor_timer_.expires_after(MONITOR_INTERVAL);
    monitor_timer_.async_wait([self = shared_from_this()](boost::system::error_code ec) {
        if (!ec && self->state_ == ClientState::RUNNING) {
            self->on_monitor_timer();
        }
    });
}

void Client::on_monitor_timer() {
    log_thread_stats();

    // Reschedule
    start_monitor_timer();
}

void Client::log_thread_stats() {
    // Log IO thread pool stats
    LOG_INFO("Thread Pool Stats: {} IO threads active", io_threads_.size());

    // Log client stats
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - stats_.start_time).count();

        LOG_INFO("Client Stats: uptime={}s, packets_sent={}, packets_recv={}, "
                 "bytes_sent={}, bytes_recv={}, encrypt_errs={}, decrypt_errs={}, route_misses={}",
                 uptime,
                 stats_.packets_sent,
                 stats_.packets_received,
                 stats_.bytes_sent,
                 stats_.bytes_received,
                 stats_.encrypt_errors,
                 stats_.decrypt_errors,
                 stats_.route_misses);
    }

    // Log P2P manager stats
    if (p2p_manager_) {
        auto connected_peers = p2p_manager_->get_connected_peers();
        LOG_INFO("P2P Stats: {} peers connected", connected_peers.size());
    }

    // Log Relay manager stats
    if (relay_manager_) {
        auto connected = relay_manager_->get_connected_relays();
        LOG_INFO("Relay Stats: {} relays connected", connected.size());
    }
}

} // namespace edgelink::client
