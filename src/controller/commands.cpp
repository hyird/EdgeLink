#include "commands.hpp"
#include "common/log.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <filesystem>
#include <random>

namespace edgelink::controller {

ControllerCLI::ControllerCLI(std::shared_ptr<Database> db, const std::string& jwt_secret)
    : db_(std::move(db))
    , jwt_(std::make_unique<JWTManager>(jwt_secret)) {
}

void ControllerCLI::print_help() {
    std::cout << "EdgeLink Controller\n\n";
    std::cout << "Usage: edgelink-controller <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  serve                Start the controller service\n";
    std::cout << "  network <action>     Manage networks (list|create|show|delete)\n";
    std::cout << "  node <action>        Manage nodes (list|show|authorize|deauthorize|rename|delete)\n";
    std::cout << "  server <action>      Manage servers (list|add|show|enable|disable|token|delete)\n";
    std::cout << "  route <action>       Manage routes (list|add|enable|disable|delete)\n";
    std::cout << "  authkey <action>     Manage auth keys (list|create|show|delete)\n";
    std::cout << "  status               Show system status\n";
    std::cout << "  latency              Show latency matrix\n";
    std::cout << "  init                 Initialize configuration file\n\n";
    std::cout << "Global Options:\n";
    std::cout << "  -c, --config <file>  Configuration file path\n";
    std::cout << "  --db <path>          Database file path\n";
    std::cout << "  -q, --quiet          Suppress log output\n";
    std::cout << "  -h, --help           Show help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  edgelink-controller serve -c controller.json\n";
    std::cout << "  edgelink-controller network create --name main --subnet 10.100.0.0/16\n";
    std::cout << "  edgelink-controller authkey create --network 1 --reusable\n";
    std::cout << "  edgelink-controller node list --online\n";
}

int ControllerCLI::run(const std::vector<std::string>& args) {
    if (args.empty()) {
        print_help();
        return 1;
    }
    
    const std::string& cmd = args[0];
    
    if (cmd == "network") return cmd_network(args);
    if (cmd == "node") return cmd_node(args);
    if (cmd == "server") return cmd_server(args);
    if (cmd == "route") return cmd_route(args);
    if (cmd == "token") return cmd_token(args);
    if (cmd == "authkey") return cmd_authkey(args);
    if (cmd == "status") return cmd_status(args);
    if (cmd == "latency") return cmd_latency(args);
    if (cmd == "init") return cmd_config_init(args);
    
    std::cerr << "Unknown command: " << cmd << "\n";
    print_help();
    return 1;
}

// ============================================================================
// Network Commands
// ============================================================================

int ControllerCLI::cmd_network(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller network <list|create|show|delete> [options]\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "list") {
        return network_list();
    } else if (action == "create") {
        return network_create(args);
    } else if (action == "show" && args.size() > 2) {
        return network_show(std::stoul(args[2]));
    } else if (action == "delete" && args.size() > 2) {
        return network_delete(std::stoul(args[2]), has_option(args, "--force"));
    }
    
    std::cerr << "Usage: edgelink-controller network <list|create|show|delete> [options]\n";
    return 1;
}

int ControllerCLI::network_list() {
    auto networks = db_->list_networks();
    
    if (networks.empty()) {
        std::cout << "No networks found.\n";
        return 0;
    }
    
    std::vector<std::vector<std::string>> rows;
    for (const auto& n : networks) {
        rows.push_back({
            std::to_string(n.id),
            n.name,
            n.subnet,
            n.description,
            format_time(n.created_at)
        });
    }
    
    print_table(rows, {"ID", "Name", "Subnet", "Description", "Created"});
    return 0;
}

int ControllerCLI::network_create(const std::vector<std::string>& args) {
    std::string name = get_option(args, "--name", "");
    std::string subnet = get_option(args, "--subnet", "10.100.0.0/16");
    std::string desc = get_option(args, "--description", "");
    
    if (name.empty()) {
        std::cerr << "Error: --name is required\n";
        return 1;
    }
    
    Network network;
    network.name = name;
    network.subnet = subnet;
    network.description = desc;
    
    uint32_t id = db_->create_network(network);
    if (id == 0) {
        std::cerr << "Error: Failed to create network\n";
        return 1;
    }
    
    std::cout << "Network created: ID=" << id << "\n";
    return 0;
}

int ControllerCLI::network_show(uint32_t id) {
    auto network = db_->get_network(id);
    if (!network) {
        std::cerr << "Error: Network not found\n";
        return 1;
    }
    
    std::cout << "ID:          " << network->id << "\n";
    std::cout << "Name:        " << network->name << "\n";
    std::cout << "Subnet:      " << network->subnet << "\n";
    std::cout << "Description: " << network->description << "\n";
    std::cout << "Created:     " << format_time(network->created_at) << "\n";
    
    auto nodes = db_->list_nodes(id);
    auto online = db_->list_online_nodes(id);
    std::cout << "Nodes:       " << nodes.size() << " total, " << online.size() << " online\n";
    
    return 0;
}

int ControllerCLI::network_delete(uint32_t id, bool force) {
    auto nodes = db_->list_nodes(id);
    if (!nodes.empty() && !force) {
        std::cerr << "Error: Network has " << nodes.size() << " nodes. Use --force to delete.\n";
        return 1;
    }
    
    if (!db_->delete_network(id)) {
        std::cerr << "Error: Failed to delete network\n";
        return 1;
    }
    
    std::cout << "Network deleted: " << id << "\n";
    return 0;
}

// ============================================================================
// Node Commands
// ============================================================================

int ControllerCLI::cmd_node(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller node <list|show|authorize|deauthorize|rename|delete> [options]\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "list") {
        uint32_t network_id = 0;
        std::string net_opt = get_option(args, "--network", "");
        if (!net_opt.empty()) network_id = std::stoul(net_opt);
        return node_list(network_id, has_option(args, "--online"));
    } else if (action == "show" && args.size() > 2) {
        return node_show(std::stoul(args[2]));
    } else if (action == "authorize" && args.size() > 2) {
        return node_authorize(std::stoul(args[2]));
    } else if (action == "deauthorize" && args.size() > 2) {
        return node_deauthorize(std::stoul(args[2]));
    } else if (action == "delete" && args.size() > 2) {
        return node_delete(std::stoul(args[2]));
    } else if (action == "rename" && args.size() > 2) {
        return node_rename(std::stoul(args[2]), get_option(args, "--name", ""));
    }
    
    std::cerr << "Usage: edgelink-controller node <list|show|authorize|deauthorize|rename|delete> [options]\n";
    return 1;
}

int ControllerCLI::node_list(uint32_t network_id, bool online_only) {
    std::vector<Node> nodes;
    if (online_only) {
        nodes = db_->list_online_nodes(network_id);
    } else {
        nodes = db_->list_nodes(network_id);
    }
    
    if (nodes.empty()) {
        std::cout << "No nodes found.\n";
        return 0;
    }
    
    std::vector<std::vector<std::string>> rows;
    for (const auto& n : nodes) {
        rows.push_back({
            std::to_string(n.id),
            n.name.empty() ? n.hostname : n.name,
            n.virtual_ip,
            format_status(n.online, n.authorized),
            n.os + "/" + n.arch,
            format_time(n.last_seen)
        });
    }
    
    print_table(rows, {"ID", "Name", "Virtual IP", "Status", "Platform", "Last Seen"});
    return 0;
}

int ControllerCLI::node_show(uint32_t id) {
    auto node = db_->get_node(id);
    if (!node) {
        std::cerr << "Error: Node not found\n";
        return 1;
    }
    
    std::cout << "ID:           " << node->id << "\n";
    std::cout << "Name:         " << (node->name.empty() ? "-" : node->name) << "\n";
    std::cout << "Hostname:     " << node->hostname << "\n";
    std::cout << "Virtual IP:   " << node->virtual_ip << "\n";
    std::cout << "Network ID:   " << node->network_id << "\n";
    std::cout << "Status:       " << format_status(node->online, node->authorized) << "\n";
    std::cout << "Platform:     " << node->os << "/" << node->arch << "\n";
    std::cout << "Version:      " << node->version << "\n";
    std::cout << "NAT Type:     " << (node->nat_type.empty() ? "-" : node->nat_type) << "\n";
    std::cout << "Last Seen:    " << format_time(node->last_seen) << "\n";
    
    auto endpoints = db_->get_node_endpoints(id);
    if (!endpoints.empty()) {
        std::cout << "Endpoints:\n";
        for (const auto& ep : endpoints) {
            std::cout << "  - " << ep.type << ": " << ep.ip << ":" << ep.port << "\n";
        }
    }
    
    auto routes = db_->get_node_routes(id);
    if (!routes.empty()) {
        std::cout << "Routes:\n";
        for (const auto& r : routes) {
            std::cout << "  - " << r.cidr << " (pri:" << r.priority << " wt:" << r.weight << ")\n";
        }
    }
    
    return 0;
}

int ControllerCLI::node_authorize(uint32_t id) {
    auto node = db_->get_node(id);
    if (!node) {
        std::cerr << "Error: Node not found\n";
        return 1;
    }
    
    node->authorized = true;
    if (!db_->update_node(*node)) {
        std::cerr << "Error: Failed to authorize node\n";
        return 1;
    }
    
    std::cout << "Node authorized: " << id << "\n";
    return 0;
}

int ControllerCLI::node_deauthorize(uint32_t id) {
    auto node = db_->get_node(id);
    if (!node) {
        std::cerr << "Error: Node not found\n";
        return 1;
    }
    
    node->authorized = false;
    if (!db_->update_node(*node)) {
        std::cerr << "Error: Failed to deauthorize node\n";
        return 1;
    }
    
    std::cout << "Node deauthorized: " << id << "\n";
    return 0;
}

int ControllerCLI::node_delete(uint32_t id) {
    if (!db_->delete_node(id)) {
        std::cerr << "Error: Failed to delete node\n";
        return 1;
    }
    
    std::cout << "Node deleted: " << id << "\n";
    return 0;
}

int ControllerCLI::node_rename(uint32_t id, const std::string& name) {
    if (name.empty()) {
        std::cerr << "Error: --name is required\n";
        return 1;
    }
    
    auto node = db_->get_node(id);
    if (!node) {
        std::cerr << "Error: Node not found\n";
        return 1;
    }
    
    node->name = name;
    if (!db_->update_node(*node)) {
        std::cerr << "Error: Failed to rename node\n";
        return 1;
    }
    
    std::cout << "Node renamed: " << id << " -> " << name << "\n";
    return 0;
}

// ============================================================================
// Server Commands
// ============================================================================

int ControllerCLI::cmd_server(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller server <list|add|show|enable|disable|token|delete> [options]\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "list") {
        return server_list();
    } else if (action == "add") {
        return server_add(args);
    } else if (action == "show" && args.size() > 2) {
        return server_show(std::stoul(args[2]), has_option(args, "--show-token"));
    } else if (action == "delete" && args.size() > 2) {
        return server_delete(std::stoul(args[2]));
    } else if (action == "enable" && args.size() > 2) {
        return server_enable(std::stoul(args[2]));
    } else if (action == "disable" && args.size() > 2) {
        return server_disable(std::stoul(args[2]));
    } else if (action == "token" && args.size() > 2) {
        return server_token(std::stoul(args[2]), has_option(args, "--regenerate"));
    }
    
    std::cerr << "Usage: edgelink-controller server <list|add|show|enable|disable|token|delete> [options]\n";
    return 1;
}

int ControllerCLI::server_list() {
    auto servers = db_->list_servers();
    
    if (servers.empty()) {
        std::cout << "No servers found.\n";
        return 0;
    }
    
    std::vector<std::vector<std::string>> rows;
    for (const auto& s : servers) {
        // Parse capabilities for display
        std::string caps_display = s.type;
        if (!s.capabilities.empty() && s.capabilities != "[]") {
            // Extract from JSON array like ["relay","stun"]
            caps_display = "";
            if (s.capabilities.find("relay") != std::string::npos) {
                caps_display += "relay";
            }
            if (s.capabilities.find("stun") != std::string::npos) {
                if (!caps_display.empty()) caps_display += "+";
                caps_display += "stun";
            }
            if (caps_display.empty()) caps_display = s.type;
        }
        
        rows.push_back({
            std::to_string(s.id),
            s.name,
            caps_display,
            s.region,
            s.url.empty() ? "-" : s.url,
            s.stun_ip.empty() ? "-" : (s.stun_ip + ":" + std::to_string(s.stun_port)),
            format_bool(s.enabled)
        });
    }
    
    print_table(rows, {"ID", "Name", "Capabilities", "Region", "Relay URL", "STUN", "Enabled"});
    return 0;
}

int ControllerCLI::server_add(const std::vector<std::string>& args) {
    std::string name = get_option(args, "--name", "");
    if (name.empty()) {
        std::cerr << "Error: --name is required\n";
        return 1;
    }
    
    Server server;
    server.name = name;
    server.url = get_option(args, "--url", "");
    server.region = get_option(args, "--region", "default");
    server.type = get_option(args, "--type", "external");
    server.stun_ip = get_option(args, "--stun-ip", "");
    server.stun_ip2 = get_option(args, "--stun-ip2", "");
    server.stun_port = static_cast<uint16_t>(std::stoul(get_option(args, "--stun-port", "3478")));
    server.enabled = true;
    
    server.server_token = jwt_->create_server_token(0, name,
        static_cast<uint8_t>(ServerCapability::RELAY | ServerCapability::STUN), server.region);
    
    uint32_t id = db_->create_server(server);
    if (id == 0) {
        std::cerr << "Error: Failed to add server\n";
        return 1;
    }
    
    std::cout << "Server added: ID=" << id << "\n";
    std::cout << "Token: " << server.server_token << "\n";
    return 0;
}

int ControllerCLI::server_show(uint32_t id, bool show_token) {
    auto server = db_->get_server(id);
    if (!server) {
        std::cerr << "Error: Server not found\n";
        return 1;
    }
    
    // Parse capabilities
    std::string caps_display = server->type;
    if (!server->capabilities.empty() && server->capabilities != "[]") {
        caps_display = "";
        if (server->capabilities.find("relay") != std::string::npos) {
            caps_display += "relay";
        }
        if (server->capabilities.find("stun") != std::string::npos) {
            if (!caps_display.empty()) caps_display += ", ";
            caps_display += "stun";
        }
        if (caps_display.empty()) caps_display = server->type;
    }
    
    std::cout << "ID:           " << server->id << "\n";
    std::cout << "Name:         " << server->name << "\n";
    std::cout << "Type:         " << server->type << "\n";
    std::cout << "Capabilities: " << caps_display << "\n";
    std::cout << "Region:       " << server->region << "\n";
    std::cout << "Relay URL:    " << (server->url.empty() ? "-" : server->url) << "\n";
    std::cout << "STUN IP:      " << (server->stun_ip.empty() ? "-" : server->stun_ip) << "\n";
    std::cout << "STUN IP2:     " << (server->stun_ip2.empty() ? "-" : server->stun_ip2) << "\n";
    std::cout << "STUN Port:    " << server->stun_port << "\n";
    std::cout << "Enabled:      " << format_bool(server->enabled) << "\n";
    
    if (show_token && !server->server_token.empty()) {
        std::cout << "Token:        " << server->server_token << "\n";
    }
    
    return 0;
}

int ControllerCLI::server_delete(uint32_t id) {
    if (!db_->delete_server(id)) {
        std::cerr << "Error: Failed to delete server\n";
        return 1;
    }
    std::cout << "Server deleted: " << id << "\n";
    return 0;
}

int ControllerCLI::server_enable(uint32_t id) {
    auto server = db_->get_server(id);
    if (!server) {
        std::cerr << "Error: Server not found\n";
        return 1;
    }
    server->enabled = true;
    db_->update_server(*server);
    std::cout << "Server enabled: " << id << "\n";
    return 0;
}

int ControllerCLI::server_disable(uint32_t id) {
    auto server = db_->get_server(id);
    if (!server) {
        std::cerr << "Error: Server not found\n";
        return 1;
    }
    server->enabled = false;
    db_->update_server(*server);
    std::cout << "Server disabled: " << id << "\n";
    return 0;
}

int ControllerCLI::server_token(uint32_t id, bool regenerate) {
    auto server = db_->get_server(id);
    if (!server) {
        std::cerr << "Error: Server not found\n";
        return 1;
    }
    
    if (regenerate) {
        server->server_token = jwt_->create_server_token(id, server->name,
            static_cast<uint8_t>(ServerCapability::RELAY | ServerCapability::STUN), server->region);
        db_->update_server(*server);
        std::cout << "Token regenerated.\n";
    }
    
    std::cout << server->server_token << "\n";
    return 0;
}

// ============================================================================
// Route Commands
// ============================================================================

int ControllerCLI::cmd_route(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller route <list|add|enable|disable|delete> [options]\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "list") {
        uint32_t network_id = 0;
        std::string net_opt = get_option(args, "--network", "");
        if (!net_opt.empty()) network_id = std::stoul(net_opt);
        return route_list(network_id);
    } else if (action == "add") {
        return route_add(args);
    } else if (action == "delete" && args.size() > 2) {
        return route_delete(std::stoul(args[2]));
    } else if (action == "enable" && args.size() > 2) {
        return route_enable(std::stoul(args[2]));
    } else if (action == "disable" && args.size() > 2) {
        return route_disable(std::stoul(args[2]));
    }
    
    std::cerr << "Usage: edgelink-controller route <list|add|enable|disable|delete> [options]\n";
    return 1;
}

int ControllerCLI::route_list(uint32_t network_id) {
    auto routes = db_->get_all_routes(network_id);
    
    if (routes.empty()) {
        std::cout << "No routes found.\n";
        return 0;
    }
    
    std::vector<std::vector<std::string>> rows;
    for (const auto& r : routes) {
        auto node = db_->get_node(r.node_id);
        std::string gateway = node ? (node->name.empty() ? node->hostname : node->name) : "?";
        
        rows.push_back({
            std::to_string(r.id),
            r.cidr,
            gateway + " (" + std::to_string(r.node_id) + ")",
            std::to_string(r.priority),
            std::to_string(r.weight),
            format_bool(r.enabled)
        });
    }
    
    print_table(rows, {"ID", "CIDR", "Gateway", "Priority", "Weight", "Enabled"});
    return 0;
}

int ControllerCLI::route_add(const std::vector<std::string>& args) {
    std::string cidr = get_option(args, "--cidr", "");
    std::string node_str = get_option(args, "--node", "");
    
    if (cidr.empty() || node_str.empty()) {
        std::cerr << "Error: --cidr and --node are required\n";
        return 1;
    }
    
    uint32_t node_id = std::stoul(node_str);
    auto node = db_->get_node(node_id);
    if (!node) {
        std::cerr << "Error: Node not found\n";
        return 1;
    }
    
    NodeRoute route;
    route.node_id = node_id;
    route.cidr = cidr;
    route.priority = static_cast<uint16_t>(std::stoul(get_option(args, "--priority", "100")));
    route.weight = static_cast<uint16_t>(std::stoul(get_option(args, "--weight", "100")));
    route.enabled = true;
    
    uint32_t id = db_->create_node_route(route);
    if (id == 0) {
        std::cerr << "Error: Failed to add route\n";
        return 1;
    }
    
    std::cout << "Route added: ID=" << id << "\n";
    return 0;
}

int ControllerCLI::route_delete(uint32_t id) {
    if (!db_->delete_node_route(id)) {
        std::cerr << "Error: Failed to delete route\n";
        return 1;
    }
    std::cout << "Route deleted: " << id << "\n";
    return 0;
}

int ControllerCLI::route_enable(uint32_t id) {
    auto routes = db_->get_all_routes();
    for (auto& r : routes) {
        if (r.id == id) {
            r.enabled = true;
            db_->update_node_route(r);
            std::cout << "Route enabled: " << id << "\n";
            return 0;
        }
    }
    std::cerr << "Error: Route not found\n";
    return 1;
}

int ControllerCLI::route_disable(uint32_t id) {
    auto routes = db_->get_all_routes();
    for (auto& r : routes) {
        if (r.id == id) {
            r.enabled = false;
            db_->update_node_route(r);
            std::cout << "Route disabled: " << id << "\n";
            return 0;
        }
    }
    std::cerr << "Error: Route not found\n";
    return 1;
}

// ============================================================================
// Token Commands
// ============================================================================

int ControllerCLI::cmd_token(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller token <generate|blacklist> [options]\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "generate") {
        std::string name = get_option(args, "--name", "");
        std::string region = get_option(args, "--region", "default");
        if (name.empty()) {
            std::cerr << "Error: --name is required\n";
            return 1;
        }
        auto token = jwt_->create_server_token(0, name,
            static_cast<uint8_t>(ServerCapability::RELAY | ServerCapability::STUN), region);
        std::cout << token << "\n";
        return 0;
    } else if (action == "blacklist") {
        if (args.size() < 3) {
            std::cerr << "Usage: edgelink-controller token blacklist <list|add|cleanup>\n";
            return 1;
        }
        
        const std::string& sub = args[2];
        if (sub == "list") {
            auto blacklist = db_->get_blacklist();
            if (blacklist.empty()) {
                std::cout << "No blacklisted tokens.\n";
                return 0;
            }
            std::vector<std::vector<std::string>> rows;
            for (const auto& e : blacklist) {
                rows.push_back({e.jti, std::to_string(e.node_id), e.reason, format_time(e.expires_at)});
            }
            print_table(rows, {"JTI", "Node", "Reason", "Expires"});
            return 0;
        } else if (sub == "add" && args.size() > 3) {
            std::string jti = args[3];
            std::string reason = get_option(args, "--reason", "Manual");
            int64_t expires = std::time(nullptr) + 24 * 3600;
            db_->blacklist_token(jti, 0, reason, expires);
            std::cout << "Token blacklisted: " << jti << "\n";
            return 0;
        } else if (sub == "cleanup") {
            db_->cleanup_blacklist();
            std::cout << "Blacklist cleanup done.\n";
            return 0;
        }
    }
    
    std::cerr << "Usage: edgelink-controller token <generate|blacklist> [options]\n";
    return 1;
}

// ============================================================================
// Status Commands
// ============================================================================

int ControllerCLI::cmd_status(const std::vector<std::string>& /*args*/) {
    auto networks = db_->list_networks();
    auto nodes = db_->list_nodes();
    auto online = db_->list_online_nodes();
    auto servers = db_->list_servers();
    auto routes = db_->get_all_routes();
    
    std::cout << "EdgeLink Status\n";
    std::cout << "===============\n";
    std::cout << "Networks:  " << networks.size() << "\n";
    std::cout << "Nodes:     " << nodes.size() << " total, " << online.size() << " online\n";
    std::cout << "Servers:   " << servers.size() << "\n";
    std::cout << "Routes:    " << routes.size() << "\n";
    
    size_t authorized = 0, pending = 0;
    for (const auto& n : nodes) {
        if (n.authorized) authorized++;
        else pending++;
    }
    std::cout << "\nNodes: " << authorized << " authorized, " << pending << " pending\n";
    
    return 0;
}

int ControllerCLI::cmd_latency(const std::vector<std::string>& /*args*/) {
    auto latencies = db_->get_latencies();
    
    if (latencies.empty()) {
        std::cout << "No latency data.\n";
        return 0;
    }
    
    std::vector<std::vector<std::string>> rows;
    for (const auto& l : latencies) {
        rows.push_back({
            l.src_type + ":" + std::to_string(l.src_id),
            l.dst_type + ":" + std::to_string(l.dst_id),
            std::to_string(l.rtt_ms) + "ms",
            format_time(l.recorded_at)
        });
    }
    
    print_table(rows, {"Source", "Destination", "RTT", "Time"});
    return 0;
}

int ControllerCLI::cmd_config_init(const std::vector<std::string>& args) {
    std::string path = get_option(args, "--output", "controller.json");
    
    // Generate random server token
    std::string server_token;
    {
        uint8_t bytes[24];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (int i = 0; i < 24; ++i) {
            bytes[i] = static_cast<uint8_t>(dis(gen));
        }
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 24; i += 3) {
            server_token += b64[(bytes[i] >> 2) & 0x3F];
            server_token += b64[((bytes[i] & 0x03) << 4) | ((bytes[i+1] >> 4) & 0x0F)];
            server_token += b64[((bytes[i+1] & 0x0F) << 2) | ((bytes[i+2] >> 6) & 0x03)];
            server_token += b64[bytes[i+2] & 0x3F];
        }
    }
    
    ControllerConfig config;
    config.http.listen_address = "0.0.0.0";
    config.http.listen_port = 8080;
    config.http.enable_tls = false;
    config.database.type = "sqlite";
    config.database.path = "edgelink.db";
    config.jwt.secret = "change-this-secret-" + std::to_string(std::time(nullptr));
    config.server_token = server_token;
    config.builtin_relay.enabled = true;
    config.builtin_stun.enabled = true;
    config.builtin_stun.listen = "0.0.0.0:3478";
    
    if (config.save(path)) {
        std::cout << "Config created: " << path << "\n";
        std::cout << "Update builtin_stun.ip with your public IP!\n";
        std::cout << "\nServer Token (for relay registration): " << server_token << "\n";
        return 0;
    }
    
    std::cerr << "Error: Failed to create config\n";
    return 1;
}

// ============================================================================
// Helpers
// ============================================================================

std::string ControllerCLI::get_option(const std::vector<std::string>& args,
                                       const std::string& opt,
                                       const std::string& default_val) {
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == opt && i + 1 < args.size()) {
            return args[i + 1];
        }
        if (args[i].find(opt + "=") == 0) {
            return args[i].substr(opt.length() + 1);
        }
    }
    return default_val;
}

bool ControllerCLI::has_option(const std::vector<std::string>& args, const std::string& opt) {
    return std::find(args.begin(), args.end(), opt) != args.end();
}

void ControllerCLI::print_table(const std::vector<std::vector<std::string>>& rows,
                                const std::vector<std::string>& headers) {
    std::vector<size_t> widths(headers.size(), 0);
    for (size_t i = 0; i < headers.size(); ++i) {
        widths[i] = headers[i].length();
    }
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].length());
        }
    }
    
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << std::left << std::setw(widths[i] + 2) << headers[i];
    }
    std::cout << "\n";
    
    for (size_t i = 0; i < headers.size(); ++i) {
        std::cout << std::string(widths[i], '-') << "  ";
    }
    std::cout << "\n";
    
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            std::cout << std::left << std::setw(widths[i] + 2) << row[i];
        }
        std::cout << "\n";
    }
}

std::string ControllerCLI::format_time(int64_t timestamp) {
    if (timestamp == 0) return "-";
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm* tm = std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M");
    return oss.str();
}

std::string ControllerCLI::format_bool(bool val) {
    return val ? "Yes" : "No";
}

std::string ControllerCLI::format_status(bool online, bool authorized) {
    if (!authorized) return "Pending";
    return online ? "Online" : "Offline";
}

// ============================================================================
// Auth Key Commands
// ============================================================================

int ControllerCLI::cmd_authkey(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cerr << "Usage: edgelink-controller authkey <list|create|show|delete> [options]\n\n";
        std::cerr << "Actions:\n";
        std::cerr << "  list                    List all auth keys\n";
        std::cerr << "  create                  Create a new auth key\n";
        std::cerr << "  show <id>               Show auth key details\n";
        std::cerr << "  delete <id>             Delete an auth key\n\n";
        std::cerr << "Create Options:\n";
        std::cerr << "  --network <id>          Network ID (required)\n";
        std::cerr << "  --desc <text>           Description\n";
        std::cerr << "  --reusable              Can be used multiple times\n";
        std::cerr << "  --ephemeral             Nodes will be removed when offline\n";
        std::cerr << "  --max-uses <n>          Maximum uses (for reusable keys)\n";
        std::cerr << "  --expires <hours>       Expire after N hours\n";
        return 1;
    }
    
    const std::string& action = args[1];
    
    if (action == "list") {
        uint32_t network_id = 0;
        std::string net_str = get_option(args, "--network");
        if (!net_str.empty()) {
            network_id = static_cast<uint32_t>(std::stoul(net_str));
        }
        return authkey_list(network_id);
    } else if (action == "create") {
        return authkey_create(args);
    } else if (action == "show" && args.size() > 2) {
        return authkey_show(static_cast<uint32_t>(std::stoul(args[2])));
    } else if (action == "delete" && args.size() > 2) {
        return authkey_delete(static_cast<uint32_t>(std::stoul(args[2])));
    }
    
    std::cerr << "Unknown authkey action: " << action << "\n";
    return 1;
}

int ControllerCLI::authkey_list(uint32_t network_id) {
    if (!db_) {
        std::cerr << "Error: Database not initialized\n";
        return 1;
    }
    
    auto keys = db_->list_auth_keys(network_id);
    if (keys.empty()) {
        std::cout << "No auth keys found.\n";
        return 0;
    }
    
    std::vector<std::string> headers = {"ID", "Key", "Network", "Reusable", "Uses", "Expires", "Created"};
    std::vector<std::vector<std::string>> rows;
    
    for (const auto& k : keys) {
        std::string key_display = k.key.substr(0, 8) + "...";
        std::string expires = k.expires_at > 0 ? format_time(k.expires_at) : "Never";
        std::string uses = std::to_string(k.used_count);
        if (k.reusable && k.max_uses >= 0) {
            uses += "/" + std::to_string(k.max_uses);
        } else if (!k.reusable) {
            uses += "/1";
        }
        
        rows.push_back({
            std::to_string(k.id),
            key_display,
            std::to_string(k.network_id),
            format_bool(k.reusable),
            uses,
            expires,
            format_time(k.created_at)
        });
    }
    
    print_table(rows, headers);
    return 0;
}

int ControllerCLI::authkey_create(const std::vector<std::string>& args) {
    if (!db_) {
        std::cerr << "Error: Database not initialized\n";
        return 1;
    }
    
    std::string network_str = get_option(args, "--network");
    if (network_str.empty()) {
        std::cerr << "Error: --network is required\n";
        return 1;
    }
    
    uint32_t network_id = static_cast<uint32_t>(std::stoul(network_str));
    
    // Verify network exists
    auto network = db_->get_network(network_id);
    if (!network) {
        std::cerr << "Error: Network " << network_id << " not found\n";
        return 1;
    }
    
    AuthKey key;
    key.network_id = network_id;
    key.description = get_option(args, "--desc");
    key.reusable = has_option(args, "--reusable");
    key.ephemeral = has_option(args, "--ephemeral");
    key.created_by = "cli";
    
    std::string max_uses_str = get_option(args, "--max-uses");
    if (!max_uses_str.empty()) {
        key.max_uses = std::stoi(max_uses_str);
    } else {
        key.max_uses = -1;
    }
    
    std::string expires_str = get_option(args, "--expires");
    if (!expires_str.empty()) {
        int hours = std::stoi(expires_str);
        key.expires_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + (hours * 3600);
    }
    
    // Generate random key (32 bytes base64)
    std::string random_key;
    {
        uint8_t bytes[24];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (int i = 0; i < 24; ++i) {
            bytes[i] = static_cast<uint8_t>(dis(gen));
        }
        
        // Simple base64 encoding
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 24; i += 3) {
            random_key += b64[(bytes[i] >> 2) & 0x3F];
            random_key += b64[((bytes[i] & 0x03) << 4) | ((bytes[i+1] >> 4) & 0x0F)];
            random_key += b64[((bytes[i+1] & 0x0F) << 2) | ((bytes[i+2] >> 6) & 0x03)];
            random_key += b64[bytes[i+2] & 0x3F];
        }
    }
    key.key = random_key;
    
    uint32_t id = db_->create_auth_key(key);
    if (id == 0) {
        std::cerr << "Error: Failed to create auth key\n";
        return 1;
    }
    
    std::cout << "Auth key created:\n";
    std::cout << "  ID:       " << id << "\n";
    std::cout << "  Key:      " << key.key << "\n";
    std::cout << "  Network:  " << network->name << " (" << network_id << ")\n";
    std::cout << "  Reusable: " << format_bool(key.reusable) << "\n";
    if (key.expires_at > 0) {
        std::cout << "  Expires:  " << format_time(key.expires_at) << "\n";
    }
    std::cout << "\nUse this key with: edgelink-client connect --auth-key " << key.key << "\n";
    
    return 0;
}

int ControllerCLI::authkey_show(uint32_t id) {
    if (!db_) {
        std::cerr << "Error: Database not initialized\n";
        return 1;
    }
    
    auto key = db_->get_auth_key(id);
    if (!key) {
        std::cerr << "Error: Auth key " << id << " not found\n";
        return 1;
    }
    
    auto network = db_->get_network(key->network_id);
    
    std::cout << "Auth Key Details\n";
    std::cout << "================\n";
    std::cout << "ID:          " << key->id << "\n";
    std::cout << "Key:         " << key->key << "\n";
    std::cout << "Network:     " << (network ? network->name : "?") << " (" << key->network_id << ")\n";
    std::cout << "Description: " << key->description << "\n";
    std::cout << "Reusable:    " << format_bool(key->reusable) << "\n";
    std::cout << "Ephemeral:   " << format_bool(key->ephemeral) << "\n";
    std::cout << "Used:        " << key->used_count;
    if (key->max_uses >= 0) {
        std::cout << " / " << key->max_uses;
    }
    std::cout << "\n";
    std::cout << "Expires:     " << (key->expires_at > 0 ? format_time(key->expires_at) : "Never") << "\n";
    std::cout << "Valid:       " << format_bool(db_->is_auth_key_valid(*key)) << "\n";
    std::cout << "Created:     " << format_time(key->created_at) << "\n";
    std::cout << "Created by:  " << key->created_by << "\n";
    
    return 0;
}

int ControllerCLI::authkey_delete(uint32_t id) {
    if (!db_) {
        std::cerr << "Error: Database not initialized\n";
        return 1;
    }
    
    auto key = db_->get_auth_key(id);
    if (!key) {
        std::cerr << "Error: Auth key " << id << " not found\n";
        return 1;
    }
    
    if (!db_->delete_auth_key(id)) {
        std::cerr << "Error: Failed to delete auth key\n";
        return 1;
    }
    
    std::cout << "Auth key " << id << " deleted.\n";
    return 0;
}

} // namespace edgelink::controller
