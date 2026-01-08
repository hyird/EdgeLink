#pragma once

#include "controller/db/database.hpp"
#include "common/jwt.hpp"
#include "common/config.hpp"

#include <string>
#include <vector>
#include <memory>

namespace edgelink::controller {

// ============================================================================
// Controller CLI Commands
// ============================================================================
class ControllerCLI {
public:
    ControllerCLI(std::shared_ptr<Database> db, const std::string& jwt_secret);
    
    // Run a command, returns exit code
    int run(const std::vector<std::string>& args);
    
    // Print help
    static void print_help();

private:
    std::shared_ptr<Database> db_;
    std::unique_ptr<JWTManager> jwt_;
    
    // Command handlers
    int cmd_network(const std::vector<std::string>& args);
    int cmd_node(const std::vector<std::string>& args);
    int cmd_server(const std::vector<std::string>& args);
    int cmd_route(const std::vector<std::string>& args);
    int cmd_token(const std::vector<std::string>& args);
    int cmd_authkey(const std::vector<std::string>& args);
    int cmd_status(const std::vector<std::string>& args);
    int cmd_latency(const std::vector<std::string>& args);
    int cmd_config_init(const std::vector<std::string>& args);
    
    // Network subcommands
    int network_list();
    int network_create(const std::vector<std::string>& args);
    int network_show(uint32_t id);
    int network_delete(uint32_t id, bool force);
    
    // Node subcommands
    int node_list(uint32_t network_id, bool online_only);
    int node_show(uint32_t id);
    int node_authorize(uint32_t id);
    int node_deauthorize(uint32_t id);
    int node_delete(uint32_t id);
    int node_rename(uint32_t id, const std::string& name);
    
    // Server subcommands
    int server_list();
    int server_add(const std::vector<std::string>& args);
    int server_show(uint32_t id, bool show_token);
    int server_delete(uint32_t id);
    int server_enable(uint32_t id);
    int server_disable(uint32_t id);
    int server_token(uint32_t id, bool regenerate);
    
    // Route subcommands
    int route_list(uint32_t network_id);
    int route_add(const std::vector<std::string>& args);
    int route_delete(uint32_t id);
    int route_enable(uint32_t id);
    int route_disable(uint32_t id);
    
    // Auth key subcommands
    int authkey_list(uint32_t network_id);
    int authkey_create(const std::vector<std::string>& args);
    int authkey_show(uint32_t id);
    int authkey_delete(uint32_t id);
    
    // Helpers
    std::string get_option(const std::vector<std::string>& args, 
                          const std::string& opt, 
                          const std::string& default_val = "");
    bool has_option(const std::vector<std::string>& args, const std::string& opt);
    void print_table(const std::vector<std::vector<std::string>>& rows,
                    const std::vector<std::string>& headers);
    std::string format_time(int64_t timestamp);
    std::string format_bool(bool val);
    std::string format_status(bool online, bool authorized);
};

} // namespace edgelink::controller
