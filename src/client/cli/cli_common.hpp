#pragma once

#include "client/ipc_server.hpp"
#include "client/prefs_store.hpp"
#include "client/service_manager.hpp"
#include "client/version.hpp"
#include "common/config.hpp"

#include <boost/json.hpp>

#include <iostream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace edgelink::client::cli {

// Split string by delimiter with trimming
inline std::vector<std::string> split_string(const std::string& str, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delim)) {
        size_t start = item.find_first_not_of(" \t");
        size_t end = item.find_last_not_of(" \t");
        if (start != std::string::npos)
            result.push_back(item.substr(start, end - start + 1));
    }
    return result;
}

}  // namespace edgelink::client::cli

// Command declarations (global scope, called from main)
int cmd_version();
int cmd_status(int argc, char* argv[]);
int cmd_peers(int argc, char* argv[]);
int cmd_ping(int argc, char* argv[]);
int cmd_routes(int argc, char* argv[]);
int cmd_config(int argc, char* argv[]);
int cmd_set(int argc, char* argv[]);
int cmd_up(int argc, char* argv[]);
int cmd_down(int argc, char* argv[]);
int cmd_daemon(int argc, char* argv[]);
