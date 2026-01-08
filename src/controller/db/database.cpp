#include "database.hpp"
#include "migrations.hpp"
#include "common/log.hpp"
#include <sstream>
#include <set>
#include <chrono>
#include "common/platform_net.hpp"

namespace edgelink::controller {

// Helper type aliases for lock guards
using ReadLock = std::shared_lock<std::shared_mutex>;
using WriteLock = std::unique_lock<std::shared_mutex>;

// ============================================================================
// Helper Functions
// ============================================================================

static int64_t current_timestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// Safe sqlite3 text retrieval with default value
static std::string sqlite_text(sqlite3_stmt* stmt, int col, const char* default_val = "") {
    auto text = sqlite3_column_text(stmt, col);
    return text ? reinterpret_cast<const char*>(text) : default_val;
}

// Parse subnet CIDR to get base IP and prefix length
static bool parse_subnet(const std::string& subnet, uint32_t& base_ip, int& prefix_len) {
    auto slash_pos = subnet.find('/');
    if (slash_pos == std::string::npos) return false;
    
    std::string ip_str = subnet.substr(0, slash_pos);
    prefix_len = std::stoi(subnet.substr(slash_pos + 1));
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;
    
    base_ip = ntohl(addr.s_addr);
    return true;
}

// Convert IP to string
static std::string ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

// ============================================================================
// Database Class Implementation
// ============================================================================

Database::Database(const DatabaseConfig& config) : config_(config) {}

Database::~Database() {
    // Clear statement cache first (before closing db)
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        stmt_cache_.stmts.clear();
    }
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ============================================================================
// Prepared Statement Cache Implementation
// ============================================================================

sqlite3_stmt* Database::get_cached_stmt(const std::string& sql) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);

    auto it = stmt_cache_.stmts.find(sql);
    if (it != stmt_cache_.stmts.end() && it->second != nullptr) {
        // Found cached statement, return it
        sqlite3_stmt* stmt = it->second;
        it->second = nullptr;  // Mark as in-use
        return stmt;
    }

    // Create new statement
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: {} - {}", sqlite3_errmsg(db_), sql);
        return nullptr;
    }

    // Store in cache (as nullptr since it's being used)
    stmt_cache_.stmts[sql] = nullptr;
    return stmt;
}

void Database::return_stmt(sqlite3_stmt* stmt) const {
    if (!stmt) return;

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Find the entry and return the statement
    const char* sql = sqlite3_sql(stmt);
    if (sql) {
        auto it = stmt_cache_.stmts.find(sql);
        if (it != stmt_cache_.stmts.end()) {
            if (it->second == nullptr) {
                it->second = stmt;  // Return to cache
                return;
            }
        }
    }

    // If we can't return to cache, finalize it
    sqlite3_finalize(stmt);
}

bool Database::initialize() {
    WriteLock lock(mutex_);
    
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int rc = sqlite3_open_v2(config_.path.c_str(), &db_, flags, nullptr);
    
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to open database {}: {}", config_.path, sqlite3_errmsg(db_));
        return false;
    }
    
    // Enable foreign keys
    execute_sql("PRAGMA foreign_keys = ON");

    // Enable WAL mode for better concurrency
    execute_sql("PRAGMA journal_mode = WAL");
    
    // Run migrations
    if (!run_migrations(db_)) {
        LOG_ERROR("Failed to run database migrations");
        return false;
    }
    
    LOG_INFO("Database initialized: {}", config_.path);
    return true;
}

bool Database::execute_sql(const std::string& sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQL error: {} - {}", err_msg ? err_msg : "unknown", sql);
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool Database::execute_sql(const std::string& sql, const std::vector<std::string>& params) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: {}", sqlite3_errmsg(db_));
        return false;
    }

    for (size_t i = 0; i < params.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

// ============================================================================
// Generic Query/Execute Implementation
// ============================================================================

void Database::bind_value(sqlite3_stmt* stmt, int index, const Value& value) const {
    std::visit([stmt, index](auto&& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
            sqlite3_bind_null(stmt, index);
        } else if constexpr (std::is_same_v<T, int64_t>) {
            sqlite3_bind_int64(stmt, index, v);
        } else if constexpr (std::is_same_v<T, double>) {
            sqlite3_bind_double(stmt, index, v);
        } else if constexpr (std::is_same_v<T, std::string>) {
            sqlite3_bind_text(stmt, index, v.c_str(), -1, SQLITE_TRANSIENT);
        }
    }, value);
}

bool Database::execute_impl(const std::string& sql, const std::vector<Value>& params) {
    WriteLock lock(mutex_);  // Write lock for modifications

    StmtGuard guard(this, sql);
    if (!guard) {
        return false;
    }

    sqlite3_stmt* stmt = guard.get();
    for (size_t i = 0; i < params.size(); ++i) {
        bind_value(stmt, static_cast<int>(i + 1), params[i]);
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        LOG_ERROR("Execute failed: {} - {}", sqlite3_errmsg(db_), sql);
        return false;
    }
    return true;
}

std::vector<Database::Row> Database::query(const std::string& sql) {
    return query_impl(sql, {});
}

std::vector<Database::Row> Database::query_impl(const std::string& sql, const std::vector<Value>& params) {
    ReadLock lock(mutex_);  // Read lock for queries
    std::vector<Row> results;

    StmtGuard guard(this, sql);
    if (!guard) {
        return results;
    }

    sqlite3_stmt* stmt = guard.get();
    for (size_t i = 0; i < params.size(); ++i) {
        bind_value(stmt, static_cast<int>(i + 1), params[i]);
    }

    int col_count = sqlite3_column_count(stmt);
    std::vector<std::string> col_names;
    col_names.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        col_names.push_back(sqlite3_column_name(stmt, i));
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Row row;
        for (int i = 0; i < col_count; ++i) {
            int col_type = sqlite3_column_type(stmt, i);
            switch (col_type) {
                case SQLITE_INTEGER:
                    row[col_names[i]] = sqlite3_column_int64(stmt, i);
                    break;
                case SQLITE_FLOAT:
                    row[col_names[i]] = sqlite3_column_double(stmt, i);
                    break;
                case SQLITE_TEXT: {
                    const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                    row[col_names[i]] = text ? std::string(text) : std::string();
                    break;
                }
                case SQLITE_NULL:
                default:
                    row[col_names[i]] = nullptr;
                    break;
            }
        }
        results.push_back(std::move(row));
    }

    return results;
}

// ============================================================================
// Network Operations
// ============================================================================

std::optional<Network> Database::get_network(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "SELECT id, name, subnet, description, created_at, updated_at FROM networks WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    std::optional<Network> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Network net;
        net.id = sqlite3_column_int(stmt, 0);
        net.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        net.subnet = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        net.description = sqlite_text(stmt, 3, "");
        net.created_at = sqlite3_column_int64(stmt, 4);
        net.updated_at = sqlite3_column_int64(stmt, 5);
        result = net;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::optional<Network> Database::get_network_by_name(const std::string& name) {
    WriteLock lock(mutex_);
    
    const char* sql = "SELECT id, name, subnet, description, created_at, updated_at FROM networks WHERE name = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    
    std::optional<Network> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Network net;
        net.id = sqlite3_column_int(stmt, 0);
        net.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        net.subnet = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        net.description = sqlite_text(stmt, 3, "");
        net.created_at = sqlite3_column_int64(stmt, 4);
        net.updated_at = sqlite3_column_int64(stmt, 5);
        result = net;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Network> Database::list_networks() {
    WriteLock lock(mutex_);
    std::vector<Network> networks;
    
    const char* sql = "SELECT id, name, subnet, description, created_at, updated_at FROM networks ORDER BY id";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return networks;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Network net;
        net.id = sqlite3_column_int(stmt, 0);
        net.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        net.subnet = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        net.description = sqlite_text(stmt, 3, "");
        net.created_at = sqlite3_column_int64(stmt, 4);
        net.updated_at = sqlite3_column_int64(stmt, 5);
        networks.push_back(net);
    }
    
    sqlite3_finalize(stmt);
    return networks;
}

uint32_t Database::create_network(const Network& network) {
    WriteLock lock(mutex_);
    
    const char* sql = "INSERT INTO networks (name, subnet, description) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare create_network: {}", sqlite3_errmsg(db_));
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, network.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, network.subnet.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, network.description.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_ERROR("Failed to create network: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return 0;
    }
    
    uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    sqlite3_finalize(stmt);
    return id;
}

bool Database::update_network(const Network& network) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE networks SET name = ?, subnet = ?, description = ?, updated_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, network.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, network.subnet.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, network.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, current_timestamp());
    sqlite3_bind_int(stmt, 5, static_cast<int>(network.id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::delete_network(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM networks WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// ============================================================================
// Node Operations
// ============================================================================

std::optional<Node> Database::get_node(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        SELECT id, network_id, name, machine_key_pub, node_key_pub, node_key_updated_at,
               virtual_ip, hostname, os, arch, version, nat_type, online, last_seen,
               authorized, created_at, updated_at
        FROM nodes WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    std::optional<Node> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Node node;
        node.id = sqlite3_column_int(stmt, 0);
        node.network_id = sqlite3_column_int(stmt, 1);
        node.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        node.machine_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        node.node_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        node.node_key_updated_at = sqlite3_column_int64(stmt, 5);
        node.virtual_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        node.hostname = sqlite_text(stmt, 7, "");
        node.os = sqlite_text(stmt, 8, "");
        node.arch = sqlite_text(stmt, 9, "");
        node.version = sqlite_text(stmt, 10, "");
        node.nat_type = sqlite_text(stmt, 11, "unknown");
        node.online = sqlite3_column_int(stmt, 12) != 0;
        node.last_seen = sqlite3_column_int64(stmt, 13);
        node.authorized = sqlite3_column_int(stmt, 14) != 0;
        node.created_at = sqlite3_column_int64(stmt, 15);
        node.updated_at = sqlite3_column_int64(stmt, 16);
        result = node;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::optional<Node> Database::get_node_by_machine_key(const std::string& machine_key_pub) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        SELECT id, network_id, name, machine_key_pub, node_key_pub, node_key_updated_at,
               virtual_ip, hostname, os, arch, version, nat_type, online, last_seen,
               authorized, created_at, updated_at
        FROM nodes WHERE machine_key_pub = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, machine_key_pub.c_str(), -1, SQLITE_TRANSIENT);
    
    std::optional<Node> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Node node;
        node.id = sqlite3_column_int(stmt, 0);
        node.network_id = sqlite3_column_int(stmt, 1);
        node.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        node.machine_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        node.node_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        node.node_key_updated_at = sqlite3_column_int64(stmt, 5);
        node.virtual_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        node.hostname = sqlite_text(stmt, 7, "");
        node.os = sqlite_text(stmt, 8, "");
        node.arch = sqlite_text(stmt, 9, "");
        node.version = sqlite_text(stmt, 10, "");
        node.nat_type = sqlite_text(stmt, 11, "unknown");
        node.online = sqlite3_column_int(stmt, 12) != 0;
        node.last_seen = sqlite3_column_int64(stmt, 13);
        node.authorized = sqlite3_column_int(stmt, 14) != 0;
        node.created_at = sqlite3_column_int64(stmt, 15);
        node.updated_at = sqlite3_column_int64(stmt, 16);
        result = node;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Node> Database::list_nodes(uint32_t network_id) {
    WriteLock lock(mutex_);
    std::vector<Node> nodes;
    
    std::string sql = R"(
        SELECT id, network_id, name, machine_key_pub, node_key_pub, node_key_updated_at,
               virtual_ip, hostname, os, arch, version, nat_type, online, last_seen,
               authorized, created_at, updated_at
        FROM nodes
    )";
    if (network_id > 0) {
        sql += " WHERE network_id = ?";
    }
    sql += " ORDER BY id";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return nodes;
    }
    
    if (network_id > 0) {
        sqlite3_bind_int(stmt, 1, static_cast<int>(network_id));
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Node node;
        node.id = sqlite3_column_int(stmt, 0);
        node.network_id = sqlite3_column_int(stmt, 1);
        node.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        node.machine_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        node.node_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        node.node_key_updated_at = sqlite3_column_int64(stmt, 5);
        node.virtual_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        node.hostname = sqlite_text(stmt, 7, "");
        node.os = sqlite_text(stmt, 8, "");
        node.arch = sqlite_text(stmt, 9, "");
        node.version = sqlite_text(stmt, 10, "");
        node.nat_type = sqlite_text(stmt, 11, "unknown");
        node.online = sqlite3_column_int(stmt, 12) != 0;
        node.last_seen = sqlite3_column_int64(stmt, 13);
        node.authorized = sqlite3_column_int(stmt, 14) != 0;
        node.created_at = sqlite3_column_int64(stmt, 15);
        node.updated_at = sqlite3_column_int64(stmt, 16);
        nodes.push_back(node);
    }
    
    sqlite3_finalize(stmt);
    return nodes;
}

std::vector<Node> Database::list_online_nodes(uint32_t network_id) {
    WriteLock lock(mutex_);
    std::vector<Node> nodes;
    
    std::string sql = R"(
        SELECT id, network_id, name, machine_key_pub, node_key_pub, node_key_updated_at,
               virtual_ip, hostname, os, arch, version, nat_type, online, last_seen,
               authorized, created_at, updated_at
        FROM nodes WHERE online = 1
    )";
    if (network_id > 0) {
        sql += " AND network_id = ?";
    }
    sql += " ORDER BY id";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return nodes;
    }
    
    if (network_id > 0) {
        sqlite3_bind_int(stmt, 1, static_cast<int>(network_id));
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Node node;
        node.id = sqlite3_column_int(stmt, 0);
        node.network_id = sqlite3_column_int(stmt, 1);
        node.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        node.machine_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        node.node_key_pub = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        node.node_key_updated_at = sqlite3_column_int64(stmt, 5);
        node.virtual_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        node.hostname = sqlite_text(stmt, 7, "");
        node.os = sqlite_text(stmt, 8, "");
        node.arch = sqlite_text(stmt, 9, "");
        node.version = sqlite_text(stmt, 10, "");
        node.nat_type = sqlite_text(stmt, 11, "unknown");
        node.online = sqlite3_column_int(stmt, 12) != 0;
        node.last_seen = sqlite3_column_int64(stmt, 13);
        node.authorized = sqlite3_column_int(stmt, 14) != 0;
        node.created_at = sqlite3_column_int64(stmt, 15);
        node.updated_at = sqlite3_column_int64(stmt, 16);
        nodes.push_back(node);
    }
    
    sqlite3_finalize(stmt);
    return nodes;
}

uint32_t Database::create_node(const Node& node) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO nodes (network_id, name, machine_key_pub, node_key_pub, virtual_ip,
                          hostname, os, arch, version, nat_type, authorized)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare create_node: {}", sqlite3_errmsg(db_));
        return 0;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(node.network_id));
    sqlite3_bind_text(stmt, 2, node.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, node.machine_key_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, node.node_key_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, node.virtual_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, node.hostname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, node.os.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, node.arch.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, node.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, node.nat_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 11, node.authorized ? 1 : 0);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_ERROR("Failed to create node: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return 0;
    }
    
    uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    sqlite3_finalize(stmt);
    return id;
}

bool Database::update_node(const Node& node) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        UPDATE nodes SET name = ?, node_key_pub = ?, hostname = ?, os = ?, arch = ?,
                        version = ?, nat_type = ?, authorized = ?, online = ?, 
                        last_seen = ?, updated_at = ?
        WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, node.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, node.node_key_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, node.hostname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, node.os.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, node.arch.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, node.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, node.nat_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, node.authorized ? 1 : 0);
    sqlite3_bind_int(stmt, 9, node.online ? 1 : 0);
    sqlite3_bind_int64(stmt, 10, node.last_seen);
    sqlite3_bind_int64(stmt, 11, current_timestamp());
    sqlite3_bind_int(stmt, 12, static_cast<int>(node.id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::delete_node(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM nodes WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::set_node_online(uint32_t id, bool online) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE nodes SET online = ?, last_seen = ?, updated_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    int64_t now = current_timestamp();
    sqlite3_bind_int(stmt, 1, online ? 1 : 0);
    sqlite3_bind_int64(stmt, 2, now);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_int(stmt, 4, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::update_node_key(uint32_t id, const std::string& node_key_pub) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE nodes SET node_key_pub = ?, node_key_updated_at = ?, updated_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    int64_t now = current_timestamp();
    sqlite3_bind_text(stmt, 1, node_key_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, now);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_int(stmt, 4, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::string Database::allocate_virtual_ip(uint32_t network_id) {
    // Get network subnet
    auto network = get_network(network_id);
    if (!network) {
        return "";
    }
    
    uint32_t base_ip;
    int prefix_len;
    if (!parse_subnet(network->subnet, base_ip, prefix_len)) {
        return "";
    }
    
    // Calculate IP range
    uint32_t host_bits = 32 - prefix_len;
    uint32_t num_hosts = (1u << host_bits) - 2; // Exclude network and broadcast
    uint32_t first_host = base_ip + 1; // .1 is often gateway, start from .2
    
    WriteLock lock(mutex_);
    
    // Get all used IPs
    const char* sql = "SELECT virtual_ip FROM nodes WHERE network_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(network_id));
    
    std::set<uint32_t> used_ips;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* ip_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
            used_ips.insert(ntohl(addr.s_addr));
        }
    }
    sqlite3_finalize(stmt);
    
    // Find first available IP (start from .2 to reserve .1 for gateway)
    for (uint32_t i = 1; i < num_hosts; ++i) {
        uint32_t candidate = first_host + i;
        if (used_ips.find(candidate) == used_ips.end()) {
            return ip_to_string(candidate);
        }
    }
    
    return ""; // No available IPs
}

// ============================================================================
// Node Endpoint Operations
// ============================================================================

std::vector<NodeEndpoint> Database::get_node_endpoints(uint32_t node_id) {
    WriteLock lock(mutex_);
    std::vector<NodeEndpoint> endpoints;
    
    const char* sql = R"(
        SELECT id, node_id, type, ip, port, priority, updated_at
        FROM node_endpoints WHERE node_id = ? ORDER BY priority ASC
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return endpoints;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NodeEndpoint ep;
        ep.id = sqlite3_column_int(stmt, 0);
        ep.node_id = sqlite3_column_int(stmt, 1);
        ep.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        ep.ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        ep.port = static_cast<uint16_t>(sqlite3_column_int(stmt, 4));
        ep.priority = static_cast<uint8_t>(sqlite3_column_int(stmt, 5));
        ep.updated_at = sqlite3_column_int64(stmt, 6);
        endpoints.push_back(ep);
    }
    
    sqlite3_finalize(stmt);
    return endpoints;
}

bool Database::update_node_endpoints(uint32_t node_id, const std::vector<NodeEndpoint>& endpoints) {
    WriteLock lock(mutex_);
    
    // Delete existing endpoints
    const char* del_sql = "DELETE FROM node_endpoints WHERE node_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, del_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    // Insert new endpoints
    const char* ins_sql = R"(
        INSERT INTO node_endpoints (node_id, type, ip, port, priority)
        VALUES (?, ?, ?, ?, ?)
    )";
    
    for (const auto& ep : endpoints) {
        if (sqlite3_prepare_v2(db_, ins_sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
        sqlite3_bind_text(stmt, 2, ep.type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, ep.ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, ep.port);
        sqlite3_bind_int(stmt, 5, ep.priority);
        
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
    }
    
    return true;
}

// ============================================================================
// Node Route Operations
// ============================================================================

std::vector<NodeRoute> Database::get_node_routes(uint32_t node_id) {
    WriteLock lock(mutex_);
    std::vector<NodeRoute> routes;
    
    const char* sql = R"(
        SELECT id, node_id, cidr, priority, weight, enabled, created_at
        FROM node_routes WHERE node_id = ? ORDER BY priority ASC
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return routes;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NodeRoute route;
        route.id = sqlite3_column_int(stmt, 0);
        route.node_id = sqlite3_column_int(stmt, 1);
        route.cidr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        route.priority = static_cast<uint16_t>(sqlite3_column_int(stmt, 3));
        route.weight = static_cast<uint16_t>(sqlite3_column_int(stmt, 4));
        route.enabled = sqlite3_column_int(stmt, 5) != 0;
        route.created_at = sqlite3_column_int64(stmt, 6);
        routes.push_back(route);
    }
    
    sqlite3_finalize(stmt);
    return routes;
}

std::vector<NodeRoute> Database::get_all_routes(uint32_t network_id) {
    WriteLock lock(mutex_);
    std::vector<NodeRoute> routes;
    
    std::string sql = R"(
        SELECT r.id, r.node_id, r.cidr, r.priority, r.weight, r.enabled, r.created_at
        FROM node_routes r
        JOIN nodes n ON r.node_id = n.id
        WHERE r.enabled = 1
    )";
    if (network_id > 0) {
        sql += " AND n.network_id = ?";
    }
    sql += " ORDER BY r.priority ASC";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return routes;
    }
    
    if (network_id > 0) {
        sqlite3_bind_int(stmt, 1, static_cast<int>(network_id));
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        NodeRoute route;
        route.id = sqlite3_column_int(stmt, 0);
        route.node_id = sqlite3_column_int(stmt, 1);
        route.cidr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        route.priority = static_cast<uint16_t>(sqlite3_column_int(stmt, 3));
        route.weight = static_cast<uint16_t>(sqlite3_column_int(stmt, 4));
        route.enabled = sqlite3_column_int(stmt, 5) != 0;
        route.created_at = sqlite3_column_int64(stmt, 6);
        routes.push_back(route);
    }
    
    sqlite3_finalize(stmt);
    return routes;
}

uint32_t Database::create_node_route(const NodeRoute& route) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO node_routes (node_id, cidr, priority, weight, enabled)
        VALUES (?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(route.node_id));
    sqlite3_bind_text(stmt, 2, route.cidr.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, route.priority);
    sqlite3_bind_int(stmt, 4, route.weight);
    sqlite3_bind_int(stmt, 5, route.enabled ? 1 : 0);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 0;
    }
    
    uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    sqlite3_finalize(stmt);
    return id;
}

bool Database::update_node_route(const NodeRoute& route) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE node_routes SET cidr = ?, priority = ?, weight = ?, enabled = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, route.cidr.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, route.priority);
    sqlite3_bind_int(stmt, 3, route.weight);
    sqlite3_bind_int(stmt, 4, route.enabled ? 1 : 0);
    sqlite3_bind_int(stmt, 5, static_cast<int>(route.id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::delete_node_route(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM node_routes WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// ============================================================================
// Server Operations
// ============================================================================

std::optional<Server> Database::get_server(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        SELECT id, name, type, url, region, capabilities, stun_ip, stun_ip2, stun_port,
               enabled, server_token, last_heartbeat, created_at
        FROM servers WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    std::optional<Server> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Server srv;
        srv.id = sqlite3_column_int(stmt, 0);
        srv.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        srv.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        srv.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        srv.region = sqlite_text(stmt, 4, "");
        srv.capabilities = sqlite_text(stmt, 5, "[]");
        srv.stun_ip = sqlite_text(stmt, 6, "");
        srv.stun_ip2 = sqlite_text(stmt, 7, "");
        srv.stun_port = static_cast<uint16_t>(sqlite3_column_int(stmt, 8));
        srv.enabled = sqlite3_column_int(stmt, 9) != 0;
        srv.server_token = sqlite_text(stmt, 10, "");
        srv.last_heartbeat = sqlite3_column_int64(stmt, 11);
        srv.created_at = sqlite3_column_int64(stmt, 12);
        result = srv;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Server> Database::list_servers() {
    WriteLock lock(mutex_);
    std::vector<Server> servers;
    
    const char* sql = R"(
        SELECT id, name, type, url, region, capabilities, stun_ip, stun_ip2, stun_port,
               enabled, server_token, last_heartbeat, created_at
        FROM servers ORDER BY id
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return servers;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Server srv;
        srv.id = sqlite3_column_int(stmt, 0);
        srv.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        srv.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        srv.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        srv.region = sqlite_text(stmt, 4, "");
        srv.capabilities = sqlite_text(stmt, 5, "[]");
        srv.stun_ip = sqlite_text(stmt, 6, "");
        srv.stun_ip2 = sqlite_text(stmt, 7, "");
        srv.stun_port = static_cast<uint16_t>(sqlite3_column_int(stmt, 8));
        srv.enabled = sqlite3_column_int(stmt, 9) != 0;
        srv.server_token = sqlite_text(stmt, 10, "");
        srv.last_heartbeat = sqlite3_column_int64(stmt, 11);
        srv.created_at = sqlite3_column_int64(stmt, 12);
        servers.push_back(srv);
    }
    
    sqlite3_finalize(stmt);
    return servers;
}

std::vector<Server> Database::list_enabled_servers() {
    WriteLock lock(mutex_);
    std::vector<Server> servers;
    
    const char* sql = R"(
        SELECT id, name, type, url, region, capabilities, stun_ip, stun_ip2, stun_port,
               enabled, server_token, last_heartbeat, created_at
        FROM servers WHERE enabled = 1 ORDER BY id
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return servers;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Server srv;
        srv.id = sqlite3_column_int(stmt, 0);
        srv.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        srv.type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        srv.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        srv.region = sqlite_text(stmt, 4, "");
        srv.capabilities = sqlite_text(stmt, 5, "[]");
        srv.stun_ip = sqlite_text(stmt, 6, "");
        srv.stun_ip2 = sqlite_text(stmt, 7, "");
        srv.stun_port = static_cast<uint16_t>(sqlite3_column_int(stmt, 8));
        srv.enabled = sqlite3_column_int(stmt, 9) != 0;
        srv.server_token = sqlite_text(stmt, 10, "");
        srv.last_heartbeat = sqlite3_column_int64(stmt, 11);
        srv.created_at = sqlite3_column_int64(stmt, 12);
        servers.push_back(srv);
    }
    
    sqlite3_finalize(stmt);
    return servers;
}

uint32_t Database::create_server(const Server& server) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO servers (name, type, url, region, capabilities, stun_ip, stun_ip2,
                            stun_port, enabled, server_token)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, server.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, server.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, server.url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, server.region.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, server.capabilities.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, server.stun_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, server.stun_ip2.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, server.stun_port);
    sqlite3_bind_int(stmt, 9, server.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 10, server.server_token.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 0;
    }
    
    uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    sqlite3_finalize(stmt);
    return id;
}

bool Database::update_server(const Server& server) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        UPDATE servers SET name = ?, type = ?, url = ?, region = ?, capabilities = ?,
                          stun_ip = ?, stun_ip2 = ?, stun_port = ?, enabled = ?, server_token = ?
        WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, server.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, server.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, server.url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, server.region.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, server.capabilities.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, server.stun_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, server.stun_ip2.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, server.stun_port);
    sqlite3_bind_int(stmt, 9, server.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 10, server.server_token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 11, static_cast<int>(server.id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::delete_server(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM servers WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::update_server_heartbeat(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE servers SET last_heartbeat = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, current_timestamp());
    sqlite3_bind_int(stmt, 2, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// ============================================================================
// Latency Operations
// ============================================================================

bool Database::update_latency(const std::string& src_type, uint32_t src_id,
                              const std::string& dst_type, uint32_t dst_id,
                              uint32_t rtt_ms) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO latency_records (src_type, src_id, dst_type, dst_id, rtt_ms, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(src_type, src_id, dst_type, dst_id) DO UPDATE SET
            rtt_ms = excluded.rtt_ms,
            recorded_at = excluded.recorded_at
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, src_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, static_cast<int>(src_id));
    sqlite3_bind_text(stmt, 3, dst_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, static_cast<int>(dst_id));
    sqlite3_bind_int(stmt, 5, static_cast<int>(rtt_ms));
    sqlite3_bind_int64(stmt, 6, current_timestamp());
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<LatencyRecord> Database::get_latencies() {
    WriteLock lock(mutex_);
    std::vector<LatencyRecord> records;
    
    const char* sql = "SELECT id, src_type, src_id, dst_type, dst_id, rtt_ms, recorded_at FROM latency_records";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return records;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        LatencyRecord rec;
        rec.id = sqlite3_column_int(stmt, 0);
        rec.src_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.src_id = sqlite3_column_int(stmt, 2);
        rec.dst_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        rec.dst_id = sqlite3_column_int(stmt, 4);
        rec.rtt_ms = sqlite3_column_int(stmt, 5);
        rec.recorded_at = sqlite3_column_int64(stmt, 6);
        records.push_back(rec);
    }
    
    sqlite3_finalize(stmt);
    return records;
}

std::optional<uint32_t> Database::get_latency(const std::string& src_type, uint32_t src_id,
                                               const std::string& dst_type, uint32_t dst_id) {
    WriteLock lock(mutex_);
    
    const char* sql = "SELECT rtt_ms FROM latency_records WHERE src_type = ? AND src_id = ? AND dst_type = ? AND dst_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, src_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, static_cast<int>(src_id));
    sqlite3_bind_text(stmt, 3, dst_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, static_cast<int>(dst_id));
    
    std::optional<uint32_t> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

// ============================================================================
// Token Blacklist Operations
// ============================================================================

bool Database::blacklist_token(const std::string& jti, uint32_t node_id,
                               const std::string& reason, int64_t expires_at) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT OR REPLACE INTO token_blacklist (jti, node_id, reason, expires_at)
        VALUES (?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, jti.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, static_cast<int>(node_id));
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, expires_at);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::is_token_blacklisted(const std::string& jti) {
    WriteLock lock(mutex_);
    
    const char* sql = "SELECT 1 FROM token_blacklist WHERE jti = ? AND expires_at > ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, jti.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, current_timestamp());
    
    bool blacklisted = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return blacklisted;
}

std::vector<TokenBlacklistEntry> Database::get_blacklist() {
    WriteLock lock(mutex_);
    std::vector<TokenBlacklistEntry> entries;
    
    const char* sql = "SELECT jti, node_id, reason, expires_at, created_at FROM token_blacklist WHERE expires_at > ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return entries;
    }
    
    sqlite3_bind_int64(stmt, 1, current_timestamp());
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TokenBlacklistEntry entry;
        entry.jti = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.node_id = sqlite3_column_int(stmt, 1);
        entry.reason = sqlite_text(stmt, 2, "");
        entry.expires_at = sqlite3_column_int64(stmt, 3);
        entry.created_at = sqlite3_column_int64(stmt, 4);
        entries.push_back(entry);
    }
    
    sqlite3_finalize(stmt);
    return entries;
}

bool Database::cleanup_blacklist() {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM token_blacklist WHERE expires_at <= ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, current_timestamp());
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// ============================================================================
// Settings Operations
// ============================================================================

std::optional<std::string> Database::get_setting(const std::string& key) {
    WriteLock lock(mutex_);
    
    const char* sql = "SELECT value FROM settings WHERE key = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    
    std::optional<std::string> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool Database::set_setting(const std::string& key, const std::string& value) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, current_timestamp());
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

// ============================================================================
// Node-Server Connection Operations
// ============================================================================

bool Database::update_node_server_connection(uint32_t node_id, uint32_t server_id) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO node_server_connections (node_id, server_id, connected_at, last_ping)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(node_id, server_id) DO UPDATE SET last_ping = excluded.last_ping
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    int64_t now = current_timestamp();
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    sqlite3_bind_int(stmt, 2, static_cast<int>(server_id));
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_int64(stmt, 4, now);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::remove_node_server_connection(uint32_t node_id, uint32_t server_id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM node_server_connections WHERE node_id = ? AND server_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    sqlite3_bind_int(stmt, 2, static_cast<int>(server_id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

std::vector<uint32_t> Database::get_node_connected_servers(uint32_t node_id) {
    WriteLock lock(mutex_);
    std::vector<uint32_t> server_ids;
    
    const char* sql = "SELECT server_id FROM node_server_connections WHERE node_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return server_ids;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(node_id));
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        server_ids.push_back(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return server_ids;
}

std::vector<uint32_t> Database::get_server_connected_nodes(uint32_t server_id) {
    WriteLock lock(mutex_);
    std::vector<uint32_t> node_ids;
    
    const char* sql = "SELECT node_id FROM node_server_connections WHERE server_id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return node_ids;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(server_id));
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        node_ids.push_back(sqlite3_column_int(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return node_ids;
}

// ============================================================================
// Auth Key Operations
// ============================================================================

std::optional<AuthKey> Database::get_auth_key(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        SELECT id, key, network_id, description, reusable, ephemeral, 
               max_uses, used_count, expires_at, created_at, created_by
        FROM auth_keys WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    
    AuthKey key;
    key.id = sqlite3_column_int(stmt, 0);
    key.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    key.network_id = sqlite3_column_int(stmt, 2);
    key.description = sqlite3_column_text(stmt, 3) ? 
                      reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)) : "";
    key.reusable = sqlite3_column_int(stmt, 4) != 0;
    key.ephemeral = sqlite3_column_int(stmt, 5) != 0;
    key.max_uses = sqlite3_column_type(stmt, 6) != SQLITE_NULL ? sqlite3_column_int(stmt, 6) : -1;
    key.used_count = sqlite3_column_int(stmt, 7);
    key.expires_at = sqlite3_column_int64(stmt, 8);
    key.created_at = sqlite3_column_int64(stmt, 9);
    key.created_by = sqlite3_column_text(stmt, 10) ?
                     reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10)) : "";
    
    sqlite3_finalize(stmt);
    return key;
}

std::optional<AuthKey> Database::get_auth_key_by_key(const std::string& key_str) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        SELECT id, key, network_id, description, reusable, ephemeral, 
               max_uses, used_count, expires_at, created_at, created_by
        FROM auth_keys WHERE key = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, key_str.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    
    AuthKey key;
    key.id = sqlite3_column_int(stmt, 0);
    key.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    key.network_id = sqlite3_column_int(stmt, 2);
    key.description = sqlite3_column_text(stmt, 3) ? 
                      reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)) : "";
    key.reusable = sqlite3_column_int(stmt, 4) != 0;
    key.ephemeral = sqlite3_column_int(stmt, 5) != 0;
    key.max_uses = sqlite3_column_type(stmt, 6) != SQLITE_NULL ? sqlite3_column_int(stmt, 6) : -1;
    key.used_count = sqlite3_column_int(stmt, 7);
    key.expires_at = sqlite3_column_int64(stmt, 8);
    key.created_at = sqlite3_column_int64(stmt, 9);
    key.created_by = sqlite3_column_text(stmt, 10) ?
                     reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10)) : "";
    
    sqlite3_finalize(stmt);
    return key;
}

std::vector<AuthKey> Database::list_auth_keys(uint32_t network_id) {
    WriteLock lock(mutex_);
    std::vector<AuthKey> keys;
    
    std::string sql = R"(
        SELECT id, key, network_id, description, reusable, ephemeral, 
               max_uses, used_count, expires_at, created_at, created_by
        FROM auth_keys
    )";
    if (network_id > 0) {
        sql += " WHERE network_id = ?";
    }
    sql += " ORDER BY created_at DESC";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return keys;
    }
    
    if (network_id > 0) {
        sqlite3_bind_int(stmt, 1, static_cast<int>(network_id));
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuthKey key;
        key.id = sqlite3_column_int(stmt, 0);
        key.key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        key.network_id = sqlite3_column_int(stmt, 2);
        key.description = sqlite3_column_text(stmt, 3) ? 
                          reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)) : "";
        key.reusable = sqlite3_column_int(stmt, 4) != 0;
        key.ephemeral = sqlite3_column_int(stmt, 5) != 0;
        key.max_uses = sqlite3_column_type(stmt, 6) != SQLITE_NULL ? sqlite3_column_int(stmt, 6) : -1;
        key.used_count = sqlite3_column_int(stmt, 7);
        key.expires_at = sqlite3_column_int64(stmt, 8);
        key.created_at = sqlite3_column_int64(stmt, 9);
        key.created_by = sqlite3_column_text(stmt, 10) ?
                         reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10)) : "";
        keys.push_back(key);
    }
    
    sqlite3_finalize(stmt);
    return keys;
}

uint32_t Database::create_auth_key(const AuthKey& auth_key) {
    WriteLock lock(mutex_);
    
    const char* sql = R"(
        INSERT INTO auth_keys (key, network_id, description, reusable, ephemeral, 
                               max_uses, expires_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Database: Failed to prepare auth_key insert: {}", sqlite3_errmsg(db_));
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, auth_key.key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, static_cast<int>(auth_key.network_id));
    sqlite3_bind_text(stmt, 3, auth_key.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, auth_key.reusable ? 1 : 0);
    sqlite3_bind_int(stmt, 5, auth_key.ephemeral ? 1 : 0);
    if (auth_key.max_uses >= 0) {
        sqlite3_bind_int(stmt, 6, auth_key.max_uses);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    if (auth_key.expires_at > 0) {
        sqlite3_bind_int64(stmt, 7, auth_key.expires_at);
    } else {
        sqlite3_bind_null(stmt, 7);
    }
    sqlite3_bind_text(stmt, 8, auth_key.created_by.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        LOG_ERROR("Database: Failed to create auth_key: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return 0;
    }
    
    uint32_t id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    sqlite3_finalize(stmt);
    return id;
}

bool Database::delete_auth_key(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "DELETE FROM auth_keys WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::increment_auth_key_usage(uint32_t id) {
    WriteLock lock(mutex_);
    
    const char* sql = "UPDATE auth_keys SET used_count = used_count + 1 WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, static_cast<int>(id));
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

bool Database::is_auth_key_valid(const AuthKey& key) {
    // Check expiration
    if (key.expires_at > 0) {
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now > key.expires_at) {
            return false;
        }
    }
    
    // Check usage limit
    if (!key.reusable && key.used_count > 0) {
        return false;
    }
    
    if (key.reusable && key.max_uses >= 0 && key.used_count >= key.max_uses) {
        return false;
    }
    
    return true;
}

} // namespace edgelink::controller
