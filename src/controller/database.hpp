#pragma once

#include "common/types.hpp"
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace edgelink::controller {

// Database error types
enum class DbError {
    OPEN_FAILED,
    QUERY_FAILED,
    NOT_FOUND,
    DUPLICATE_KEY,
    CONSTRAINT_VIOLATION,
    INTERNAL_ERROR,
};

std::string db_error_message(DbError error);

// Network record
struct NetworkRecord {
    uint32_t id = 0;
    std::string name;
    std::string cidr;          // e.g., "10.0.0.0/8"
    uint64_t created_at = 0;   // Unix timestamp (ms)
};

// AuthKey record
struct AuthKeyRecord {
    uint32_t id = 0;
    std::string key;           // e.g., "tskey-auth-abc123"
    uint32_t network_id = 0;
    int32_t use_count = 0;
    int32_t max_uses = -1;     // -1 = unlimited
    uint64_t expires_at = 0;   // 0 = no expiration
    uint64_t created_at = 0;
};

// Node record
struct NodeRecord {
    NodeId id = 0;
    NetworkId network_id = 0;
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key{};
    std::array<uint8_t, X25519_KEY_SIZE> node_key{};
    IPv4Address virtual_ip{};
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    bool online = false;
    uint64_t last_seen = 0;
    uint64_t created_at = 0;
};

// RAII wrapper for SQLite statement
class Statement {
public:
    Statement() = default;
    explicit Statement(sqlite3_stmt* stmt) : stmt_(stmt) {}
    ~Statement();

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    Statement(Statement&& other) noexcept;
    Statement& operator=(Statement&& other) noexcept;

    sqlite3_stmt* get() const { return stmt_; }
    explicit operator bool() const { return stmt_ != nullptr; }

    // Binding helpers
    bool bind_int(int index, int value);
    bool bind_int64(int index, int64_t value);
    bool bind_text(int index, std::string_view text);
    bool bind_blob(int index, std::span<const uint8_t> data);
    bool bind_null(int index);

    // Step and reset
    int step();
    void reset();

    // Column getters
    int column_int(int index);
    int64_t column_int64(int index);
    std::string column_text(int index);
    std::vector<uint8_t> column_blob(int index);
    bool column_is_null(int index);

private:
    sqlite3_stmt* stmt_ = nullptr;
};

// Database manager
class Database {
public:
    Database() = default;
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Open database file
    std::expected<void, DbError> open(const std::string& path);

    // Close database
    void close();

    // Initialize schema
    std::expected<void, DbError> init_schema();

    // ========================================================================
    // Network operations
    // ========================================================================
    std::expected<NetworkRecord, DbError> create_network(
        const std::string& name, const std::string& cidr);
    std::expected<NetworkRecord, DbError> get_network(uint32_t id);
    std::expected<NetworkRecord, DbError> get_network_by_name(const std::string& name);
    std::expected<std::vector<NetworkRecord>, DbError> list_networks();

    // ========================================================================
    // AuthKey operations
    // ========================================================================
    std::expected<AuthKeyRecord, DbError> create_authkey(
        const std::string& key, uint32_t network_id,
        int32_t max_uses = -1, uint64_t expires_at = 0);
    std::expected<AuthKeyRecord, DbError> get_authkey(const std::string& key);
    std::expected<std::vector<AuthKeyRecord>, DbError> list_authkeys(uint32_t network_id = 0);
    std::expected<void, DbError> increment_authkey_use(const std::string& key);
    std::expected<void, DbError> delete_authkey(const std::string& key);

    // ========================================================================
    // Node operations
    // ========================================================================
    std::expected<NodeRecord, DbError> create_node(
        NetworkId network_id,
        std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key,
        std::span<const uint8_t, X25519_KEY_SIZE> node_key,
        const std::string& hostname,
        const std::string& os,
        const std::string& arch,
        const std::string& version);

    std::expected<NodeRecord, DbError> get_node(NodeId id);
    std::expected<NodeRecord, DbError> get_node_by_machine_key(
        std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key);
    std::expected<std::vector<NodeRecord>, DbError> get_nodes_by_network(NetworkId network_id);
    std::expected<std::vector<NodeRecord>, DbError> list_all_nodes();
    std::expected<void, DbError> delete_node(NodeId id);

    std::expected<void, DbError> update_node_key(
        NodeId id, std::span<const uint8_t, X25519_KEY_SIZE> node_key);
    std::expected<void, DbError> update_node_online(NodeId id, bool online);
    std::expected<void, DbError> update_node_last_seen(NodeId id, uint64_t timestamp);
    std::expected<void, DbError> update_node_info(
        NodeId id, const std::string& hostname,
        const std::string& os, const std::string& arch, const std::string& version);

    // Find or create node by machine_key
    std::expected<NodeRecord, DbError> find_or_create_node(
        NetworkId network_id,
        std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key,
        std::span<const uint8_t, X25519_KEY_SIZE> node_key,
        const std::string& hostname,
        const std::string& os,
        const std::string& arch,
        const std::string& version);

    // ========================================================================
    // Utility
    // ========================================================================

    // Allocate next available virtual IP in network
    std::expected<IPv4Address, DbError> allocate_virtual_ip(NetworkId network_id);

    // Get current timestamp in milliseconds
    static uint64_t now_ms();

private:
    std::expected<Statement, DbError> prepare(const std::string& sql);
    std::expected<void, DbError> execute(const std::string& sql);

    sqlite3* db_ = nullptr;
};

} // namespace edgelink::controller
