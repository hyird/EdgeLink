#include "migrations.hpp"
#include "common/log.hpp"
#include <spdlog/spdlog.h>

namespace edgelink::controller {

// Define all database migrations
static const std::vector<Migration> migrations = {
    {
        1, "initial_schema",
        R"SQL(
-- Networks table
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    subnet TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    machine_key_pub TEXT NOT NULL UNIQUE,
    node_key_pub TEXT NOT NULL,
    node_key_updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    virtual_ip TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    os TEXT DEFAULT '',
    arch TEXT DEFAULT '',
    version TEXT DEFAULT '',
    nat_type TEXT DEFAULT 'unknown',
    online INTEGER NOT NULL DEFAULT 0,
    last_seen INTEGER DEFAULT NULL,
    authorized INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE,
    UNIQUE(network_id, virtual_ip)
);
CREATE INDEX IF NOT EXISTS idx_nodes_network ON nodes(network_id);
CREATE INDEX IF NOT EXISTS idx_nodes_online ON nodes(online);
CREATE INDEX IF NOT EXISTS idx_nodes_machine_key ON nodes(machine_key_pub);

-- Node endpoints table
CREATE TABLE IF NOT EXISTS node_endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('lan', 'wan', 'relay')),
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    priority INTEGER NOT NULL DEFAULT 2,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(node_id, type, ip, port)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_node ON node_endpoints(node_id);

-- Node routes table
CREATE TABLE IF NOT EXISTS node_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL,
    cidr TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    weight INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(node_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_routes_node ON node_routes(node_id);

-- Servers table (relay/STUN)
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL CHECK(type IN ('builtin', 'external')),
    url TEXT NOT NULL,
    region TEXT DEFAULT '',
    capabilities TEXT DEFAULT '[]',
    stun_ip TEXT DEFAULT '',
    stun_ip2 TEXT DEFAULT '',
    stun_port INTEGER NOT NULL DEFAULT 3478,
    enabled INTEGER NOT NULL DEFAULT 1,
    server_token TEXT DEFAULT '',
    last_heartbeat INTEGER DEFAULT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_servers_enabled ON servers(enabled);

-- Latency records table
CREATE TABLE IF NOT EXISTS latency_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_type TEXT NOT NULL CHECK(src_type IN ('node', 'server')),
    src_id INTEGER NOT NULL,
    dst_type TEXT NOT NULL CHECK(dst_type IN ('node', 'server')),
    dst_id INTEGER NOT NULL,
    rtt_ms INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(src_type, src_id, dst_type, dst_id)
);
CREATE INDEX IF NOT EXISTS idx_latency_src ON latency_records(src_type, src_id);
CREATE INDEX IF NOT EXISTS idx_latency_dst ON latency_records(dst_type, dst_id);

-- Token blacklist table
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti TEXT PRIMARY KEY,
    node_id INTEGER DEFAULT NULL,
    reason TEXT DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON token_blacklist(expires_at);

-- Node-server connections table
CREATE TABLE IF NOT EXISTS node_server_connections (
    node_id INTEGER NOT NULL,
    server_id INTEGER NOT NULL,
    connected_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_ping INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (node_id, server_id),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id INTEGER DEFAULT NULL,
    action TEXT NOT NULL,
    target_type TEXT DEFAULT NULL,
    target_id INTEGER DEFAULT NULL,
    details TEXT DEFAULT '{}',
    ip_address TEXT DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_type, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at);

-- Schema version table
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
        )SQL"
    },
    {
        2, "add_config_version",
        R"SQL(
-- Add config_version to networks for incremental updates
ALTER TABLE networks ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1;

-- Create triggers to auto-increment config_version on changes
-- Separate triggers for INSERT, UPDATE, DELETE (SQLite requirement)

CREATE TRIGGER IF NOT EXISTS trg_nodes_insert_config
AFTER INSERT ON nodes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = NEW.network_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_nodes_update_config
AFTER UPDATE ON nodes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = NEW.network_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_nodes_delete_config
AFTER DELETE ON nodes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id = OLD.network_id;
END;

CREATE TRIGGER IF NOT EXISTS trg_routes_insert_config
AFTER INSERT ON node_routes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id IN (
        SELECT network_id FROM nodes 
        WHERE id = NEW.node_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_routes_update_config
AFTER UPDATE ON node_routes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id IN (
        SELECT network_id FROM nodes 
        WHERE id = NEW.node_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_routes_delete_config
AFTER DELETE ON node_routes
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now')
    WHERE id IN (
        SELECT network_id FROM nodes 
        WHERE id = OLD.node_id
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_servers_insert_config
AFTER INSERT ON servers
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now');
END;

CREATE TRIGGER IF NOT EXISTS trg_servers_update_config
AFTER UPDATE ON servers
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now');
END;

CREATE TRIGGER IF NOT EXISTS trg_servers_delete_config
AFTER DELETE ON servers
BEGIN
    UPDATE networks SET 
        config_version = config_version + 1,
        updated_at = strftime('%s', 'now');
END;
        )SQL"
    },
    {
        3, "add_node_metadata",
        R"SQL(
-- Add metadata column for extensible node properties
ALTER TABLE nodes ADD COLUMN metadata TEXT DEFAULT '{}';

-- Add last gateway mode info
ALTER TABLE nodes ADD COLUMN gateway_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN gateway_lan_interface TEXT DEFAULT '';
        )SQL"
    },
    {
        4, "add_auth_keys",
        R"SQL(
-- Auth keys for client registration
CREATE TABLE IF NOT EXISTS auth_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    network_id INTEGER NOT NULL,
    description TEXT DEFAULT '',
    reusable INTEGER NOT NULL DEFAULT 0,
    ephemeral INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER DEFAULT NULL,
    used_count INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER DEFAULT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT DEFAULT 'cli',
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_auth_keys_key ON auth_keys(key);
CREATE INDEX IF NOT EXISTS idx_auth_keys_network ON auth_keys(network_id);

-- Track which auth key was used to register a node
ALTER TABLE nodes ADD COLUMN auth_key_id INTEGER DEFAULT NULL REFERENCES auth_keys(id);
        )SQL"
    }
};

const std::vector<Migration>& get_migrations() {
    return migrations;
}

int get_schema_version(sqlite3* db) {
    const char* sql = "SELECT MAX(version) FROM schema_version";
    sqlite3_stmt* stmt = nullptr;
    int version = 0;
    
    // First check if schema_version table exists
    const char* check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'";
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return 0; // Table doesn't exist yet
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            version = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    return version;
}

bool run_migrations(sqlite3* db) {
    int current_version = get_schema_version(db);
    const auto& all_migrations = get_migrations();
    
    LOG_INFO("Current schema version: {}, latest: {}", 
             current_version, 
             all_migrations.empty() ? 0 : all_migrations.back().version);
    
    for (const auto& migration : all_migrations) {
        if (migration.version <= current_version) {
            continue;
        }
        
        LOG_INFO("Applying migration {}: {}", migration.version, migration.name);
        
        // Begin transaction
        char* err_msg = nullptr;
        if (sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
            LOG_ERROR("Failed to begin transaction: {}", err_msg ? err_msg : "unknown");
            sqlite3_free(err_msg);
            return false;
        }
        
        // Execute migration SQL
        if (sqlite3_exec(db, migration.sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
            LOG_ERROR("Failed to apply migration {}: {}", migration.version, err_msg ? err_msg : "unknown");
            sqlite3_free(err_msg);
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        
        // Record migration
        std::string record_sql = "INSERT INTO schema_version (version, name) VALUES (" +
                                  std::to_string(migration.version) + ", '" + migration.name + "')";
        if (sqlite3_exec(db, record_sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
            LOG_ERROR("Failed to record migration: {}", err_msg ? err_msg : "unknown");
            sqlite3_free(err_msg);
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        
        // Commit transaction
        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
            LOG_ERROR("Failed to commit migration: {}", err_msg ? err_msg : "unknown");
            sqlite3_free(err_msg);
            return false;
        }
        
        LOG_INFO("Migration {} applied successfully", migration.version);
    }
    
    return true;
}

} // namespace edgelink::controller
