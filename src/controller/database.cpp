#include "controller/database.hpp"
#include <sqlite3.h>
#include <chrono>
#include <cstring>
#include <spdlog/spdlog.h>

namespace edgelink::controller {

std::string db_error_message(DbError error) {
    switch (error) {
        case DbError::OPEN_FAILED: return "Failed to open database";
        case DbError::QUERY_FAILED: return "Query execution failed";
        case DbError::NOT_FOUND: return "Record not found";
        case DbError::DUPLICATE_KEY: return "Duplicate key";
        case DbError::CONSTRAINT_VIOLATION: return "Constraint violation";
        case DbError::INTERNAL_ERROR: return "Internal database error";
        default: return "Unknown database error";
    }
}

// ============================================================================
// Statement implementation
// ============================================================================

Statement::~Statement() {
    if (stmt_) {
        sqlite3_finalize(stmt_);
    }
}

Statement::Statement(Statement&& other) noexcept : stmt_(other.stmt_) {
    other.stmt_ = nullptr;
}

Statement& Statement::operator=(Statement&& other) noexcept {
    if (this != &other) {
        if (stmt_) sqlite3_finalize(stmt_);
        stmt_ = other.stmt_;
        other.stmt_ = nullptr;
    }
    return *this;
}

bool Statement::bind_int(int index, int value) {
    return sqlite3_bind_int(stmt_, index, value) == SQLITE_OK;
}

bool Statement::bind_int64(int index, int64_t value) {
    return sqlite3_bind_int64(stmt_, index, value) == SQLITE_OK;
}

bool Statement::bind_text(int index, std::string_view text) {
    return sqlite3_bind_text(stmt_, index, text.data(),
                             static_cast<int>(text.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool Statement::bind_blob(int index, std::span<const uint8_t> data) {
    return sqlite3_bind_blob(stmt_, index, data.data(),
                             static_cast<int>(data.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

bool Statement::bind_null(int index) {
    return sqlite3_bind_null(stmt_, index) == SQLITE_OK;
}

int Statement::step() {
    return sqlite3_step(stmt_);
}

void Statement::reset() {
    sqlite3_reset(stmt_);
    sqlite3_clear_bindings(stmt_);
}

int Statement::column_int(int index) {
    return sqlite3_column_int(stmt_, index);
}

int64_t Statement::column_int64(int index) {
    return sqlite3_column_int64(stmt_, index);
}

std::string Statement::column_text(int index) {
    const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt_, index));
    return text ? text : "";
}

std::vector<uint8_t> Statement::column_blob(int index) {
    const void* data = sqlite3_column_blob(stmt_, index);
    int size = sqlite3_column_bytes(stmt_, index);
    if (data && size > 0) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        return std::vector<uint8_t>(bytes, bytes + size);
    }
    return {};
}

bool Statement::column_is_null(int index) {
    return sqlite3_column_type(stmt_, index) == SQLITE_NULL;
}

// ============================================================================
// Database implementation
// ============================================================================

Database::~Database() {
    close();
}

std::expected<void, DbError> Database::open(const std::string& path) {
    // Open with FULLMUTEX for thread-safe access from multiple threads
    int rc = sqlite3_open_v2(path.c_str(), &db_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to open database: {}", sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return std::unexpected(DbError::OPEN_FAILED);
    }

    // Enable WAL mode for better concurrency
    execute("PRAGMA journal_mode=WAL");
    execute("PRAGMA synchronous=NORMAL");
    execute("PRAGMA foreign_keys=ON");
    execute("PRAGMA busy_timeout=5000");

    spdlog::info("Database opened: {}", path);
    return {};
}

void Database::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

std::expected<Statement, DbError> Database::prepare(const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare statement: {}", sqlite3_errmsg(db_));
        return std::unexpected(DbError::QUERY_FAILED);
    }
    return Statement(stmt);
}

std::expected<void, DbError> Database::execute(const std::string& sql) {
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string error = errmsg ? errmsg : "Unknown error";
        sqlite3_free(errmsg);
        spdlog::error("Failed to execute SQL: {}", error);
        return std::unexpected(DbError::QUERY_FAILED);
    }
    return {};
}

std::expected<void, DbError> Database::init_schema() {
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            cidr TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS authkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            network_id INTEGER NOT NULL,
            use_count INTEGER DEFAULT 0,
            max_uses INTEGER DEFAULT -1,
            expires_at INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER NOT NULL,
            machine_key BLOB UNIQUE NOT NULL,
            node_key BLOB NOT NULL,
            virtual_ip INTEGER NOT NULL,
            hostname TEXT NOT NULL,
            os TEXT DEFAULT '',
            arch TEXT DEFAULT '',
            version TEXT DEFAULT '',
            online INTEGER DEFAULT 0,
            last_seen INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (network_id) REFERENCES networks(id)
        );

        CREATE INDEX IF NOT EXISTS idx_nodes_network ON nodes(network_id);
        CREATE INDEX IF NOT EXISTS idx_nodes_virtual_ip ON nodes(network_id, virtual_ip);
        CREATE INDEX IF NOT EXISTS idx_authkeys_network ON authkeys(network_id);
    )";

    auto result = execute(schema);
    if (!result) {
        return result;
    }

    // Create default network if not exists
    auto network = get_network_by_name("default");
    if (!network) {
        auto created = create_network("default", "100.64.0.0/16");
        if (!created) {
            return std::unexpected(created.error());
        }
        spdlog::info("Created default network: {}", created->cidr);

        // Create default authkey for development
        auto authkey = create_authkey("tskey-dev-test123", created->id);
        if (authkey) {
            spdlog::info("Created development authkey: tskey-dev-test123");
        }
    }

    return {};
}

uint64_t Database::now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// Network operations
// ============================================================================

std::expected<NetworkRecord, DbError> Database::create_network(
    const std::string& name, const std::string& cidr) {

    auto stmt = prepare("INSERT INTO networks (name, cidr, created_at) VALUES (?, ?, ?)");
    if (!stmt) return std::unexpected(stmt.error());

    uint64_t now = now_ms();
    stmt->bind_text(1, name);
    stmt->bind_text(2, cidr);
    stmt->bind_int64(3, static_cast<int64_t>(now));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    NetworkRecord record;
    record.id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    record.name = name;
    record.cidr = cidr;
    record.created_at = now;

    return record;
}

std::expected<NetworkRecord, DbError> Database::get_network(uint32_t id) {
    auto stmt = prepare("SELECT id, name, cidr, created_at FROM networks WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, static_cast<int>(id));

    if (stmt->step() != SQLITE_ROW) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    NetworkRecord record;
    record.id = static_cast<uint32_t>(stmt->column_int(0));
    record.name = stmt->column_text(1);
    record.cidr = stmt->column_text(2);
    record.created_at = static_cast<uint64_t>(stmt->column_int64(3));

    return record;
}

std::expected<NetworkRecord, DbError> Database::get_network_by_name(const std::string& name) {
    auto stmt = prepare("SELECT id, name, cidr, created_at FROM networks WHERE name = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_text(1, name);

    if (stmt->step() != SQLITE_ROW) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    NetworkRecord record;
    record.id = static_cast<uint32_t>(stmt->column_int(0));
    record.name = stmt->column_text(1);
    record.cidr = stmt->column_text(2);
    record.created_at = static_cast<uint64_t>(stmt->column_int64(3));

    return record;
}

std::expected<std::vector<NetworkRecord>, DbError> Database::list_networks() {
    auto stmt = prepare("SELECT id, name, cidr, created_at FROM networks");
    if (!stmt) return std::unexpected(stmt.error());

    std::vector<NetworkRecord> records;
    while (stmt->step() == SQLITE_ROW) {
        NetworkRecord record;
        record.id = static_cast<uint32_t>(stmt->column_int(0));
        record.name = stmt->column_text(1);
        record.cidr = stmt->column_text(2);
        record.created_at = static_cast<uint64_t>(stmt->column_int64(3));
        records.push_back(record);
    }

    return records;
}

// ============================================================================
// AuthKey operations
// ============================================================================

std::expected<AuthKeyRecord, DbError> Database::create_authkey(
    const std::string& key, uint32_t network_id, int32_t max_uses, uint64_t expires_at) {

    auto stmt = prepare(
        "INSERT INTO authkeys (key, network_id, max_uses, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?)");
    if (!stmt) return std::unexpected(stmt.error());

    uint64_t now = now_ms();
    stmt->bind_text(1, key);
    stmt->bind_int(2, static_cast<int>(network_id));
    stmt->bind_int(3, max_uses);
    stmt->bind_int64(4, static_cast<int64_t>(expires_at));
    stmt->bind_int64(5, static_cast<int64_t>(now));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    AuthKeyRecord record;
    record.id = static_cast<uint32_t>(sqlite3_last_insert_rowid(db_));
    record.key = key;
    record.network_id = network_id;
    record.use_count = 0;
    record.max_uses = max_uses;
    record.expires_at = expires_at;
    record.created_at = now;

    return record;
}

std::expected<AuthKeyRecord, DbError> Database::get_authkey(const std::string& key) {
    auto stmt = prepare(
        "SELECT id, key, network_id, use_count, max_uses, expires_at, created_at "
        "FROM authkeys WHERE key = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_text(1, key);

    if (stmt->step() != SQLITE_ROW) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    AuthKeyRecord record;
    record.id = static_cast<uint32_t>(stmt->column_int(0));
    record.key = stmt->column_text(1);
    record.network_id = static_cast<uint32_t>(stmt->column_int(2));
    record.use_count = stmt->column_int(3);
    record.max_uses = stmt->column_int(4);
    record.expires_at = static_cast<uint64_t>(stmt->column_int64(5));
    record.created_at = static_cast<uint64_t>(stmt->column_int64(6));

    return record;
}

std::expected<void, DbError> Database::increment_authkey_use(const std::string& key) {
    auto stmt = prepare("UPDATE authkeys SET use_count = use_count + 1 WHERE key = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_text(1, key);

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<void, DbError> Database::delete_authkey(const std::string& key) {
    auto stmt = prepare("DELETE FROM authkeys WHERE key = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_text(1, key);

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<std::vector<AuthKeyRecord>, DbError> Database::list_authkeys(uint32_t network_id) {
    std::string sql = "SELECT id, key, network_id, use_count, max_uses, expires_at, created_at FROM authkeys";
    if (network_id != 0) {
        sql += " WHERE network_id = ?";
    }
    sql += " ORDER BY created_at DESC";

    auto stmt = prepare(sql);
    if (!stmt) return std::unexpected(stmt.error());

    if (network_id != 0) {
        stmt->bind_int(1, static_cast<int>(network_id));
    }

    std::vector<AuthKeyRecord> records;
    while (stmt->step() == SQLITE_ROW) {
        AuthKeyRecord record;
        record.id = static_cast<uint32_t>(stmt->column_int(0));
        record.key = stmt->column_text(1);
        record.network_id = static_cast<uint32_t>(stmt->column_int(2));
        record.use_count = stmt->column_int(3);
        record.max_uses = stmt->column_int(4);
        record.expires_at = static_cast<uint64_t>(stmt->column_int64(5));
        record.created_at = static_cast<uint64_t>(stmt->column_int64(6));
        records.push_back(record);
    }

    return records;
}

// ============================================================================
// Node operations
// ============================================================================

std::expected<NodeRecord, DbError> Database::create_node(
    NetworkId network_id,
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key,
    std::span<const uint8_t, X25519_KEY_SIZE> node_key,
    const std::string& hostname,
    const std::string& os,
    const std::string& arch,
    const std::string& version) {

    // Allocate virtual IP first
    auto vip = allocate_virtual_ip(network_id);
    if (!vip) {
        return std::unexpected(vip.error());
    }

    auto stmt = prepare(
        "INSERT INTO nodes (network_id, machine_key, node_key, virtual_ip, "
        "hostname, os, arch, version, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    if (!stmt) return std::unexpected(stmt.error());

    uint64_t now = now_ms();
    stmt->bind_int(1, static_cast<int>(network_id));
    stmt->bind_blob(2, machine_key);
    stmt->bind_blob(3, node_key);
    stmt->bind_int(4, static_cast<int>(vip->to_u32()));
    stmt->bind_text(5, hostname);
    stmt->bind_text(6, os);
    stmt->bind_text(7, arch);
    stmt->bind_text(8, version);
    stmt->bind_int64(9, static_cast<int64_t>(now));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    NodeRecord record;
    record.id = static_cast<NodeId>(sqlite3_last_insert_rowid(db_));
    record.network_id = network_id;
    std::copy(machine_key.begin(), machine_key.end(), record.machine_key.begin());
    std::copy(node_key.begin(), node_key.end(), record.node_key.begin());
    record.virtual_ip = *vip;
    record.hostname = hostname;
    record.os = os;
    record.arch = arch;
    record.version = version;
    record.online = false;
    record.last_seen = 0;
    record.created_at = now;

    return record;
}

std::expected<NodeRecord, DbError> Database::get_node(NodeId id) {
    auto stmt = prepare(
        "SELECT id, network_id, machine_key, node_key, virtual_ip, "
        "hostname, os, arch, version, online, last_seen, created_at "
        "FROM nodes WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, static_cast<int>(id));

    if (stmt->step() != SQLITE_ROW) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    NodeRecord record;
    record.id = static_cast<NodeId>(stmt->column_int(0));
    record.network_id = static_cast<NetworkId>(stmt->column_int(1));

    auto mk = stmt->column_blob(2);
    auto nk = stmt->column_blob(3);
    if (mk.size() == ED25519_PUBLIC_KEY_SIZE) {
        std::copy(mk.begin(), mk.end(), record.machine_key.begin());
    }
    if (nk.size() == X25519_KEY_SIZE) {
        std::copy(nk.begin(), nk.end(), record.node_key.begin());
    }

    record.virtual_ip = IPv4Address::from_u32(static_cast<uint32_t>(stmt->column_int(4)));
    record.hostname = stmt->column_text(5);
    record.os = stmt->column_text(6);
    record.arch = stmt->column_text(7);
    record.version = stmt->column_text(8);
    record.online = stmt->column_int(9) != 0;
    record.last_seen = static_cast<uint64_t>(stmt->column_int64(10));
    record.created_at = static_cast<uint64_t>(stmt->column_int64(11));

    return record;
}

std::expected<NodeRecord, DbError> Database::get_node_by_machine_key(
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key) {

    auto stmt = prepare(
        "SELECT id, network_id, machine_key, node_key, virtual_ip, "
        "hostname, os, arch, version, online, last_seen, created_at "
        "FROM nodes WHERE machine_key = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_blob(1, machine_key);

    if (stmt->step() != SQLITE_ROW) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    NodeRecord record;
    record.id = static_cast<NodeId>(stmt->column_int(0));
    record.network_id = static_cast<NetworkId>(stmt->column_int(1));

    auto mk = stmt->column_blob(2);
    auto nk = stmt->column_blob(3);
    if (mk.size() == ED25519_PUBLIC_KEY_SIZE) {
        std::copy(mk.begin(), mk.end(), record.machine_key.begin());
    }
    if (nk.size() == X25519_KEY_SIZE) {
        std::copy(nk.begin(), nk.end(), record.node_key.begin());
    }

    record.virtual_ip = IPv4Address::from_u32(static_cast<uint32_t>(stmt->column_int(4)));
    record.hostname = stmt->column_text(5);
    record.os = stmt->column_text(6);
    record.arch = stmt->column_text(7);
    record.version = stmt->column_text(8);
    record.online = stmt->column_int(9) != 0;
    record.last_seen = static_cast<uint64_t>(stmt->column_int64(10));
    record.created_at = static_cast<uint64_t>(stmt->column_int64(11));

    return record;
}

std::expected<std::vector<NodeRecord>, DbError> Database::get_nodes_by_network(NetworkId network_id) {
    auto stmt = prepare(
        "SELECT id, network_id, machine_key, node_key, virtual_ip, "
        "hostname, os, arch, version, online, last_seen, created_at "
        "FROM nodes WHERE network_id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, static_cast<int>(network_id));

    std::vector<NodeRecord> records;
    while (stmt->step() == SQLITE_ROW) {
        NodeRecord record;
        record.id = static_cast<NodeId>(stmt->column_int(0));
        record.network_id = static_cast<NetworkId>(stmt->column_int(1));

        auto mk = stmt->column_blob(2);
        auto nk = stmt->column_blob(3);
        if (mk.size() == ED25519_PUBLIC_KEY_SIZE) {
            std::copy(mk.begin(), mk.end(), record.machine_key.begin());
        }
        if (nk.size() == X25519_KEY_SIZE) {
            std::copy(nk.begin(), nk.end(), record.node_key.begin());
        }

        record.virtual_ip = IPv4Address::from_u32(static_cast<uint32_t>(stmt->column_int(4)));
        record.hostname = stmt->column_text(5);
        record.os = stmt->column_text(6);
        record.arch = stmt->column_text(7);
        record.version = stmt->column_text(8);
        record.online = stmt->column_int(9) != 0;
        record.last_seen = static_cast<uint64_t>(stmt->column_int64(10));
        record.created_at = static_cast<uint64_t>(stmt->column_int64(11));

        records.push_back(record);
    }

    return records;
}

std::expected<std::vector<NodeRecord>, DbError> Database::list_all_nodes() {
    auto stmt = prepare(
        "SELECT id, network_id, machine_key, node_key, virtual_ip, "
        "hostname, os, arch, version, online, last_seen, created_at "
        "FROM nodes ORDER BY id");
    if (!stmt) return std::unexpected(stmt.error());

    std::vector<NodeRecord> records;
    while (stmt->step() == SQLITE_ROW) {
        NodeRecord record;
        record.id = static_cast<NodeId>(stmt->column_int(0));
        record.network_id = static_cast<NetworkId>(stmt->column_int(1));

        auto mk = stmt->column_blob(2);
        auto nk = stmt->column_blob(3);
        if (mk.size() == ED25519_PUBLIC_KEY_SIZE) {
            std::copy(mk.begin(), mk.end(), record.machine_key.begin());
        }
        if (nk.size() == X25519_KEY_SIZE) {
            std::copy(nk.begin(), nk.end(), record.node_key.begin());
        }

        record.virtual_ip = IPv4Address::from_u32(static_cast<uint32_t>(stmt->column_int(4)));
        record.hostname = stmt->column_text(5);
        record.os = stmt->column_text(6);
        record.arch = stmt->column_text(7);
        record.version = stmt->column_text(8);
        record.online = stmt->column_int(9) != 0;
        record.last_seen = static_cast<uint64_t>(stmt->column_int64(10));
        record.created_at = static_cast<uint64_t>(stmt->column_int64(11));

        records.push_back(record);
    }

    return records;
}

std::expected<void, DbError> Database::delete_node(NodeId id) {
    auto stmt = prepare("DELETE FROM nodes WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, static_cast<int>(id));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    if (sqlite3_changes(db_) == 0) {
        return std::unexpected(DbError::NOT_FOUND);
    }

    return {};
}

std::expected<void, DbError> Database::update_node_key(
    NodeId id, std::span<const uint8_t, X25519_KEY_SIZE> node_key) {

    auto stmt = prepare("UPDATE nodes SET node_key = ? WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_blob(1, node_key);
    stmt->bind_int(2, static_cast<int>(id));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<void, DbError> Database::update_node_online(NodeId id, bool online) {
    auto stmt = prepare("UPDATE nodes SET online = ?, last_seen = ? WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, online ? 1 : 0);
    stmt->bind_int64(2, static_cast<int64_t>(now_ms()));
    stmt->bind_int(3, static_cast<int>(id));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<void, DbError> Database::update_node_last_seen(NodeId id, uint64_t timestamp) {
    auto stmt = prepare("UPDATE nodes SET last_seen = ? WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int64(1, static_cast<int64_t>(timestamp));
    stmt->bind_int(2, static_cast<int>(id));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<void, DbError> Database::update_node_info(
    NodeId id, const std::string& hostname,
    const std::string& os, const std::string& arch, const std::string& version) {

    auto stmt = prepare(
        "UPDATE nodes SET hostname = ?, os = ?, arch = ?, version = ? WHERE id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_text(1, hostname);
    stmt->bind_text(2, os);
    stmt->bind_text(3, arch);
    stmt->bind_text(4, version);
    stmt->bind_int(5, static_cast<int>(id));

    if (stmt->step() != SQLITE_DONE) {
        return std::unexpected(DbError::QUERY_FAILED);
    }

    return {};
}

std::expected<NodeRecord, DbError> Database::find_or_create_node(
    NetworkId network_id,
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key,
    std::span<const uint8_t, X25519_KEY_SIZE> node_key,
    const std::string& hostname,
    const std::string& os,
    const std::string& arch,
    const std::string& version) {

    // Try to find existing node
    auto existing = get_node_by_machine_key(machine_key);
    if (existing) {
        // Update node_key if changed
        if (existing->node_key != std::array<uint8_t, X25519_KEY_SIZE>{}) {
            std::array<uint8_t, X25519_KEY_SIZE> new_key;
            std::copy(node_key.begin(), node_key.end(), new_key.begin());
            if (existing->node_key != new_key) {
                update_node_key(existing->id, node_key);
                std::copy(node_key.begin(), node_key.end(), existing->node_key.begin());
            }
        }

        // Update node info
        update_node_info(existing->id, hostname, os, arch, version);
        existing->hostname = hostname;
        existing->os = os;
        existing->arch = arch;
        existing->version = version;

        return existing;
    }

    // Create new node
    return create_node(network_id, machine_key, node_key, hostname, os, arch, version);
}

std::expected<IPv4Address, DbError> Database::allocate_virtual_ip(NetworkId network_id) {
    // Get network CIDR
    auto network = get_network(network_id);
    if (!network) {
        return std::unexpected(network.error());
    }

    // Parse CIDR (e.g., "10.0.0.0/8")
    auto slash_pos = network->cidr.find('/');
    if (slash_pos == std::string::npos) {
        return std::unexpected(DbError::INTERNAL_ERROR);
    }

    auto base_ip = IPv4Address::from_string(network->cidr.substr(0, slash_pos));
    int prefix_len = std::stoi(network->cidr.substr(slash_pos + 1));

    uint32_t base = base_ip.to_u32();
    uint32_t mask = prefix_len == 0 ? 0 : (0xFFFFFFFF << (32 - prefix_len));
    uint32_t network_addr = base & mask;
    uint32_t broadcast = network_addr | ~mask;

    // Find maximum used IP in this network
    auto stmt = prepare(
        "SELECT MAX(virtual_ip) FROM nodes WHERE network_id = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind_int(1, static_cast<int>(network_id));

    uint32_t next_ip;
    if (stmt->step() == SQLITE_ROW && !stmt->column_is_null(0)) {
        uint32_t max_ip = static_cast<uint32_t>(stmt->column_int(0));
        next_ip = max_ip + 1;
    } else {
        // First node, start from network + 1 (skip network address)
        next_ip = network_addr + 1;
    }

    // Check if we've exhausted the address space
    if (next_ip >= broadcast) {
        return std::unexpected(DbError::INTERNAL_ERROR);
    }

    return IPv4Address::from_u32(next_ip);
}

} // namespace edgelink::controller
