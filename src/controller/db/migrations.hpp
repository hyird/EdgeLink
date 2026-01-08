#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <functional>

namespace edgelink::controller {

// Migration definition
struct Migration {
    int version;
    std::string name;
    std::string sql;
};

// Get all migrations
const std::vector<Migration>& get_migrations();

// Run pending migrations
bool run_migrations(sqlite3* db);

// Get current schema version
int get_schema_version(sqlite3* db);

} // namespace edgelink::controller
