#include "client/peer_routing_table.hpp"
#include "common/log.hpp"
#include <chrono>

namespace edgelink::client {

namespace {
spdlog::logger& log() {
    static auto logger = edgelink::create_logger("peer_routing");
    return *logger;
}
} // anonymous namespace

void PeerRoutingTable::update(const PeerRoutingUpdate& update) {
    std::unique_lock lock(mutex_);

    // 只接受更新版本
    if (update.version <= version_) {
        log().debug("Ignoring outdated routing update: {} <= {}",
                    update.version, version_);
        return;
    }

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    for (const auto& entry : update.routes) {
        PeerRoute route;
        route.peer_node_id = entry.peer_node_id;
        route.relay_id = entry.relay_id;
        route.connection_id = entry.connection_id;
        route.priority = entry.priority;
        route.update_time = now;

        routes_[entry.peer_node_id] = route;

        log().debug("Updated route: peer={} -> relay={}, conn=0x{:08x}, priority={}",
                    entry.peer_node_id, entry.relay_id,
                    entry.connection_id, entry.priority);
    }

    version_ = update.version;
    log().info("Routing table updated to version {}, {} routes",
               version_, routes_.size());
}

std::optional<PeerRoute> PeerRoutingTable::get_route(NodeId peer_id) const {
    std::shared_lock lock(mutex_);
    auto it = routes_.find(peer_id);
    if (it != routes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<PeerRoute> PeerRoutingTable::all_routes() const {
    std::vector<PeerRoute> result;
    std::shared_lock lock(mutex_);
    result.reserve(routes_.size());
    for (const auto& [id, route] : routes_) {
        result.push_back(route);
    }
    return result;
}

void PeerRoutingTable::set_route(const PeerRoute& route) {
    std::unique_lock lock(mutex_);
    routes_[route.peer_node_id] = route;
    log().debug("Set local route: peer={} -> relay={}, conn=0x{:08x}",
                route.peer_node_id, route.relay_id, route.connection_id);
}

void PeerRoutingTable::remove_route(NodeId peer_id) {
    std::unique_lock lock(mutex_);
    routes_.erase(peer_id);
    log().debug("Removed route for peer {}", peer_id);
}

void PeerRoutingTable::clear() {
    std::unique_lock lock(mutex_);
    routes_.clear();
    version_ = 0;
    log().debug("Cleared routing table");
}

size_t PeerRoutingTable::size() const {
    std::shared_lock lock(mutex_);
    return routes_.size();
}

bool PeerRoutingTable::has_route(NodeId peer_id) const {
    std::shared_lock lock(mutex_);
    return routes_.find(peer_id) != routes_.end();
}

std::vector<NodeId> PeerRoutingTable::get_peers_via_relay(ServerId relay_id) const {
    std::vector<NodeId> result;
    std::shared_lock lock(mutex_);
    for (const auto& [id, route] : routes_) {
        if (route.relay_id == relay_id) {
            result.push_back(id);
        }
    }
    return result;
}

} // namespace edgelink::client
