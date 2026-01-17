#pragma once

// Proto Conversion Helpers
//
// This file provides conversion functions between C++ types (edgelink::)
// and Protobuf types (edgelink::pb::).
//
// Usage:
//   #include "common/proto_convert.hpp"
//   #include "edgelink.pb.h"
//
//   // Convert C++ to Protobuf
//   edgelink::IPv4Address cpp_ip = ...;
//   edgelink::pb::IPv4Address pb_ip;
//   to_proto(cpp_ip, &pb_ip);
//
//   // Convert Protobuf to C++
//   edgelink::IPv4Address cpp_ip2;
//   from_proto(pb_ip, &cpp_ip2);

#include "common/types.hpp"
#include "common/message.hpp"  // For Config, ConfigUpdate, ConfigAck
#include <string>
#include <vector>
#include <cstring>

// Include protobuf types (required for inline function implementations)
#include "edgelink.pb.h"

namespace edgelink {

// ============================================================================
// IPv4Address Conversion
// ============================================================================

inline void to_proto(const IPv4Address& src, pb::IPv4Address* dst) {
    dst->set_addr(src.to_u32());
}

inline void from_proto(const pb::IPv4Address& src, IPv4Address* dst) {
    *dst = IPv4Address::from_u32(src.addr());
}

// ============================================================================
// Endpoint Conversion
// ============================================================================

inline void to_proto(const Endpoint& src, pb::Endpoint* dst) {
    dst->set_type(static_cast<pb::EndpointType>(src.type));
    dst->set_ip_type(src.ip_type == IpType::IPv4 ? pb::IP_TYPE_V4 : pb::IP_TYPE_V6);

    size_t addr_len = (src.ip_type == IpType::IPv4) ? 4 : 16;
    dst->set_address(src.address.data(), addr_len);

    dst->set_port(src.port);
    dst->set_priority(src.priority);
}

inline void from_proto(const pb::Endpoint& src, Endpoint* dst) {
    dst->type = static_cast<EndpointType>(src.type());
    dst->ip_type = (src.ip_type() == pb::IP_TYPE_V6) ? IpType::IPv6 : IpType::IPv4;

    dst->address.fill(0);
    size_t copy_len = std::min(src.address().size(), dst->address.size());
    std::memcpy(dst->address.data(), src.address().data(), copy_len);

    dst->port = static_cast<uint16_t>(src.port());
    dst->priority = static_cast<uint8_t>(src.priority());
}

// ============================================================================
// SubnetInfo Conversion
// ============================================================================

inline void to_proto(const SubnetInfo& src, pb::SubnetInfo* dst) {
    dst->set_ip_type(src.ip_type == IpType::IPv4 ? pb::IP_TYPE_V4 : pb::IP_TYPE_V6);

    size_t prefix_len = (src.ip_type == IpType::IPv4) ? 4 : 16;
    dst->set_prefix(src.prefix.data(), prefix_len);

    dst->set_prefix_len(src.prefix_len);
}

inline void from_proto(const pb::SubnetInfo& src, SubnetInfo* dst) {
    dst->ip_type = (src.ip_type() == pb::IP_TYPE_V6) ? IpType::IPv6 : IpType::IPv4;

    dst->prefix.fill(0);
    size_t copy_len = std::min(src.prefix().size(), dst->prefix.size());
    std::memcpy(dst->prefix.data(), src.prefix().data(), copy_len);

    dst->prefix_len = static_cast<uint8_t>(src.prefix_len());
}

// ============================================================================
// RouteInfo Conversion
// ============================================================================

inline void to_proto(const RouteInfo& src, pb::RouteInfo* dst) {
    dst->set_ip_type(src.ip_type == IpType::IPv4 ? pb::IP_TYPE_V4 : pb::IP_TYPE_V6);

    size_t prefix_len = (src.ip_type == IpType::IPv4) ? 4 : 16;
    dst->set_prefix(src.prefix.data(), prefix_len);

    dst->set_prefix_len(src.prefix_len);
    dst->set_gateway_node(src.gateway_node);
    dst->set_metric(src.metric);
    dst->set_flags(static_cast<uint32_t>(src.flags));
}

inline void from_proto(const pb::RouteInfo& src, RouteInfo* dst) {
    dst->ip_type = (src.ip_type() == pb::IP_TYPE_V6) ? IpType::IPv6 : IpType::IPv4;

    dst->prefix.fill(0);
    size_t copy_len = std::min(src.prefix().size(), dst->prefix.size());
    std::memcpy(dst->prefix.data(), src.prefix().data(), copy_len);

    dst->prefix_len = static_cast<uint8_t>(src.prefix_len());
    dst->gateway_node = src.gateway_node();
    dst->metric = static_cast<uint16_t>(src.metric());
    dst->flags = static_cast<RouteFlags>(src.flags());
}

// ============================================================================
// PeerInfo Conversion
// ============================================================================

inline void to_proto(const PeerInfo& src, pb::PeerInfo* dst) {
    dst->set_node_id(src.node_id);

    pb::IPv4Address* vip = dst->mutable_virtual_ip();
    to_proto(src.virtual_ip, vip);

    dst->set_node_key(src.node_key.data(), src.node_key.size());
    dst->set_online(src.online);
    dst->set_exit_node(src.exit_node);
    dst->set_name(src.name);

    for (const auto& ep : src.endpoints) {
        to_proto(ep, dst->add_endpoints());
    }

    for (const auto& subnet : src.allowed_subnets) {
        to_proto(subnet, dst->add_allowed_subnets());
    }
}

inline void from_proto(const pb::PeerInfo& src, PeerInfo* dst) {
    dst->node_id = src.node_id();

    from_proto(src.virtual_ip(), &dst->virtual_ip);

    dst->node_key.fill(0);
    size_t key_len = std::min(src.node_key().size(), dst->node_key.size());
    std::memcpy(dst->node_key.data(), src.node_key().data(), key_len);

    dst->online = src.online();
    dst->exit_node = src.exit_node();
    dst->name = src.name();

    dst->endpoints.clear();
    for (const auto& ep : src.endpoints()) {
        Endpoint cpp_ep;
        from_proto(ep, &cpp_ep);
        dst->endpoints.push_back(cpp_ep);
    }

    dst->allowed_subnets.clear();
    for (const auto& subnet : src.allowed_subnets()) {
        SubnetInfo cpp_subnet;
        from_proto(subnet, &cpp_subnet);
        dst->allowed_subnets.push_back(cpp_subnet);
    }
}

// ============================================================================
// RelayInfo Conversion
// ============================================================================

inline void to_proto(const RelayInfo& src, pb::RelayInfo* dst) {
    dst->set_server_id(src.server_id);
    dst->set_hostname(src.hostname);
    dst->set_priority(src.priority);
    dst->set_region(src.region);

    for (const auto& ep : src.endpoints) {
        to_proto(ep, dst->add_endpoints());
    }
}

inline void from_proto(const pb::RelayInfo& src, RelayInfo* dst) {
    dst->server_id = src.server_id();
    dst->hostname = src.hostname();
    dst->priority = static_cast<uint16_t>(src.priority());
    dst->region = src.region();

    dst->endpoints.clear();
    for (const auto& ep : src.endpoints()) {
        Endpoint cpp_ep;
        from_proto(ep, &cpp_ep);
        dst->endpoints.push_back(cpp_ep);
    }
}

// ============================================================================
// StunInfo Conversion
// ============================================================================

inline void to_proto(const StunInfo& src, pb::StunInfo* dst) {
    dst->set_hostname(src.hostname);
    dst->set_port(src.port);
}

inline void from_proto(const pb::StunInfo& src, StunInfo* dst) {
    dst->hostname = src.hostname();
    dst->port = static_cast<uint16_t>(src.port());
}

// ============================================================================
// LatencyEntry Conversion
// ============================================================================

inline void to_proto(const LatencyEntry& src, pb::LatencyEntry* dst) {
    dst->set_server_id(src.server_id);
    dst->set_latency_ms(src.latency_ms);
    dst->set_jitter_ms(src.jitter_ms);
    dst->set_packet_loss(src.packet_loss);
}

inline void from_proto(const pb::LatencyEntry& src, LatencyEntry* dst) {
    dst->server_id = src.server_id();
    dst->latency_ms = static_cast<uint16_t>(src.latency_ms());
    dst->jitter_ms = static_cast<uint16_t>(src.jitter_ms());
    dst->packet_loss = static_cast<uint8_t>(src.packet_loss());
}

// ============================================================================
// Vector/Repeated Field Helpers
// ============================================================================

template<typename CppT, typename PbT, typename PbRepeated>
inline void to_proto_repeated(const std::vector<CppT>& src, PbRepeated* dst) {
    for (const auto& item : src) {
        to_proto(item, dst->Add());
    }
}

template<typename CppT, typename PbT, typename PbRepeated>
inline void from_proto_repeated(const PbRepeated& src, std::vector<CppT>* dst) {
    dst->clear();
    dst->reserve(src.size());
    for (const auto& item : src) {
        CppT cpp_item;
        from_proto(item, &cpp_item);
        dst->push_back(std::move(cpp_item));
    }
}

// ============================================================================
// ConfigAckStatus Conversion
// ============================================================================

inline pb::ConfigAckStatus to_proto_config_ack_status(ConfigAckStatus status) {
    switch (status) {
        case ConfigAckStatus::SUCCESS:
            return pb::CONFIG_ACK_STATUS_SUCCESS;
        case ConfigAckStatus::PARTIAL_FAILURE:
            return pb::CONFIG_ACK_STATUS_PARTIAL_FAILURE;
        case ConfigAckStatus::TOTAL_FAILURE:
            return pb::CONFIG_ACK_STATUS_TOTAL_FAILURE;
        default:
            return pb::CONFIG_ACK_STATUS_SUCCESS;
    }
}

inline ConfigAckStatus from_proto_config_ack_status(pb::ConfigAckStatus status) {
    switch (status) {
        case pb::CONFIG_ACK_STATUS_SUCCESS:
            return ConfigAckStatus::SUCCESS;
        case pb::CONFIG_ACK_STATUS_PARTIAL_FAILURE:
            return ConfigAckStatus::PARTIAL_FAILURE;
        case pb::CONFIG_ACK_STATUS_TOTAL_FAILURE:
            return ConfigAckStatus::TOTAL_FAILURE;
        default:
            return ConfigAckStatus::SUCCESS;
    }
}

// ============================================================================
// ConfigErrorItemType Conversion
// ============================================================================

inline pb::ConfigErrorItemType to_proto_config_error_item_type(ConfigErrorItemType type) {
    switch (type) {
        case ConfigErrorItemType::RELAY:
            return pb::CONFIG_ERROR_ITEM_TYPE_RELAY;
        case ConfigErrorItemType::PEER:
            return pb::CONFIG_ERROR_ITEM_TYPE_PEER;
        case ConfigErrorItemType::ROUTE:
            return pb::CONFIG_ERROR_ITEM_TYPE_ROUTE;
        default:
            return pb::CONFIG_ERROR_ITEM_TYPE_UNKNOWN;
    }
}

inline ConfigErrorItemType from_proto_config_error_item_type(pb::ConfigErrorItemType type) {
    switch (type) {
        case pb::CONFIG_ERROR_ITEM_TYPE_RELAY:
            return ConfigErrorItemType::RELAY;
        case pb::CONFIG_ERROR_ITEM_TYPE_PEER:
            return ConfigErrorItemType::PEER;
        case pb::CONFIG_ERROR_ITEM_TYPE_ROUTE:
            return ConfigErrorItemType::ROUTE;
        default:
            return ConfigErrorItemType::RELAY;
    }
}

// ============================================================================
// Config Conversion
// ============================================================================

inline void to_proto(const Config& src, pb::Config* dst) {
    dst->set_version(src.version);
    dst->set_network_id(src.network_id);
    to_proto(src.subnet, dst->mutable_subnet());
    dst->set_subnet_mask(src.subnet_mask);
    dst->set_network_name(src.network_name);

    for (const auto& relay : src.relays) {
        to_proto(relay, dst->add_relays());
    }
    for (const auto& stun : src.stuns) {
        to_proto(stun, dst->add_stuns());
    }
    for (const auto& peer : src.peers) {
        to_proto(peer, dst->add_peers());
    }
    for (const auto& route : src.routes) {
        to_proto(route, dst->add_routes());
    }

    dst->set_relay_token(src.relay_token.data(), src.relay_token.size());
    dst->set_relay_token_expires(src.relay_token_expires);
}

inline void from_proto(const pb::Config& src, Config* dst) {
    dst->version = src.version();
    dst->network_id = src.network_id();
    from_proto(src.subnet(), &dst->subnet);
    dst->subnet_mask = static_cast<uint8_t>(src.subnet_mask());
    dst->network_name = src.network_name();

    dst->relays.clear();
    for (const auto& relay : src.relays()) {
        RelayInfo cpp_relay;
        from_proto(relay, &cpp_relay);
        dst->relays.push_back(std::move(cpp_relay));
    }

    dst->stuns.clear();
    for (const auto& stun : src.stuns()) {
        StunInfo cpp_stun;
        from_proto(stun, &cpp_stun);
        dst->stuns.push_back(std::move(cpp_stun));
    }

    dst->peers.clear();
    for (const auto& peer : src.peers()) {
        PeerInfo cpp_peer;
        from_proto(peer, &cpp_peer);
        dst->peers.push_back(std::move(cpp_peer));
    }

    dst->routes.clear();
    for (const auto& route : src.routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->routes.push_back(std::move(cpp_route));
    }

    const auto& token = src.relay_token();
    dst->relay_token.assign(token.begin(), token.end());
    dst->relay_token_expires = src.relay_token_expires();
}

// ============================================================================
// ConfigUpdate Conversion
// ============================================================================

inline void to_proto(const ConfigUpdate& src, pb::ConfigUpdate* dst) {
    dst->set_version(src.version);
    dst->set_update_flags(static_cast<uint32_t>(src.update_flags));

    for (const auto& relay : src.add_relays) {
        to_proto(relay, dst->add_add_relays());
    }
    for (const auto& id : src.del_relay_ids) {
        dst->add_del_relay_ids(id);
    }
    for (const auto& peer : src.add_peers) {
        to_proto(peer, dst->add_add_peers());
    }
    for (const auto& id : src.del_peer_ids) {
        dst->add_del_peer_ids(id);
    }
    for (const auto& route : src.add_routes) {
        to_proto(route, dst->add_add_routes());
    }
    for (const auto& route : src.del_routes) {
        to_proto(route, dst->add_del_routes());
    }

    dst->set_relay_token(src.relay_token.data(), src.relay_token.size());
    dst->set_relay_token_expires(src.relay_token_expires);
}

inline void from_proto(const pb::ConfigUpdate& src, ConfigUpdate* dst) {
    dst->version = src.version();
    dst->update_flags = static_cast<ConfigUpdateFlags>(src.update_flags());

    dst->add_relays.clear();
    for (const auto& relay : src.add_relays()) {
        RelayInfo cpp_relay;
        from_proto(relay, &cpp_relay);
        dst->add_relays.push_back(std::move(cpp_relay));
    }

    dst->del_relay_ids.clear();
    for (const auto& id : src.del_relay_ids()) {
        dst->del_relay_ids.push_back(id);
    }

    dst->add_peers.clear();
    for (const auto& peer : src.add_peers()) {
        PeerInfo cpp_peer;
        from_proto(peer, &cpp_peer);
        dst->add_peers.push_back(std::move(cpp_peer));
    }

    dst->del_peer_ids.clear();
    for (const auto& id : src.del_peer_ids()) {
        dst->del_peer_ids.push_back(id);
    }

    dst->add_routes.clear();
    for (const auto& route : src.add_routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->add_routes.push_back(std::move(cpp_route));
    }

    dst->del_routes.clear();
    for (const auto& route : src.del_routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->del_routes.push_back(std::move(cpp_route));
    }

    const auto& token = src.relay_token();
    dst->relay_token.assign(token.begin(), token.end());
    dst->relay_token_expires = src.relay_token_expires();
}

// ============================================================================
// ConfigAck Conversion
// ============================================================================

inline void to_proto(const ConfigAck& src, pb::ConfigAck* dst) {
    dst->set_version(src.version);
    dst->set_status(to_proto_config_ack_status(src.status));

    for (const auto& err : src.error_items) {
        auto* pb_err = dst->add_errors();
        pb_err->set_item_type(to_proto_config_error_item_type(err.item_type));
        pb_err->set_item_id(err.item_id);
        pb_err->set_error_code(err.error_code);
    }
}

inline void from_proto(const pb::ConfigAck& src, ConfigAck* dst) {
    dst->version = src.version();
    dst->status = from_proto_config_ack_status(src.status());

    dst->error_items.clear();
    for (const auto& err : src.errors()) {
        ConfigAck::ErrorItem cpp_err;
        cpp_err.item_type = from_proto_config_error_item_type(err.item_type());
        cpp_err.item_id = err.item_id();
        cpp_err.error_code = static_cast<uint16_t>(err.error_code());
        dst->error_items.push_back(cpp_err);
    }
}

// ============================================================================
// DataPayload Conversion
// ============================================================================

inline void to_proto(const DataPayload& src, pb::DataPayload* dst) {
    dst->set_src_node(src.src_node);
    dst->set_dst_node(src.dst_node);
    dst->set_nonce(src.nonce.data(), src.nonce.size());
    dst->set_encrypted_payload(src.encrypted_payload.data(), src.encrypted_payload.size());
}

inline void from_proto(const pb::DataPayload& src, DataPayload* dst) {
    dst->src_node = src.src_node();
    dst->dst_node = src.dst_node();

    dst->nonce.fill(0);
    const auto& nonce = src.nonce();
    size_t nonce_len = std::min(nonce.size(), dst->nonce.size());
    std::memcpy(dst->nonce.data(), nonce.data(), nonce_len);

    const auto& payload = src.encrypted_payload();
    dst->encrypted_payload.assign(payload.begin(), payload.end());
}

// ============================================================================
// DataAck Conversion
// ============================================================================

inline pb::DataAckFlags to_proto_data_ack_flags(DataAckFlags flags) {
    // DataAckFlags is a bitmask, just cast directly
    return static_cast<pb::DataAckFlags>(static_cast<uint8_t>(flags));
}

inline DataAckFlags from_proto_data_ack_flags(uint32_t flags) {
    return static_cast<DataAckFlags>(flags);
}

inline void to_proto(const DataAck& src, pb::DataAck* dst) {
    dst->set_src_node(src.src_node);
    dst->set_dst_node(src.dst_node);
    dst->set_ack_nonce(src.ack_nonce.data(), src.ack_nonce.size());
    dst->set_ack_flags(static_cast<uint32_t>(src.ack_flags));
}

inline void from_proto(const pb::DataAck& src, DataAck* dst) {
    dst->src_node = src.src_node();
    dst->dst_node = src.dst_node();

    dst->ack_nonce.fill(0);
    const auto& nonce = src.ack_nonce();
    size_t nonce_len = std::min(nonce.size(), dst->ack_nonce.size());
    std::memcpy(dst->ack_nonce.data(), nonce.data(), nonce_len);

    dst->ack_flags = from_proto_data_ack_flags(src.ack_flags());
}

// ============================================================================
// RelayAuth Conversion
// ============================================================================

inline void to_proto(const RelayAuth& src, pb::RelayAuth* dst) {
    dst->set_relay_token(src.relay_token.data(), src.relay_token.size());
    dst->set_node_id(src.node_id);
    dst->set_node_key(src.node_key.data(), src.node_key.size());
    dst->set_connection_id(src.connection_id);
}

inline void from_proto(const pb::RelayAuth& src, RelayAuth* dst) {
    const auto& token = src.relay_token();
    dst->relay_token.assign(token.begin(), token.end());
    dst->node_id = src.node_id();

    dst->node_key.fill(0);
    const auto& key = src.node_key();
    size_t key_len = std::min(key.size(), dst->node_key.size());
    std::memcpy(dst->node_key.data(), key.data(), key_len);

    dst->connection_id = src.connection_id();
}

// ============================================================================
// RelayAuthResp Conversion
// ============================================================================

inline void to_proto(const RelayAuthResp& src, pb::RelayAuthResp* dst) {
    dst->set_success(src.success);
    dst->set_error_code(src.error_code);
    dst->set_error_msg(src.error_msg);
}

inline void from_proto(const pb::RelayAuthResp& src, RelayAuthResp* dst) {
    dst->success = src.success();
    dst->error_code = static_cast<uint16_t>(src.error_code());
    dst->error_msg = src.error_msg();
}

// ============================================================================
// P2PInit Conversion
// ============================================================================

inline void to_proto(const P2PInit& src, pb::P2PInit* dst) {
    dst->set_target_node(src.target_node);
    dst->set_init_seq(src.init_seq);
}

inline void from_proto(const pb::P2PInit& src, P2PInit* dst) {
    dst->target_node = src.target_node();
    dst->init_seq = src.init_seq();
}

// ============================================================================
// P2PEndpointMsg Conversion (C++ P2PEndpointMsg <-> proto P2PEndpoint)
// ============================================================================

inline void to_proto(const P2PEndpointMsg& src, pb::P2PEndpoint* dst) {
    dst->set_init_seq(src.init_seq);
    dst->set_peer_node(src.peer_node);
    dst->set_peer_key(src.peer_key.data(), src.peer_key.size());
    for (const auto& ep : src.endpoints) {
        to_proto(ep, dst->add_endpoints());
    }
}

inline void from_proto(const pb::P2PEndpoint& src, P2PEndpointMsg* dst) {
    dst->init_seq = src.init_seq();
    dst->peer_node = src.peer_node();

    dst->peer_key.fill(0);
    const auto& key = src.peer_key();
    size_t key_len = std::min(key.size(), dst->peer_key.size());
    std::memcpy(dst->peer_key.data(), key.data(), key_len);

    dst->endpoints.clear();
    for (const auto& ep : src.endpoints()) {
        Endpoint cpp_ep;
        from_proto(ep, &cpp_ep);
        dst->endpoints.push_back(std::move(cpp_ep));
    }
}

// ============================================================================
// P2PPing Conversion
// ============================================================================

inline void to_proto(const P2PPing& src, pb::P2PPing* dst) {
    dst->set_magic(src.magic);
    dst->set_src_node(src.src_node);
    dst->set_dst_node(src.dst_node);
    dst->set_timestamp(src.timestamp);
    dst->set_seq_num(src.seq_num);
    dst->set_nonce(src.nonce.data(), src.nonce.size());
    dst->set_signature(src.signature.data(), src.signature.size());
}

inline void from_proto(const pb::P2PPing& src, P2PPing* dst) {
    dst->magic = src.magic();
    dst->src_node = src.src_node();
    dst->dst_node = src.dst_node();
    dst->timestamp = src.timestamp();
    dst->seq_num = src.seq_num();

    dst->nonce.fill(0);
    const auto& nonce = src.nonce();
    size_t nonce_len = std::min(nonce.size(), dst->nonce.size());
    std::memcpy(dst->nonce.data(), nonce.data(), nonce_len);

    dst->signature.fill(0);
    const auto& sig = src.signature();
    size_t sig_len = std::min(sig.size(), dst->signature.size());
    std::memcpy(dst->signature.data(), sig.data(), sig_len);
}

// P2PPong uses the same structure as P2PPing
inline void to_proto_pong(const P2PPing& src, pb::P2PPong* dst) {
    dst->set_magic(src.magic);
    dst->set_src_node(src.src_node);
    dst->set_dst_node(src.dst_node);
    dst->set_timestamp(src.timestamp);
    dst->set_seq_num(src.seq_num);
    dst->set_nonce(src.nonce.data(), src.nonce.size());
    dst->set_signature(src.signature.data(), src.signature.size());
}

inline void from_proto_pong(const pb::P2PPong& src, P2PPing* dst) {
    dst->magic = src.magic();
    dst->src_node = src.src_node();
    dst->dst_node = src.dst_node();
    dst->timestamp = src.timestamp();
    dst->seq_num = src.seq_num();

    dst->nonce.fill(0);
    const auto& nonce = src.nonce();
    size_t nonce_len = std::min(nonce.size(), dst->nonce.size());
    std::memcpy(dst->nonce.data(), nonce.data(), nonce_len);

    dst->signature.fill(0);
    const auto& sig = src.signature();
    size_t sig_len = std::min(sig.size(), dst->signature.size());
    std::memcpy(dst->signature.data(), sig.data(), sig_len);
}

// ============================================================================
// P2PKeepalive Conversion
// ============================================================================

inline void to_proto(const P2PKeepalive& src, pb::P2PKeepalive* dst) {
    dst->set_timestamp(src.timestamp);
    dst->set_seq_num(src.seq_num);
    dst->set_flags(src.flags);
    dst->set_mac(src.mac.data(), src.mac.size());
}

inline void from_proto(const pb::P2PKeepalive& src, P2PKeepalive* dst) {
    dst->timestamp = src.timestamp();
    dst->seq_num = src.seq_num();
    dst->flags = static_cast<uint8_t>(src.flags());

    dst->mac.fill(0);
    const auto& mac = src.mac();
    size_t mac_len = std::min(mac.size(), dst->mac.size());
    std::memcpy(dst->mac.data(), mac.data(), mac_len);
}

// ============================================================================
// P2PStatusMsg Conversion
// ============================================================================

inline pb::P2PStatus to_proto_p2p_status(P2PStatus status) {
    switch (status) {
        case P2PStatus::DISCONNECTED:
            return pb::P2P_STATUS_DISCONNECTED;
        case P2PStatus::P2P:
            return pb::P2P_STATUS_P2P;
        case P2PStatus::RELAY_ONLY:
            return pb::P2P_STATUS_RELAY_ONLY;
        default:
            return pb::P2P_STATUS_DISCONNECTED;
    }
}

inline P2PStatus from_proto_p2p_status(pb::P2PStatus status) {
    switch (status) {
        case pb::P2P_STATUS_DISCONNECTED:
            return P2PStatus::DISCONNECTED;
        case pb::P2P_STATUS_P2P:
            return P2PStatus::P2P;
        case pb::P2P_STATUS_RELAY_ONLY:
            return P2PStatus::RELAY_ONLY;
        default:
            return P2PStatus::DISCONNECTED;
    }
}

inline pb::PathType to_proto_path_type(PathType type) {
    switch (type) {
        case PathType::LAN:
            return pb::PATH_TYPE_LAN;
        case PathType::STUN:
            return pb::PATH_TYPE_STUN;
        case PathType::RELAY:
            return pb::PATH_TYPE_RELAY;
        default:
            return pb::PATH_TYPE_RELAY;
    }
}

inline PathType from_proto_path_type(pb::PathType type) {
    switch (type) {
        case pb::PATH_TYPE_LAN:
            return PathType::LAN;
        case pb::PATH_TYPE_STUN:
            return PathType::STUN;
        case pb::PATH_TYPE_RELAY:
            return PathType::RELAY;
        default:
            return PathType::RELAY;
    }
}

inline void to_proto(const P2PStatusMsg& src, pb::P2PStatusMsg* dst) {
    dst->set_peer_node(src.peer_node);
    dst->set_status(to_proto_p2p_status(src.status));
    dst->set_latency_ms(src.latency_ms);
    dst->set_path_type(to_proto_path_type(src.path_type));
}

inline void from_proto(const pb::P2PStatusMsg& src, P2PStatusMsg* dst) {
    dst->peer_node = src.peer_node();
    dst->status = from_proto_p2p_status(src.status());
    dst->latency_ms = static_cast<uint16_t>(src.latency_ms());
    dst->path_type = from_proto_path_type(src.path_type());
}

// ============================================================================
// ErrorPayload Conversion (C++ ErrorPayload <-> proto FrameError)
// ============================================================================

inline void to_proto(const ErrorPayload& src, pb::FrameError* dst) {
    dst->set_error_code(src.error_code);
    dst->set_request_type(static_cast<uint32_t>(src.request_type));
    dst->set_request_id(src.request_id);
    dst->set_error_msg(src.error_msg);
}

inline void from_proto(const pb::FrameError& src, ErrorPayload* dst) {
    dst->error_code = static_cast<uint16_t>(src.error_code());
    dst->request_type = static_cast<FrameType>(src.request_type());
    dst->request_id = src.request_id();
    dst->error_msg = src.error_msg();
}

// ============================================================================
// GenericAck Conversion
// ============================================================================

inline void to_proto(const GenericAck& src, pb::GenericAck* dst) {
    dst->set_request_type(static_cast<uint32_t>(src.request_type));
    dst->set_request_id(src.request_id);
    dst->set_status(src.status);
}

inline void from_proto(const pb::GenericAck& src, GenericAck* dst) {
    dst->request_type = static_cast<FrameType>(src.request_type());
    dst->request_id = src.request_id();
    dst->status = static_cast<uint8_t>(src.status());
}

// ============================================================================
// LatencyReportEntry Conversion
// ============================================================================

inline void to_proto(const LatencyReportEntry& src, pb::LatencyReportEntry* dst) {
    dst->set_peer_node_id(src.peer_node_id);
    dst->set_latency_ms(src.latency_ms);
    dst->set_path_type(src.path_type);
}

inline void from_proto(const pb::LatencyReportEntry& src, LatencyReportEntry* dst) {
    dst->peer_node_id = src.peer_node_id();
    dst->latency_ms = static_cast<uint16_t>(src.latency_ms());
    dst->path_type = static_cast<uint8_t>(src.path_type());
}

// ============================================================================
// LatencyReport Conversion
// ============================================================================

inline void to_proto(const LatencyReport& src, pb::LatencyReport* dst) {
    dst->set_timestamp(src.timestamp);
    for (const auto& entry : src.entries) {
        to_proto(entry, dst->add_entries());
    }
}

inline void from_proto(const pb::LatencyReport& src, LatencyReport* dst) {
    dst->timestamp = src.timestamp();
    dst->entries.clear();
    for (const auto& entry : src.entries()) {
        LatencyReportEntry cpp_entry;
        from_proto(entry, &cpp_entry);
        dst->entries.push_back(std::move(cpp_entry));
    }
}

// ============================================================================
// ConnectionMetricsEntry Conversion
// ============================================================================

inline void to_proto(const ConnectionMetricsEntry& src, pb::ConnectionMetricsEntry* dst) {
    dst->set_connection_id(src.connection_id);
    dst->set_rtt_ms(src.rtt_ms);
    dst->set_packet_loss(src.packet_loss);
    dst->set_is_active(src.is_active != 0);
}

inline void from_proto(const pb::ConnectionMetricsEntry& src, ConnectionMetricsEntry* dst) {
    dst->connection_id = src.connection_id();
    dst->rtt_ms = static_cast<uint16_t>(src.rtt_ms());
    dst->packet_loss = static_cast<uint8_t>(src.packet_loss());
    dst->is_active = src.is_active() ? 1 : 0;
}

// ============================================================================
// ConnectionMetrics Conversion
// ============================================================================

inline void to_proto(const ConnectionMetrics& src, pb::ConnectionMetrics* dst) {
    dst->set_timestamp(src.timestamp);
    dst->set_channel_type(src.channel_type);
    for (const auto& conn : src.connections) {
        to_proto(conn, dst->add_connections());
    }
}

inline void from_proto(const pb::ConnectionMetrics& src, ConnectionMetrics* dst) {
    dst->timestamp = src.timestamp();
    dst->channel_type = static_cast<uint8_t>(src.channel_type());
    dst->connections.clear();
    for (const auto& conn : src.connections()) {
        ConnectionMetricsEntry cpp_entry;
        from_proto(conn, &cpp_entry);
        dst->connections.push_back(std::move(cpp_entry));
    }
}

// ============================================================================
// PathSelection Conversion
// ============================================================================

inline void to_proto(const PathSelection& src, pb::PathSelection* dst) {
    dst->set_preferred_connection_id(src.preferred_connection_id);
    dst->set_channel_type(src.channel_type);
    dst->set_reason(src.reason);
}

inline void from_proto(const pb::PathSelection& src, PathSelection* dst) {
    dst->preferred_connection_id = src.preferred_connection_id();
    dst->channel_type = static_cast<uint8_t>(src.channel_type());
    dst->reason = src.reason();
}

// ============================================================================
// PeerPathReportEntry Conversion
// ============================================================================

inline void to_proto(const PeerPathReportEntry& src, pb::PeerPathReportEntry* dst) {
    dst->set_peer_node_id(src.peer_node_id);
    dst->set_relay_id(src.relay_id);
    dst->set_connection_id(src.connection_id);
    dst->set_latency_ms(src.latency_ms);
    dst->set_packet_loss(src.packet_loss);
}

inline void from_proto(const pb::PeerPathReportEntry& src, PeerPathReportEntry* dst) {
    dst->peer_node_id = src.peer_node_id();
    dst->relay_id = src.relay_id();
    dst->connection_id = src.connection_id();
    dst->latency_ms = static_cast<uint16_t>(src.latency_ms());
    dst->packet_loss = static_cast<uint8_t>(src.packet_loss());
}

// ============================================================================
// PeerPathReport Conversion
// ============================================================================

inline void to_proto(const PeerPathReport& src, pb::PeerPathReport* dst) {
    dst->set_timestamp(src.timestamp);
    for (const auto& entry : src.entries) {
        to_proto(entry, dst->add_entries());
    }
}

inline void from_proto(const pb::PeerPathReport& src, PeerPathReport* dst) {
    dst->timestamp = src.timestamp();
    dst->entries.clear();
    for (const auto& entry : src.entries()) {
        PeerPathReportEntry cpp_entry;
        from_proto(entry, &cpp_entry);
        dst->entries.push_back(std::move(cpp_entry));
    }
}

// ============================================================================
// PeerRoutingEntry Conversion
// ============================================================================

inline void to_proto(const PeerRoutingEntry& src, pb::PeerRoutingEntry* dst) {
    dst->set_peer_node_id(src.peer_node_id);
    dst->set_relay_id(src.relay_id);
    dst->set_connection_id(src.connection_id);
    dst->set_priority(src.priority);
}

inline void from_proto(const pb::PeerRoutingEntry& src, PeerRoutingEntry* dst) {
    dst->peer_node_id = src.peer_node_id();
    dst->relay_id = src.relay_id();
    dst->connection_id = src.connection_id();
    dst->priority = static_cast<uint8_t>(src.priority());
}

// ============================================================================
// PeerRoutingUpdate Conversion
// ============================================================================

inline void to_proto(const PeerRoutingUpdate& src, pb::PeerRoutingUpdate* dst) {
    dst->set_version(src.version);
    for (const auto& route : src.routes) {
        to_proto(route, dst->add_routes());
    }
}

inline void from_proto(const pb::PeerRoutingUpdate& src, PeerRoutingUpdate* dst) {
    dst->version = src.version();
    dst->routes.clear();
    for (const auto& route : src.routes()) {
        PeerRoutingEntry cpp_entry;
        from_proto(route, &cpp_entry);
        dst->routes.push_back(std::move(cpp_entry));
    }
}

// ============================================================================
// RelayLatencyReportEntry Conversion
// ============================================================================

inline void to_proto(const RelayLatencyReportEntry& src, pb::RelayLatencyReportEntry* dst) {
    dst->set_relay_id(src.relay_id);
    dst->set_connection_id(src.connection_id);
    dst->set_latency_ms(src.latency_ms);
    dst->set_packet_loss(src.packet_loss);
}

inline void from_proto(const pb::RelayLatencyReportEntry& src, RelayLatencyReportEntry* dst) {
    dst->relay_id = src.relay_id();
    dst->connection_id = src.connection_id();
    dst->latency_ms = static_cast<uint16_t>(src.latency_ms());
    dst->packet_loss = static_cast<uint8_t>(src.packet_loss());
}

// ============================================================================
// RelayLatencyReport Conversion
// ============================================================================

inline void to_proto(const RelayLatencyReport& src, pb::RelayLatencyReport* dst) {
    dst->set_timestamp(src.timestamp);
    for (const auto& entry : src.entries) {
        to_proto(entry, dst->add_entries());
    }
}

inline void from_proto(const pb::RelayLatencyReport& src, RelayLatencyReport* dst) {
    dst->timestamp = src.timestamp();
    dst->entries.clear();
    for (const auto& entry : src.entries()) {
        RelayLatencyReportEntry cpp_entry;
        from_proto(entry, &cpp_entry);
        dst->entries.push_back(std::move(cpp_entry));
    }
}

// ============================================================================
// RouteAnnounce Conversion
// ============================================================================

inline void to_proto(const RouteAnnounce& src, pb::RouteAnnounce* dst) {
    dst->set_request_id(src.request_id);
    for (const auto& route : src.routes) {
        to_proto(route, dst->add_routes());
    }
}

inline void from_proto(const pb::RouteAnnounce& src, RouteAnnounce* dst) {
    dst->request_id = src.request_id();
    dst->routes.clear();
    for (const auto& route : src.routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->routes.push_back(std::move(cpp_route));
    }
}

// ============================================================================
// RouteUpdate Conversion
// ============================================================================

inline void to_proto(const RouteUpdate& src, pb::RouteUpdate* dst) {
    dst->set_version(src.version);
    for (const auto& route : src.add_routes) {
        to_proto(route, dst->add_add_routes());
    }
    for (const auto& route : src.del_routes) {
        to_proto(route, dst->add_del_routes());
    }
}

inline void from_proto(const pb::RouteUpdate& src, RouteUpdate* dst) {
    dst->version = src.version();
    dst->add_routes.clear();
    for (const auto& route : src.add_routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->add_routes.push_back(std::move(cpp_route));
    }
    dst->del_routes.clear();
    for (const auto& route : src.del_routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->del_routes.push_back(std::move(cpp_route));
    }
}

// ============================================================================
// RouteWithdraw Conversion
// ============================================================================

inline void to_proto(const RouteWithdraw& src, pb::RouteWithdraw* dst) {
    dst->set_request_id(src.request_id);
    for (const auto& route : src.routes) {
        to_proto(route, dst->add_routes());
    }
}

inline void from_proto(const pb::RouteWithdraw& src, RouteWithdraw* dst) {
    dst->request_id = src.request_id();
    dst->routes.clear();
    for (const auto& route : src.routes()) {
        RouteInfo cpp_route;
        from_proto(route, &cpp_route);
        dst->routes.push_back(std::move(cpp_route));
    }
}

// ============================================================================
// RouteAck Conversion
// ============================================================================

inline void to_proto(const RouteAck& src, pb::RouteAck* dst) {
    dst->set_request_id(src.request_id);
    dst->set_success(src.success);
    dst->set_error_code(src.error_code);
    dst->set_error_msg(src.error_msg);
}

inline void from_proto(const pb::RouteAck& src, RouteAck* dst) {
    dst->request_id = src.request_id();
    dst->success = src.success();
    dst->error_code = static_cast<uint16_t>(src.error_code());
    dst->error_msg = src.error_msg();
}

// ============================================================================
// EndpointUpdate Conversion
// ============================================================================

inline void to_proto(const EndpointUpdate& src, pb::EndpointUpdate* dst) {
    dst->set_request_id(src.request_id);
    for (const auto& ep : src.endpoints) {
        to_proto(ep, dst->add_endpoints());
    }
}

inline void from_proto(const pb::EndpointUpdate& src, EndpointUpdate* dst) {
    dst->request_id = src.request_id();
    dst->endpoints.clear();
    for (const auto& ep : src.endpoints()) {
        Endpoint cpp_ep;
        from_proto(ep, &cpp_ep);
        dst->endpoints.push_back(std::move(cpp_ep));
    }
}

// ============================================================================
// EndpointAck Conversion
// ============================================================================

inline void to_proto(const EndpointAck& src, pb::EndpointAck* dst) {
    dst->set_request_id(src.request_id);
    dst->set_success(src.success);
    dst->set_endpoint_count(src.endpoint_count);
}

inline void from_proto(const pb::EndpointAck& src, EndpointAck* dst) {
    dst->request_id = src.request_id();
    dst->success = src.success();
    dst->endpoint_count = static_cast<uint8_t>(src.endpoint_count());
}

// ============================================================================
// AuthRequest/AuthResponse Helpers
// ============================================================================
// Note: get_auth_sign_data() is defined in auth_proto_helpers.hpp
// which must be included AFTER edgelink.pb.h

} // namespace edgelink
