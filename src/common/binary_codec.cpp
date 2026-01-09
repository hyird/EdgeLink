#include "common/binary_codec.hpp"
#include <charconv>
#include <sstream>

namespace edgelink::wire {

// ============================================================================
// BinaryWriter IPv4 string helper
// ============================================================================
bool BinaryWriter::write_ipv4_string(std::string_view ip) {
    auto result = parse_ipv4(ip);
    if (!result) return false;
    write_u32(*result);
    return true;
}

// ============================================================================
// BinaryReader IPv4 string helper
// ============================================================================
std::expected<std::string, ErrorCode> BinaryReader::read_ipv4_string() {
    auto result = read_ipv4();
    if (!result) return std::unexpected(result.error());
    return format_ipv4(*result);
}

// ============================================================================
// IPv4 Parse/Format Functions
// ============================================================================
std::expected<uint32_t, ErrorCode> parse_ipv4(std::string_view ip) {
    uint32_t result = 0;
    int octet_count = 0;
    uint32_t current_octet = 0;

    for (size_t i = 0; i <= ip.size(); ++i) {
        char c = (i < ip.size()) ? ip[i] : '.';

        if (c >= '0' && c <= '9') {
            current_octet = current_octet * 10 + (c - '0');
            if (current_octet > 255) {
                return std::unexpected(ErrorCode::INVALID_ARGUMENT);
            }
        } else if (c == '.') {
            if (octet_count >= 4) {
                return std::unexpected(ErrorCode::INVALID_ARGUMENT);
            }
            result = (result << 8) | current_octet;
            current_octet = 0;
            ++octet_count;
        } else {
            return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
    }

    if (octet_count != 4) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    return result;
}

std::string format_ipv4(uint32_t addr) {
    std::ostringstream oss;
    oss << ((addr >> 24) & 0xFF) << '.'
        << ((addr >> 16) & 0xFF) << '.'
        << ((addr >> 8) & 0xFF) << '.'
        << (addr & 0xFF);
    return oss.str();
}

// ============================================================================
// CIDR Parse/Format Functions
// ============================================================================
std::expected<CIDRv4, ErrorCode> parse_cidr_v4(std::string_view cidr) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string_view::npos) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto ip_part = cidr.substr(0, slash_pos);
    auto prefix_len_part = cidr.substr(slash_pos + 1);

    // Parse IP
    auto ip_result = parse_ipv4(ip_part);
    if (!ip_result) {
        return std::unexpected(ip_result.error());
    }

    // Parse prefix length
    uint8_t prefix_len = 0;
    auto [ptr, ec] = std::from_chars(
        prefix_len_part.data(),
        prefix_len_part.data() + prefix_len_part.size(),
        prefix_len);

    if (ec != std::errc{} || prefix_len > 32) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    return CIDRv4{*ip_result, prefix_len};
}

std::string format_cidr_v4(uint32_t prefix, uint8_t prefix_len) {
    std::ostringstream oss;
    oss << format_ipv4(prefix) << '/' << static_cast<int>(prefix_len);
    return oss.str();
}

} // namespace edgelink::wire
