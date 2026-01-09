#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <expected>
#include <array>
#include "protocol.hpp"

namespace edgelink::wire {

// ============================================================================
// Binary Encoding Rules (architecture.md section 2.4.1)
// ============================================================================
// | Type          | Encoding                              |
// |---------------|---------------------------------------|
// | uint8/16/32/64| Big Endian                            |
// | string        | 2-byte length prefix + UTF-8 data     |
// | bytes         | 2-byte length prefix + raw data       |
// | array         | 2-byte element count + elements       |
// | bool          | 1 byte (0x00=false, 0x01=true)        |
// | IPv4          | 4 bytes                               |
// | IPv6          | 16 bytes                              |
// ============================================================================

// ============================================================================
// BinaryWriter - Serialize data to binary format
// ============================================================================
class BinaryWriter {
public:
    BinaryWriter() = default;
    explicit BinaryWriter(size_t reserve_size) {
        buffer_.reserve(reserve_size);
    }

    // Write unsigned integers (big endian)
    void write_u8(uint8_t value) {
        buffer_.push_back(value);
    }

    void write_u16(uint16_t value) {
        buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    void write_u32(uint32_t value) {
        buffer_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    void write_u64(uint64_t value) {
        buffer_.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    // Write signed integers (big endian)
    void write_i64(int64_t value) {
        write_u64(static_cast<uint64_t>(value));
    }

    // Write boolean
    void write_bool(bool value) {
        buffer_.push_back(value ? 0x01 : 0x00);
    }

    // Write string with 2-byte length prefix
    void write_string(std::string_view str) {
        if (str.size() > 0xFFFF) {
            // Truncate if too long
            str = str.substr(0, 0xFFFF);
        }
        write_u16(static_cast<uint16_t>(str.size()));
        buffer_.insert(buffer_.end(), str.begin(), str.end());
    }

    // Write raw bytes with 2-byte length prefix
    void write_bytes(std::span<const uint8_t> data) {
        size_t len = std::min(data.size(), static_cast<size_t>(0xFFFF));
        write_u16(static_cast<uint16_t>(len));
        buffer_.insert(buffer_.end(), data.begin(), data.begin() + len);
    }

    // Write fixed-size bytes (no length prefix)
    void write_fixed_bytes(std::span<const uint8_t> data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
    }

    // Write array header (element count)
    void write_array_header(uint16_t count) {
        write_u16(count);
    }

    // Write IPv4 address (4 bytes)
    void write_ipv4(uint32_t addr) {
        write_u32(addr);
    }

    // Write IPv4 from string (dotted decimal)
    bool write_ipv4_string(std::string_view ip);

    // Write IPv6 address (16 bytes)
    void write_ipv6(std::span<const uint8_t, 16> addr) {
        write_fixed_bytes(addr);
    }

    // Get the resulting buffer
    std::vector<uint8_t>& data() { return buffer_; }
    const std::vector<uint8_t>& data() const { return buffer_; }

    // Move out the buffer
    std::vector<uint8_t> take() { return std::move(buffer_); }

    // Get current size
    size_t size() const { return buffer_.size(); }

private:
    std::vector<uint8_t> buffer_;
};

// ============================================================================
// BinaryReader - Deserialize data from binary format
// ============================================================================
class BinaryReader {
public:
    explicit BinaryReader(std::span<const uint8_t> data)
        : data_(data), pos_(0) {}

    // Check if there's enough data remaining
    bool has_remaining(size_t count) const {
        return pos_ + count <= data_.size();
    }

    size_t remaining() const {
        return data_.size() - pos_;
    }

    size_t position() const {
        return pos_;
    }

    // Read unsigned integers (big endian)
    std::expected<uint8_t, ErrorCode> read_u8() {
        if (!has_remaining(1)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }
        return data_[pos_++];
    }

    std::expected<uint16_t, ErrorCode> read_u16() {
        if (!has_remaining(2)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }
        uint16_t value = (static_cast<uint16_t>(data_[pos_]) << 8) |
                         static_cast<uint16_t>(data_[pos_ + 1]);
        pos_ += 2;
        return value;
    }

    std::expected<uint32_t, ErrorCode> read_u32() {
        if (!has_remaining(4)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }
        uint32_t value = (static_cast<uint32_t>(data_[pos_]) << 24) |
                         (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                         (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                         static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return value;
    }

    std::expected<uint64_t, ErrorCode> read_u64() {
        if (!has_remaining(8)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }
        uint64_t value = (static_cast<uint64_t>(data_[pos_]) << 56) |
                         (static_cast<uint64_t>(data_[pos_ + 1]) << 48) |
                         (static_cast<uint64_t>(data_[pos_ + 2]) << 40) |
                         (static_cast<uint64_t>(data_[pos_ + 3]) << 32) |
                         (static_cast<uint64_t>(data_[pos_ + 4]) << 24) |
                         (static_cast<uint64_t>(data_[pos_ + 5]) << 16) |
                         (static_cast<uint64_t>(data_[pos_ + 6]) << 8) |
                         static_cast<uint64_t>(data_[pos_ + 7]);
        pos_ += 8;
        return value;
    }

    // Read signed integers
    std::expected<int64_t, ErrorCode> read_i64() {
        auto result = read_u64();
        if (!result) return std::unexpected(result.error());
        return static_cast<int64_t>(*result);
    }

    // Read boolean
    std::expected<bool, ErrorCode> read_bool() {
        auto result = read_u8();
        if (!result) return std::unexpected(result.error());
        return *result != 0;
    }

    // Read string with 2-byte length prefix
    std::expected<std::string, ErrorCode> read_string() {
        auto len_result = read_u16();
        if (!len_result) return std::unexpected(len_result.error());

        uint16_t len = *len_result;
        if (!has_remaining(len)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }

        std::string str(reinterpret_cast<const char*>(data_.data() + pos_), len);
        pos_ += len;
        return str;
    }

    // Read bytes with 2-byte length prefix
    std::expected<std::vector<uint8_t>, ErrorCode> read_bytes() {
        auto len_result = read_u16();
        if (!len_result) return std::unexpected(len_result.error());

        uint16_t len = *len_result;
        if (!has_remaining(len)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }

        std::vector<uint8_t> bytes(data_.begin() + pos_, data_.begin() + pos_ + len);
        pos_ += len;
        return bytes;
    }

    // Read fixed-size bytes (no length prefix)
    std::expected<std::vector<uint8_t>, ErrorCode> read_fixed_bytes(size_t count) {
        if (!has_remaining(count)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }

        std::vector<uint8_t> bytes(data_.begin() + pos_, data_.begin() + pos_ + count);
        pos_ += count;
        return bytes;
    }

    // Read into fixed-size array
    template<size_t N>
    std::expected<std::array<uint8_t, N>, ErrorCode> read_fixed_array() {
        if (!has_remaining(N)) {
            return std::unexpected(ErrorCode::INVALID_MESSAGE);
        }

        std::array<uint8_t, N> arr;
        std::memcpy(arr.data(), data_.data() + pos_, N);
        pos_ += N;
        return arr;
    }

    // Read array header (element count)
    std::expected<uint16_t, ErrorCode> read_array_header() {
        return read_u16();
    }

    // Read IPv4 address
    std::expected<uint32_t, ErrorCode> read_ipv4() {
        return read_u32();
    }

    // Read IPv4 as string
    std::expected<std::string, ErrorCode> read_ipv4_string();

    // Read IPv6 address
    std::expected<std::array<uint8_t, 16>, ErrorCode> read_ipv6() {
        return read_fixed_array<16>();
    }

    // Skip bytes
    bool skip(size_t count) {
        if (!has_remaining(count)) return false;
        pos_ += count;
        return true;
    }

private:
    std::span<const uint8_t> data_;
    size_t pos_;
};

// ============================================================================
// Helper Functions
// ============================================================================

// Parse IPv4 string to uint32_t (network byte order)
std::expected<uint32_t, ErrorCode> parse_ipv4(std::string_view ip);

// Format uint32_t to IPv4 string
std::string format_ipv4(uint32_t addr);

// Parse CIDR notation (e.g., "192.168.1.0/24")
struct CIDRv4 {
    uint32_t prefix;
    uint8_t prefix_len;
};
std::expected<CIDRv4, ErrorCode> parse_cidr_v4(std::string_view cidr);
std::string format_cidr_v4(uint32_t prefix, uint8_t prefix_len);

} // namespace edgelink::wire
