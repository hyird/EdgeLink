#pragma once

#include "common/types.hpp"
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <type_traits>

// Forward declaration for protobuf message base class
namespace google::protobuf {
class MessageLite;
}

namespace edgelink {

// Frame header size: Version(1) + Type(1) + Flags(1) + Length(2) = 5 bytes
inline constexpr size_t FRAME_HEADER_SIZE = 5;

// Fragment header size: MessageId(4) + FragIndex(2) + FragTotal(2) + OrigType(1) = 9 bytes
inline constexpr size_t FRAGMENT_HEADER_SIZE = 9;

// Maximum payload size (16-bit length field)
inline constexpr size_t MAX_PAYLOAD_SIZE = 65535;

// Maximum business data per fragment
inline constexpr size_t MAX_FRAGMENT_DATA_SIZE = MAX_PAYLOAD_SIZE - FRAGMENT_HEADER_SIZE;

// Compression threshold
inline constexpr size_t COMPRESSION_THRESHOLD = 256;

// Frame header structure
struct FrameHeader {
    uint8_t version = PROTOCOL_VERSION;
    FrameType type = FrameType::FRAME_ERROR;
    FrameFlags flags = FrameFlags::NONE;
    uint16_t length = 0; // Payload length (not including header)
};

// Fragment header structure
struct FragmentHeader {
    MessageId message_id = 0;
    uint16_t frag_index = 0;
    uint16_t frag_total = 0;
    FrameType orig_type = FrameType::FRAME_ERROR;
};

// Decoded frame structure
struct Frame {
    FrameHeader header;
    std::vector<uint8_t> payload;

    // For fragmented frames
    std::optional<FragmentHeader> fragment;

    // Get the actual business data (excludes fragment header if present)
    std::span<const uint8_t> data() const {
        if (fragment.has_value()) {
            return std::span(payload).subspan(FRAGMENT_HEADER_SIZE);
        }
        return payload;
    }

    bool is_fragmented() const {
        return has_flag(header.flags, FrameFlags::FRAGMENTED);
    }

    bool is_compressed() const {
        return has_flag(header.flags, FrameFlags::COMPRESSED);
    }

    bool needs_ack() const {
        return has_flag(header.flags, FrameFlags::NEED_ACK);
    }
};

// Frame decode errors
enum class FrameError {
    INCOMPLETE_HEADER,
    INCOMPLETE_PAYLOAD,
    INVALID_VERSION,
    INVALID_TYPE,
    PAYLOAD_TOO_LARGE,
    DECOMPRESSION_FAILED,
    INVALID_FRAGMENT,
    PROTOBUF_SERIALIZE_FAILED,
    PROTOBUF_PARSE_FAILED,
};

std::string frame_error_message(FrameError error);

// 独立的大端读写工具函数（用于随机访问场景）
namespace binary {

inline uint16_t read_u16_be(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

inline uint32_t read_u32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

inline void write_u16_be(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 8));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

inline void write_u32_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 24));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

} // namespace binary

// Binary buffer utilities (stateful sequential reader/writer)
class BinaryReader {
public:
    explicit BinaryReader(std::span<const uint8_t> data)
        : data_(data), pos_(0) {}

    bool has_bytes(size_t count) const { return pos_ + count <= data_.size(); }
    size_t remaining() const { return data_.size() - pos_; }
    size_t position() const { return pos_; }

    std::optional<uint8_t> read_u8();
    std::optional<uint16_t> read_u16_be();
    std::optional<uint32_t> read_u32_be();
    std::optional<uint64_t> read_u64_be();
    std::optional<std::vector<uint8_t>> read_bytes(size_t count);
    std::optional<std::string> read_string(); // 2-byte length prefix + UTF-8

    // Read fixed-size array
    template<size_t N>
    std::optional<std::array<uint8_t, N>> read_array() {
        if (!has_bytes(N)) return std::nullopt;
        std::array<uint8_t, N> result;
        std::copy_n(data_.data() + pos_, N, result.data());
        pos_ += N;
        return result;
    }

    std::span<const uint8_t> remaining_data() const {
        return data_.subspan(pos_);
    }

private:
    std::span<const uint8_t> data_;
    size_t pos_;
};

class BinaryWriter {
public:
    BinaryWriter() = default;
    explicit BinaryWriter(size_t reserve_size) { buffer_.reserve(reserve_size); }

    void write_u8(uint8_t value);
    void write_u16_be(uint16_t value);
    void write_u32_be(uint32_t value);
    void write_u64_be(uint64_t value);
    void write_bytes(std::span<const uint8_t> data);
    void write_string(std::string_view str); // 2-byte length prefix + UTF-8

    template<size_t N>
    void write_array(const std::array<uint8_t, N>& arr) {
        buffer_.insert(buffer_.end(), arr.begin(), arr.end());
    }

    std::vector<uint8_t> take() { return std::move(buffer_); }
    const std::vector<uint8_t>& data() const { return buffer_; }
    size_t size() const { return buffer_.size(); }

    // Direct access for modification
    void set_u16_be_at(size_t offset, uint16_t value);

private:
    std::vector<uint8_t> buffer_;
};

// Frame codec
class FrameCodec {
public:
    // Encode a frame
    static std::vector<uint8_t> encode(FrameType type, std::span<const uint8_t> payload,
                                       FrameFlags flags = FrameFlags::NONE);

    // Encode with optional compression
    static std::vector<uint8_t> encode_with_compression(FrameType type,
                                                        std::span<const uint8_t> payload,
                                                        FrameFlags flags = FrameFlags::NONE);

    // Decode a frame from buffer
    // Returns the decoded frame and number of bytes consumed
    // NOTE: 对于分片帧，decode() 只解析单个 FRAGMENT 帧。
    // 调用者需自行实现基于 message_id 的分片重组（收集所有 frag_index，
    // 全部到齐后按序拼接 payload）。当前客户端/控制器未使用分片功能。
    static std::expected<std::pair<Frame, size_t>, FrameError> decode(
        std::span<const uint8_t> data);

    // Check if buffer contains a complete frame
    static std::optional<size_t> frame_size(std::span<const uint8_t> data);

    // Fragment a large payload into multiple frames
    static std::vector<std::vector<uint8_t>> fragment(
        MessageId message_id, FrameType type,
        std::span<const uint8_t> payload, FrameFlags flags = FrameFlags::NONE);

    // ========================================================================
    // Protobuf Encoding/Decoding Helpers
    // ========================================================================

    /// Encode a protobuf message into a frame
    /// @tparam T Protobuf message type (must inherit from google::protobuf::MessageLite)
    /// @param type Frame type
    /// @param msg Protobuf message to encode
    /// @param flags Frame flags
    /// @return Encoded frame bytes, or error if serialization fails
    template<typename T>
    static std::expected<std::vector<uint8_t>, FrameError> encode_protobuf(
        FrameType type, const T& msg, FrameFlags flags = FrameFlags::NONE) {
        static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                      "T must be a protobuf message type");

        std::string payload;
        if (!msg.SerializeToString(&payload)) {
            return std::unexpected(FrameError::PROTOBUF_SERIALIZE_FAILED);
        }

        std::span<const uint8_t> payload_span(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

        return encode(type, payload_span, flags);
    }

    /// Encode a protobuf message with optional compression
    template<typename T>
    static std::expected<std::vector<uint8_t>, FrameError> encode_protobuf_with_compression(
        FrameType type, const T& msg, FrameFlags flags = FrameFlags::NONE) {
        static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                      "T must be a protobuf message type");

        std::string payload;
        if (!msg.SerializeToString(&payload)) {
            return std::unexpected(FrameError::PROTOBUF_SERIALIZE_FAILED);
        }

        std::span<const uint8_t> payload_span(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

        return encode_with_compression(type, payload_span, flags);
    }

    /// Decode a frame payload into a protobuf message
    /// @tparam T Protobuf message type
    /// @param payload Frame payload bytes
    /// @return Parsed protobuf message, or error if parsing fails
    template<typename T>
    static std::expected<T, FrameError> decode_protobuf(std::span<const uint8_t> payload) {
        static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                      "T must be a protobuf message type");

        T msg;
        if (!msg.ParseFromArray(payload.data(), static_cast<int>(payload.size()))) {
            return std::unexpected(FrameError::PROTOBUF_PARSE_FAILED);
        }
        return msg;
    }

    /// Decode a frame and parse its payload as a protobuf message
    /// @tparam T Protobuf message type
    /// @param data Raw frame data
    /// @return Tuple of (message, frame header, bytes consumed), or error
    template<typename T>
    static std::expected<std::tuple<T, FrameHeader, size_t>, FrameError> decode_frame_protobuf(
        std::span<const uint8_t> data) {
        static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                      "T must be a protobuf message type");

        auto frame_result = decode(data);
        if (!frame_result) {
            return std::unexpected(frame_result.error());
        }

        auto& [frame, consumed] = *frame_result;
        auto msg_result = decode_protobuf<T>(frame.data());
        if (!msg_result) {
            return std::unexpected(msg_result.error());
        }

        return std::make_tuple(std::move(*msg_result), frame.header, consumed);
    }

private:
    static std::expected<FrameHeader, FrameError> decode_header(std::span<const uint8_t> data);
    static std::expected<FragmentHeader, FrameError> decode_fragment_header(
        std::span<const uint8_t> data);
};

// LZ4 compression utilities
namespace compression {

std::vector<uint8_t> compress(std::span<const uint8_t> data);
std::expected<std::vector<uint8_t>, FrameError> decompress(
    std::span<const uint8_t> compressed_data, uint32_t original_length);

} // namespace compression

} // namespace edgelink
