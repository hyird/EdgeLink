#include "common/frame.hpp"
#include <lz4.h>
#include <algorithm>

namespace edgelink {

std::string frame_error_message(FrameError error) {
    switch (error) {
        case FrameError::INCOMPLETE_HEADER: return "Incomplete frame header";
        case FrameError::INCOMPLETE_PAYLOAD: return "Incomplete frame payload";
        case FrameError::INVALID_VERSION: return "Invalid protocol version";
        case FrameError::INVALID_TYPE: return "Invalid frame type";
        case FrameError::PAYLOAD_TOO_LARGE: return "Payload too large";
        case FrameError::DECOMPRESSION_FAILED: return "Decompression failed";
        case FrameError::INVALID_FRAGMENT: return "Invalid fragment header";
        default: return "Unknown error";
    }
}

// BinaryReader implementation
std::optional<uint8_t> BinaryReader::read_u8() {
    if (!has_bytes(1)) return std::nullopt;
    return data_[pos_++];
}

std::optional<uint16_t> BinaryReader::read_u16_be() {
    if (!has_bytes(2)) return std::nullopt;
    uint16_t value = (static_cast<uint16_t>(data_[pos_]) << 8) |
                     static_cast<uint16_t>(data_[pos_ + 1]);
    pos_ += 2;
    return value;
}

std::optional<uint32_t> BinaryReader::read_u32_be() {
    if (!has_bytes(4)) return std::nullopt;
    uint32_t value = (static_cast<uint32_t>(data_[pos_]) << 24) |
                     (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                     (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                     static_cast<uint32_t>(data_[pos_ + 3]);
    pos_ += 4;
    return value;
}

std::optional<uint64_t> BinaryReader::read_u64_be() {
    if (!has_bytes(8)) return std::nullopt;
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<uint64_t>(data_[pos_ + i]);
    }
    pos_ += 8;
    return value;
}

std::optional<std::vector<uint8_t>> BinaryReader::read_bytes(size_t count) {
    if (!has_bytes(count)) return std::nullopt;
    std::vector<uint8_t> result(data_.begin() + pos_, data_.begin() + pos_ + count);
    pos_ += count;
    return result;
}

std::optional<std::string> BinaryReader::read_string() {
    auto len = read_u16_be();
    if (!len) return std::nullopt;
    if (!has_bytes(*len)) return std::nullopt;
    std::string result(reinterpret_cast<const char*>(data_.data() + pos_), *len);
    pos_ += *len;
    return result;
}

// BinaryWriter implementation
void BinaryWriter::write_u8(uint8_t value) {
    buffer_.push_back(value);
}

void BinaryWriter::write_u16_be(uint16_t value) {
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void BinaryWriter::write_u32_be(uint32_t value) {
    buffer_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
}

void BinaryWriter::write_u64_be(uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        buffer_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void BinaryWriter::write_bytes(std::span<const uint8_t> data) {
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void BinaryWriter::write_string(std::string_view str) {
    write_u16_be(static_cast<uint16_t>(str.size()));
    buffer_.insert(buffer_.end(), str.begin(), str.end());
}

void BinaryWriter::set_u16_be_at(size_t offset, uint16_t value) {
    buffer_[offset] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer_[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

// FrameCodec implementation
std::vector<uint8_t> FrameCodec::encode(FrameType type, std::span<const uint8_t> payload,
                                        FrameFlags flags) {
    BinaryWriter writer(FRAME_HEADER_SIZE + payload.size());

    // Frame header
    writer.write_u8(PROTOCOL_VERSION);
    writer.write_u8(static_cast<uint8_t>(type));
    writer.write_u8(static_cast<uint8_t>(flags));
    writer.write_u16_be(static_cast<uint16_t>(payload.size()));

    // Payload
    writer.write_bytes(payload);

    return writer.take();
}

std::vector<uint8_t> FrameCodec::encode_with_compression(
    FrameType type, std::span<const uint8_t> payload, FrameFlags flags) {

    // Only compress if above threshold
    if (payload.size() <= COMPRESSION_THRESHOLD) {
        return encode(type, payload, flags);
    }

    auto compressed = compression::compress(payload);

    // Only use compression if it actually helps
    if (compressed.size() >= payload.size()) {
        return encode(type, payload, flags);
    }

    // Build compressed payload: original_length (4B) + compressed data
    BinaryWriter compressed_payload(4 + compressed.size());
    compressed_payload.write_u32_be(static_cast<uint32_t>(payload.size()));
    compressed_payload.write_bytes(compressed);

    return encode(type, compressed_payload.data(), flags | FrameFlags::COMPRESSED);
}

std::expected<FrameHeader, FrameError> FrameCodec::decode_header(
    std::span<const uint8_t> data) {

    if (data.size() < FRAME_HEADER_SIZE) {
        return std::unexpected(FrameError::INCOMPLETE_HEADER);
    }

    FrameHeader header;
    header.version = data[0];
    header.type = static_cast<FrameType>(data[1]);
    header.flags = static_cast<FrameFlags>(data[2]);
    header.length = (static_cast<uint16_t>(data[3]) << 8) | static_cast<uint16_t>(data[4]);

    if (header.version != PROTOCOL_VERSION) {
        return std::unexpected(FrameError::INVALID_VERSION);
    }

    return header;
}

std::expected<FragmentHeader, FrameError> FrameCodec::decode_fragment_header(
    std::span<const uint8_t> data) {

    if (data.size() < FRAGMENT_HEADER_SIZE) {
        return std::unexpected(FrameError::INVALID_FRAGMENT);
    }

    BinaryReader reader(data);
    FragmentHeader frag;

    frag.message_id = *reader.read_u32_be();
    frag.frag_index = *reader.read_u16_be();
    frag.frag_total = *reader.read_u16_be();
    frag.orig_type = static_cast<FrameType>(*reader.read_u8());

    if (frag.frag_index >= frag.frag_total || frag.frag_total == 0) {
        return std::unexpected(FrameError::INVALID_FRAGMENT);
    }

    return frag;
}

std::expected<std::pair<Frame, size_t>, FrameError> FrameCodec::decode(
    std::span<const uint8_t> data) {

    auto header_result = decode_header(data);
    if (!header_result) {
        return std::unexpected(header_result.error());
    }

    const auto& header = *header_result;
    size_t total_size = FRAME_HEADER_SIZE + header.length;

    if (data.size() < total_size) {
        return std::unexpected(FrameError::INCOMPLETE_PAYLOAD);
    }

    Frame frame;
    frame.header = header;

    auto payload_span = data.subspan(FRAME_HEADER_SIZE, header.length);

    // Handle decompression
    if (has_flag(header.flags, FrameFlags::COMPRESSED)) {
        if (payload_span.size() < 4) {
            return std::unexpected(FrameError::DECOMPRESSION_FAILED);
        }

        uint32_t original_length = (static_cast<uint32_t>(payload_span[0]) << 24) |
                                   (static_cast<uint32_t>(payload_span[1]) << 16) |
                                   (static_cast<uint32_t>(payload_span[2]) << 8) |
                                   static_cast<uint32_t>(payload_span[3]);

        auto compressed_data = payload_span.subspan(4);
        auto decompressed = compression::decompress(compressed_data, original_length);
        if (!decompressed) {
            return std::unexpected(FrameError::DECOMPRESSION_FAILED);
        }
        frame.payload = std::move(*decompressed);
    } else {
        frame.payload.assign(payload_span.begin(), payload_span.end());
    }

    // Handle fragmentation
    if (has_flag(header.flags, FrameFlags::FRAGMENTED)) {
        auto frag_result = decode_fragment_header(frame.payload);
        if (!frag_result) {
            return std::unexpected(frag_result.error());
        }
        frame.fragment = *frag_result;
    }

    return std::make_pair(std::move(frame), total_size);
}

std::optional<size_t> FrameCodec::frame_size(std::span<const uint8_t> data) {
    if (data.size() < FRAME_HEADER_SIZE) {
        return std::nullopt;
    }

    uint16_t length = (static_cast<uint16_t>(data[3]) << 8) | static_cast<uint16_t>(data[4]);
    return FRAME_HEADER_SIZE + length;
}

std::vector<std::vector<uint8_t>> FrameCodec::fragment(
    MessageId message_id, FrameType type,
    std::span<const uint8_t> payload, FrameFlags flags) {

    std::vector<std::vector<uint8_t>> frames;

    // Calculate number of fragments
    size_t total_data = payload.size();
    size_t num_fragments = (total_data + MAX_FRAGMENT_DATA_SIZE - 1) / MAX_FRAGMENT_DATA_SIZE;

    if (num_fragments > 65535) {
        // Too large to fragment, return empty
        return frames;
    }

    frames.reserve(num_fragments);
    FrameFlags frag_flags = flags | FrameFlags::FRAGMENTED;

    for (size_t i = 0; i < num_fragments; ++i) {
        size_t offset = i * MAX_FRAGMENT_DATA_SIZE;
        size_t chunk_size = std::min(MAX_FRAGMENT_DATA_SIZE, total_data - offset);

        BinaryWriter frag_payload(FRAGMENT_HEADER_SIZE + chunk_size);

        // Fragment header
        frag_payload.write_u32_be(message_id);
        frag_payload.write_u16_be(static_cast<uint16_t>(i));
        frag_payload.write_u16_be(static_cast<uint16_t>(num_fragments));
        frag_payload.write_u8(static_cast<uint8_t>(type));

        // Fragment data
        frag_payload.write_bytes(payload.subspan(offset, chunk_size));

        frames.push_back(encode(type, frag_payload.data(), frag_flags));
    }

    return frames;
}

namespace compression {

std::vector<uint8_t> compress(std::span<const uint8_t> data) {
    if (data.empty()) return {};

    int max_compressed_size = LZ4_compressBound(static_cast<int>(data.size()));
    std::vector<uint8_t> compressed(max_compressed_size);

    int compressed_size = LZ4_compress_default(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressed.data()),
        static_cast<int>(data.size()),
        max_compressed_size);

    if (compressed_size <= 0) {
        return {};
    }

    compressed.resize(compressed_size);
    return compressed;
}

std::expected<std::vector<uint8_t>, FrameError> decompress(
    std::span<const uint8_t> compressed_data, uint32_t original_length) {

    if (compressed_data.empty() || original_length == 0) {
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> decompressed(original_length);

    int decompressed_size = LZ4_decompress_safe(
        reinterpret_cast<const char*>(compressed_data.data()),
        reinterpret_cast<char*>(decompressed.data()),
        static_cast<int>(compressed_data.size()),
        static_cast<int>(original_length));

    if (decompressed_size < 0 ||
        static_cast<uint32_t>(decompressed_size) != original_length) {
        return std::unexpected(FrameError::DECOMPRESSION_FAILED);
    }

    return decompressed;
}

} // namespace compression

} // namespace edgelink
