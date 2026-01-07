#include <gtest/gtest.h>
#include "common/protocol.hpp"
#include "common/frame.hpp"

using namespace edgelink;

TEST(ProtocolTest, MessageTypeValues) {
    EXPECT_EQ(static_cast<uint8_t>(MessageType::AUTH_REQUEST), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(MessageType::AUTH_RESPONSE), 0x02);
    EXPECT_EQ(static_cast<uint8_t>(MessageType::CONFIG), 0x10);
    EXPECT_EQ(static_cast<uint8_t>(MessageType::DATA), 0x20);
    EXPECT_EQ(static_cast<uint8_t>(MessageType::PING), 0x30);
    EXPECT_EQ(static_cast<uint8_t>(MessageType::PONG), 0x31);
}

TEST(ProtocolTest, FrameFlags) {
    EXPECT_EQ(FrameFlags::NONE, 0x00);
    EXPECT_EQ(FrameFlags::NEED_ACK, 0x01);
    EXPECT_EQ(FrameFlags::COMPRESSED, 0x02);
}

TEST(FrameTest, SerializeDeserializeSimple) {
    Frame frame = Frame::create(MessageType::PING, {0x01, 0x02, 0x03, 0x04}, FrameFlags::NONE);
    
    auto encoded = frame.serialize();
    ASSERT_GE(encoded.size(), NetworkConstants::HEADER_SIZE);
    
    auto decoded = Frame::deserialize(encoded);
    ASSERT_TRUE(decoded.has_value());
    
    EXPECT_EQ(decoded->header.version, PROTOCOL_VERSION);
    EXPECT_EQ(decoded->header.type, MessageType::PING);
    EXPECT_EQ(decoded->header.flags, FrameFlags::NONE);
    EXPECT_EQ(decoded->payload, frame.payload);
}

TEST(FrameTest, SerializeDeserializeEmpty) {
    Frame frame = Frame::create(MessageType::PONG, {}, FrameFlags::NONE);
    
    auto encoded = frame.serialize();
    EXPECT_EQ(encoded.size(), NetworkConstants::HEADER_SIZE);  // Just header
    
    auto decoded = Frame::deserialize(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->payload.empty());
}

TEST(FrameTest, DeserializeInvalidLength) {
    std::vector<uint8_t> short_data = {0x01, 0x02};  // Too short
    auto decoded = Frame::deserialize(short_data);
    EXPECT_FALSE(decoded.has_value());
}

TEST(FrameTest, CreateWithPayload) {
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    Frame frame = Frame::create(MessageType::DATA, payload, FrameFlags::COMPRESSED);
    
    EXPECT_EQ(frame.header.type, MessageType::DATA);
    EXPECT_EQ(frame.header.flags, FrameFlags::COMPRESSED);
    EXPECT_EQ(frame.payload, payload);
}

TEST(AuthPayloadTest, JsonSerialization) {
    AuthRequestPayload req;
    req.machine_key_pub = "test_machine_key";
    req.node_key_pub = "test_node_key";
    req.signature = "test_signature";
    req.timestamp = 1234567890;
    req.hostname = "test-host";
    req.os = "linux";
    req.arch = "x86_64";
    req.version = "1.0.0";
    
    auto json = req.to_json();
    
    AuthRequestPayload decoded;
    EXPECT_TRUE(decoded.from_json(json));
    
    EXPECT_EQ(decoded.machine_key_pub, req.machine_key_pub);
    EXPECT_EQ(decoded.node_key_pub, req.node_key_pub);
    EXPECT_EQ(decoded.signature, req.signature);
    EXPECT_EQ(decoded.timestamp, req.timestamp);
    EXPECT_EQ(decoded.hostname, req.hostname);
    EXPECT_EQ(decoded.os, req.os);
    EXPECT_EQ(decoded.arch, req.arch);
    EXPECT_EQ(decoded.version, req.version);
}

TEST(AuthResponsePayloadTest, JsonSerialization) {
    AuthResponsePayload resp;
    resp.success = true;
    resp.node_id = 42;
    resp.virtual_ip = "10.100.0.5";
    resp.auth_token = "test_auth_token";
    resp.relay_token = "test_relay_token";
    
    auto json = resp.to_json();
    
    auto decoded_result = AuthResponsePayload::from_json(json);
    ASSERT_TRUE(decoded_result.has_value());
    auto& decoded = *decoded_result;
    
    EXPECT_EQ(decoded.success, resp.success);
    EXPECT_EQ(decoded.node_id, resp.node_id);
    EXPECT_EQ(decoded.virtual_ip, resp.virtual_ip);
    EXPECT_EQ(decoded.auth_token, resp.auth_token);
    EXPECT_EQ(decoded.relay_token, resp.relay_token);
}

TEST(ErrorPayloadTest, JsonSerialization) {
    ErrorPayload error;
    error.code = 1001;
    error.message = "Authentication failed";
    error.details = "Invalid signature";
    
    auto json = error.to_json();
    
    ErrorPayload decoded;
    EXPECT_TRUE(decoded.from_json(json));
    
    EXPECT_EQ(decoded.code, error.code);
    EXPECT_EQ(decoded.message, error.message);
    EXPECT_EQ(decoded.details, error.details);
}

TEST(DataPayloadTest, JsonSerialization) {
    DataPayload data;
    data.dst_node_id = 123;
    data.src_node_id = 456;
    data.encrypted_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    auto json = data.to_json();
    
    DataPayload decoded;
    EXPECT_TRUE(decoded.from_json(json));
    
    EXPECT_EQ(decoded.dst_node_id, data.dst_node_id);
    EXPECT_EQ(decoded.src_node_id, data.src_node_id);
    EXPECT_EQ(decoded.encrypted_data, data.encrypted_data);
}

TEST(RelayAuthPayloadTest, JsonSerialization) {
    RelayAuthPayload auth;
    auth.relay_token = "test_relay_token_value";
    
    auto json = auth.to_json();
    
    RelayAuthPayload decoded;
    EXPECT_TRUE(decoded.from_json(json));
    
    EXPECT_EQ(decoded.relay_token, auth.relay_token);
}

TEST(EndpointTest, TypeValues) {
    EXPECT_EQ(static_cast<uint8_t>(EndpointType::LAN), 1);
    EXPECT_EQ(static_cast<uint8_t>(EndpointType::STUN), 2);
    EXPECT_EQ(static_cast<uint8_t>(EndpointType::RELAY), 3);
}

TEST(NATTypeTest, Values) {
    EXPECT_EQ(static_cast<uint8_t>(NATType::UNKNOWN), 0);
    EXPECT_EQ(static_cast<uint8_t>(NATType::OPEN), 1);
    EXPECT_EQ(static_cast<uint8_t>(NATType::FULL_CONE), 2);
    EXPECT_EQ(static_cast<uint8_t>(NATType::RESTRICTED_CONE), 3);
    EXPECT_EQ(static_cast<uint8_t>(NATType::PORT_RESTRICTED), 4);
    EXPECT_EQ(static_cast<uint8_t>(NATType::SYMMETRIC), 5);
}

TEST(ErrorCodeTest, Values) {
    EXPECT_EQ(static_cast<uint16_t>(ErrorCode::INVALID_TOKEN), 1001);
    EXPECT_EQ(static_cast<uint16_t>(ErrorCode::INVALID_MESSAGE), 2002);
    EXPECT_EQ(static_cast<uint16_t>(ErrorCode::NODE_NOT_FOUND), 3002);
}
