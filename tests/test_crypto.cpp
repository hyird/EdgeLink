#include <gtest/gtest.h>
#include "common/crypto/x25519.hpp"
#include "common/crypto/ed25519.hpp"
#include "common/crypto/chacha20.hpp"
#include "common/crypto/hkdf.hpp"

using namespace edgelink;
using namespace edgelink::crypto;

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// X25519 Tests
TEST_F(CryptoTest, X25519KeyGeneration) {
    auto [pub1, priv1] = X25519::generate_keypair();
    auto [pub2, priv2] = X25519::generate_keypair();
    
    // Keys should be the right size
    EXPECT_EQ(pub1.size(), 32u);
    EXPECT_EQ(priv1.size(), 32u);
    
    // Keys should be different
    EXPECT_NE(pub1, pub2);
    EXPECT_NE(priv1, priv2);
}

TEST_F(CryptoTest, X25519SharedSecret) {
    auto [pub_a, priv_a] = X25519::generate_keypair();
    auto [pub_b, priv_b] = X25519::generate_keypair();
    
    auto secret_a = X25519::compute_shared_secret(priv_a, pub_b);
    auto secret_b = X25519::compute_shared_secret(priv_b, pub_a);
    
    ASSERT_TRUE(secret_a.has_value());
    ASSERT_TRUE(secret_b.has_value());
    
    // Both sides should compute the same shared secret
    EXPECT_EQ(*secret_a, *secret_b);
}

TEST_F(CryptoTest, X25519Base64Roundtrip) {
    auto [pub, priv] = X25519::generate_keypair();
    
    // Convert to base64 and back
    std::string pub_b64 = X25519::public_key_to_base64(pub);
    auto pub_decoded = X25519::public_key_from_base64(pub_b64);
    
    ASSERT_TRUE(pub_decoded.has_value());
    EXPECT_EQ(pub, *pub_decoded);
}

// Ed25519 Tests
TEST_F(CryptoTest, Ed25519KeyGeneration) {
    auto [pub1, priv1] = Ed25519::generate_keypair();
    auto [pub2, priv2] = Ed25519::generate_keypair();
    
    // Keys should be the right size
    EXPECT_EQ(pub1.size(), 32u);
    EXPECT_EQ(priv1.size(), 64u);
    
    // Keys should be different
    EXPECT_NE(pub1, pub2);
    EXPECT_NE(priv1, priv2);
}

TEST_F(CryptoTest, Ed25519SignVerify) {
    auto [pub, priv] = Ed25519::generate_keypair();
    
    std::vector<uint8_t> message = {0x01, 0x02, 0x03};
    auto signature = Ed25519::sign(priv, std::span<const uint8_t>(message));
    
    bool valid = Ed25519::verify(pub, std::span<const uint8_t>(message), signature);
    EXPECT_TRUE(valid);
}

TEST_F(CryptoTest, Ed25519InvalidSignature) {
    auto [pub, priv] = Ed25519::generate_keypair();
    
    std::vector<uint8_t> message = {0x01, 0x02, 0x03};
    auto signature = Ed25519::sign(priv, std::span<const uint8_t>(message));
    
    // Modify message
    std::vector<uint8_t> modified_message = {0x01, 0x02, 0x04};
    
    bool valid = Ed25519::verify(pub, std::span<const uint8_t>(modified_message), signature);
    EXPECT_FALSE(valid);
}

TEST_F(CryptoTest, Ed25519Base64Roundtrip) {
    auto [pub, priv] = Ed25519::generate_keypair();
    
    std::string pub_b64 = Ed25519::to_base64(pub);
    auto pub_decoded = Ed25519::public_key_from_base64(pub_b64);
    
    ASSERT_TRUE(pub_decoded.has_value());
    EXPECT_EQ(pub, *pub_decoded);
}

TEST_F(CryptoTest, Ed25519KeyFingerprint) {
    auto [pub, priv] = Ed25519::generate_keypair();
    
    std::string fingerprint = Ed25519::key_fingerprint(pub);
    
    // Fingerprint should be 16 hex chars (8 bytes)
    EXPECT_EQ(fingerprint.length(), 16u);
    
    // Same key should produce same fingerprint
    std::string fingerprint2 = Ed25519::key_fingerprint(pub);
    EXPECT_EQ(fingerprint, fingerprint2);
}

// ChaCha20-Poly1305 Tests
TEST_F(CryptoTest, ChaCha20EncryptDecrypt) {
    SessionKey key;
    for (size_t i = 0; i < key.size(); i++) key[i] = static_cast<uint8_t>(i);
    
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    
    auto encrypted = ChaCha20Poly1305::encrypt(key, std::span<const uint8_t>(message));
    ASSERT_TRUE(encrypted.has_value());
    
    // Encrypted data should be different from original
    EXPECT_NE(*encrypted, message);
    
    auto decrypted = ChaCha20Poly1305::decrypt(key, std::span<const uint8_t>(*encrypted));
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, message);
}

TEST_F(CryptoTest, ChaCha20DecryptWrongKey) {
    SessionKey key1, key2;
    for (size_t i = 0; i < 32; i++) {
        key1[i] = static_cast<uint8_t>(i);
        key2[i] = static_cast<uint8_t>(i + 1);
    }
    
    std::vector<uint8_t> message = {'T', 'e', 's', 't'};
    
    auto encrypted = ChaCha20Poly1305::encrypt(key1, std::span<const uint8_t>(message));
    ASSERT_TRUE(encrypted.has_value());
    
    // Decryption with wrong key should fail
    auto decrypted = ChaCha20Poly1305::decrypt(key2, std::span<const uint8_t>(*encrypted));
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(CryptoTest, ChaCha20NonceGeneration) {
    auto nonce1 = ChaCha20Poly1305::generate_nonce();
    auto nonce2 = ChaCha20Poly1305::generate_nonce();
    
    EXPECT_EQ(nonce1.size(), 12u);
    EXPECT_EQ(nonce2.size(), 12u);
    
    // Nonces should be different
    EXPECT_NE(nonce1, nonce2);
}

// HKDF Tests
TEST_F(CryptoTest, HKDFDerive) {
    std::vector<uint8_t> ikm = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> salt = {0xaa, 0xbb, 0xcc};
    std::vector<uint8_t> info = {0x11, 0x22, 0x33};
    
    auto derived = HKDF::derive(ikm, salt, info, 32);
    
    EXPECT_EQ(derived.size(), 32u);
    
    // Same inputs should produce same output
    auto derived2 = HKDF::derive(ikm, salt, info, 32);
    EXPECT_EQ(derived, derived2);
    
    // Different info should produce different output
    std::vector<uint8_t> info2 = {0x44, 0x55, 0x66};
    auto derived3 = HKDF::derive(ikm, salt, info2, 32);
    EXPECT_NE(derived, derived3);
}

TEST_F(CryptoTest, HKDFSessionKey) {
    std::vector<uint8_t> shared_secret(32);
    for (size_t i = 0; i < 32; i++) shared_secret[i] = static_cast<uint8_t>(i * 3);
    
    auto key1 = HKDF::derive_session_key(shared_secret, 100, 200);
    auto key2 = HKDF::derive_session_key(shared_secret, 200, 100);  // Order reversed
    
    // Should produce same key regardless of node ID order
    EXPECT_EQ(key1, key2);
    
    // Different node IDs should produce different key
    auto key3 = HKDF::derive_session_key(shared_secret, 100, 300);
    EXPECT_NE(key1, key3);
}

// Integration test: Full key exchange flow
TEST_F(CryptoTest, FullKeyExchangeFlow) {
    // Node A generates identity key (Ed25519) and session key (X25519)
    auto [id_pub_a, id_priv_a] = Ed25519::generate_keypair();
    auto [sess_pub_a, sess_priv_a] = X25519::generate_keypair();
    
    // Node B generates identity key (Ed25519) and session key (X25519)
    auto [id_pub_b, id_priv_b] = Ed25519::generate_keypair();
    auto [sess_pub_b, sess_priv_b] = X25519::generate_keypair();
    
    // Node IDs
    uint32_t node_a_id = 1;
    uint32_t node_b_id = 2;
    
    // A signs its session public key
    std::vector<uint8_t> sess_pub_a_vec(sess_pub_a.begin(), sess_pub_a.end());
    auto sig_a = Ed25519::sign(id_priv_a, std::span<const uint8_t>(sess_pub_a_vec));
    
    // B verifies A's signature
    EXPECT_TRUE(Ed25519::verify(id_pub_a, std::span<const uint8_t>(sess_pub_a_vec), sig_a));
    
    // Both sides compute shared secret
    auto shared_a = X25519::compute_shared_secret(sess_priv_a, sess_pub_b);
    auto shared_b = X25519::compute_shared_secret(sess_priv_b, sess_pub_a);
    
    ASSERT_TRUE(shared_a.has_value());
    ASSERT_TRUE(shared_b.has_value());
    EXPECT_EQ(*shared_a, *shared_b);
    
    // Derive session keys
    auto session_key_a = HKDF::derive_session_key(*shared_a, node_a_id, node_b_id);
    auto session_key_b = HKDF::derive_session_key(*shared_b, node_a_id, node_b_id);
    
    EXPECT_EQ(session_key_a, session_key_b);
    
    // Encrypt message from A to B
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'B', '!'};
    auto encrypted = ChaCha20Poly1305::encrypt(session_key_a, std::span<const uint8_t>(message));
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt on B's side
    auto decrypted = ChaCha20Poly1305::decrypt(session_key_b, std::span<const uint8_t>(*encrypted));
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, message);
}
