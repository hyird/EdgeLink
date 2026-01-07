// Minimal jwt-cpp stub for compilation testing
#pragma once
#include <string>
#include <chrono>
#include <map>
#include <stdexcept>
#include <vector>
#include <picojson/picojson.h>

namespace jwt {

namespace error {
    struct token_verification_exception : public std::runtime_error {
        token_verification_exception() : std::runtime_error("Token verification failed") {}
    };
}

namespace algorithm {
    struct hs256 {
        hs256(const std::string& secret) : secret_(secret) {}
        std::string secret_;
    };
    struct rs256 {
        rs256(const std::string& public_key, const std::string& private_key = "", 
              const std::string& public_key_password = "", const std::string& private_key_password = "") {}
    };
}

struct claim {
    claim() = default;
    claim(const std::string& s) : str_value_(s), is_string_(true) {}
    claim(int64_t i) : int_value_(i), is_int_(true) {}
    claim(const picojson::value& v) : json_value_(v), is_json_(true) {}
    claim(const std::vector<std::string>& arr) : str_arr_value_(arr), is_str_array_(true) {}
    claim(const std::vector<int64_t>& arr) {
        for (auto v : arr) int_arr_value_.push_back(v);
        is_int_array_ = true;
    }
    
    std::string as_string() const { return str_value_; }
    int64_t as_integer() const { 
        if (is_json_) return static_cast<int64_t>(json_value_.get_double());
        return int_value_; 
    }
    
    // Return int64_t array for relay_ids etc.
    std::vector<int64_t> as_array() const { return int_arr_value_; }
    
    picojson::value to_json() const { return json_value_; }
    
private:
    std::string str_value_;
    int64_t int_value_{0};
    std::vector<std::string> str_arr_value_;
    std::vector<int64_t> int_arr_value_;
    picojson::value json_value_;
    bool is_string_{false};
    bool is_int_{false};
    bool is_str_array_{false};
    bool is_int_array_{false};
    bool is_json_{false};
};

struct decoded_jwt {
    bool has_payload_claim(const std::string& name) const { 
        return claims_.find(name) != claims_.end(); 
    }
    
    claim get_payload_claim(const std::string& name) const { 
        auto it = claims_.find(name);
        if (it != claims_.end()) return it->second;
        return claim{};
    }
    
    std::string get_id() const { return jti_; }
    std::chrono::system_clock::time_point get_issued_at() const { return iat_; }
    std::chrono::system_clock::time_point get_expires_at() const { return exp_; }
    
    std::map<std::string, claim> claims_;
    std::string jti_;
    std::chrono::system_clock::time_point iat_;
    std::chrono::system_clock::time_point exp_;
};

template<typename Clock = std::chrono::system_clock>
struct verifier {
    verifier& allow_algorithm(const algorithm::hs256&) { return *this; }
    verifier& allow_algorithm(const algorithm::rs256&) { return *this; }
    verifier& with_issuer(const std::string& iss) { return *this; }
    verifier& with_type(const std::string& type) { return *this; }
    verifier& leeway(std::chrono::seconds s) { return *this; }
    void verify(const decoded_jwt& jwt) const {}
};

template<typename Clock = std::chrono::system_clock>
struct builder {
    builder& set_issuer(const std::string& iss) { return *this; }
    builder& set_subject(const std::string& sub) { return *this; }
    builder& set_audience(const std::string& aud) { return *this; }
    builder& set_type(const std::string& type) { return *this; }
    builder& set_id(const std::string& id) { return *this; }
    builder& set_issued_at(std::chrono::system_clock::time_point tp) { return *this; }
    builder& set_expires_at(std::chrono::system_clock::time_point tp) { return *this; }
    builder& set_payload_claim(const std::string& name, const claim& c) { return *this; }
    std::string sign(const algorithm::hs256&) const { return "stub.jwt.token"; }
    std::string sign(const algorithm::rs256&) const { return "stub.jwt.token"; }
};

inline decoded_jwt decode(const std::string& token) { return decoded_jwt{}; }

template<typename Clock = std::chrono::system_clock>
inline verifier<Clock> verify() { return verifier<Clock>{}; }

template<typename Clock = std::chrono::system_clock>
inline builder<Clock> create() { return builder<Clock>{}; }

} // namespace jwt
