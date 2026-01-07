# jwt-cpp

A header-only library for creating and validating JSON Web Tokens in C++.

## Source

- **Repository**: https://github.com/Thalhammer/jwt-cpp
- **License**: MIT

## Note

This is a **stub implementation** for compilation testing. For production use,
replace with the actual jwt-cpp library:

```bash
# Option 1: System package (if available)
sudo apt install libjwt-cpp-dev

# Option 2: Manual installation
git clone https://github.com/Thalhammer/jwt-cpp.git
cp -r jwt-cpp/include/jwt-cpp /path/to/project/third_party/jwt-cpp/include/
```

## Usage

```cpp
#include <jwt-cpp/jwt.h>

// Create token
auto token = jwt::create()
    .set_issuer("edgelink")
    .set_type("JWT")
    .set_payload_claim("user_id", jwt::claim(std::string("123")))
    .sign(jwt::algorithm::hs256{"secret"});

// Verify token
auto decoded = jwt::decode(token);
auto verifier = jwt::verify()
    .allow_algorithm(jwt::algorithm::hs256{"secret"})
    .with_issuer("edgelink");
verifier.verify(decoded);
```
