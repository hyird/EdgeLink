# picojson

A header-only JSON parser/serializer in C++.

## Source

- **Repository**: https://github.com/kazuho/picojson
- **License**: BSD 2-Clause

## Note

This is a **stub implementation** for compilation testing. For production use,
replace with the actual picojson library:

```bash
# Manual installation
git clone https://github.com/kazuho/picojson.git
cp picojson/picojson.h /path/to/project/third_party/picojson/include/picojson/
```

## Usage

```cpp
#include <picojson/picojson.h>

// Parse JSON
picojson::value v;
std::string err = picojson::parse(v, json_string);

// Access values
if (v.is<picojson::object>()) {
    auto& obj = v.get<picojson::object>();
    std::string name = obj["name"].get<std::string>();
    double value = obj["value"].get<double>();
}

// Serialize
std::string output = v.serialize();
```

## Note on jwt-cpp

This library is used as the JSON backend for jwt-cpp. The jwt-cpp library
supports multiple JSON backends including picojson, nlohmann/json, and
boost::json.
