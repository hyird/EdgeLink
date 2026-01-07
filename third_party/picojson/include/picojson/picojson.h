// Minimal picojson stub for compilation testing
#pragma once
#include <string>
#include <vector>
#include <map>

namespace picojson {

class value;
using array = std::vector<value>;
using object = std::map<std::string, value>;

class value {
public:
    value() = default;
    value(double d) : num_(d), type_(NUMBER) {}
    value(const std::string& s) : str_(s), type_(STRING) {}
    value(const array& a) : arr_(a), type_(ARRAY) {}
    value(const object& o) : obj_(o), type_(OBJECT) {}
    value(bool b) : bool_(b), type_(BOOLEAN) {}
    
    template<typename T>
    bool is() const {
        if constexpr (std::is_same_v<T, double>) return type_ == NUMBER;
        if constexpr (std::is_same_v<T, std::string>) return type_ == STRING;
        if constexpr (std::is_same_v<T, array>) return type_ == ARRAY;
        if constexpr (std::is_same_v<T, object>) return type_ == OBJECT;
        if constexpr (std::is_same_v<T, bool>) return type_ == BOOLEAN;
        return false;
    }
    
    template<typename T>
    T get() const {
        if constexpr (std::is_same_v<T, double>) return num_;
        if constexpr (std::is_same_v<T, std::string>) return str_;
        if constexpr (std::is_same_v<T, array>) return arr_;
        if constexpr (std::is_same_v<T, object>) return obj_;
        if constexpr (std::is_same_v<T, bool>) return bool_;
        return T{};
    }
    
    double get_double() const { return num_; }
    const std::string& get_string() const { return str_; }
    const array& get_array() const { return arr_; }
    const object& get_object() const { return obj_; }
    bool get_bool() const { return bool_; }
    
private:
    enum Type { NONE, NUMBER, STRING, ARRAY, OBJECT, BOOLEAN };
    
    double num_{0};
    std::string str_;
    array arr_;
    object obj_;
    bool bool_{false};
    Type type_{NONE};
};

} // namespace picojson
