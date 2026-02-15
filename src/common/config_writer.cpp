#include "common/config_writer.hpp"
#include "common/config_metadata.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>

namespace json = boost::json;

namespace edgelink {

JsonConfigWriter::JsonConfigWriter(const std::string& file_path) : file_path_(file_path) {}

bool JsonConfigWriter::load() {
    std::ifstream file(file_path_);
    if (!file.is_open()) {
        // 文件不存在时从空对象开始
        root_ = json::object{};
        loaded_ = true;
        return true;
    }

    try {
        std::stringstream buffer;
        buffer << file.rdbuf();
        auto jv = json::parse(buffer.str());
        root_ = jv.as_object();
        loaded_ = true;
        return true;
    } catch (const std::exception& e) {
        last_error_ = std::string("JSON parse error: ") + e.what();
        return false;
    }
}

std::pair<std::string, std::string> JsonConfigWriter::parse_path(const std::string& path) const {
    auto dot = path.find('.');
    if (dot == std::string::npos)
        return {"", path};
    return {path.substr(0, dot), path.substr(dot + 1)};
}

json::object& JsonConfigWriter::ensure_section(const std::string& section) {
    if (section.empty())
        return root_;
    auto it = root_.find(section);
    if (it == root_.end() || !it->value().is_object()) {
        root_[section] = json::object{};
    }
    return root_[section].as_object();
}

json::value JsonConfigWriter::typed_value(const std::string& key, const std::string& value) const {
    // 查询 config_metadata 获取类型信息
    auto meta = get_config_metadata(key);
    if (meta) {
        switch (meta->type) {
            case ConfigType::Bool:
                return json::value(value == "true" || value == "1");
            case ConfigType::Int:
                try { return json::value(std::stoll(value)); }
                catch (...) { return json::value(value); }
            default:
                break;
        }
    } else {
        // 无元数据时，自动推断
        if (value == "true") return json::value(true);
        if (value == "false") return json::value(false);
        try {
            auto n = std::stoll(value);
            // 确保不是包含非数字字符的字符串
            if (std::to_string(n) == value)
                return json::value(n);
        } catch (...) {}
    }
    return json::value(value);
}

bool JsonConfigWriter::set_value(const std::string& path, const std::string& value) {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    auto [section, key] = parse_path(path);
    auto& obj = ensure_section(section);
    obj[key] = typed_value(path, value);
    return true;
}

bool JsonConfigWriter::set_array(const std::string& path, const std::vector<std::string>& values) {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    auto [section, key] = parse_path(path);
    auto& obj = ensure_section(section);
    json::array arr;
    for (const auto& v : values)
        arr.emplace_back(v);
    obj[key] = std::move(arr);
    return true;
}

std::optional<std::string> JsonConfigWriter::get_value(const std::string& path) const {
    if (!loaded_)
        return std::nullopt;

    auto [section, key] = parse_path(path);
    const json::object* obj = &root_;
    if (!section.empty()) {
        auto it = root_.find(section);
        if (it == root_.end() || !it->value().is_object())
            return std::nullopt;
        obj = &it->value().as_object();
    }

    auto it = obj->find(key);
    if (it == obj->end())
        return std::nullopt;

    const auto& val = it->value();
    if (val.is_string()) return std::string(val.as_string());
    if (val.is_bool()) return val.as_bool() ? std::string("true") : std::string("false");
    if (val.is_int64()) return std::to_string(val.as_int64());
    if (val.is_uint64()) return std::to_string(val.as_uint64());
    return json::serialize(val);
}

bool JsonConfigWriter::has_key(const std::string& path) const {
    if (!loaded_)
        return false;

    auto [section, key] = parse_path(path);
    const json::object* obj = &root_;
    if (!section.empty()) {
        auto it = root_.find(section);
        if (it == root_.end() || !it->value().is_object())
            return false;
        obj = &it->value().as_object();
    }
    return obj->find(key) != obj->end();
}

bool JsonConfigWriter::save() {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    auto temp_path = file_path_ + ".tmp";

    {
        std::ofstream file(temp_path);
        if (!file.is_open()) {
            last_error_ = "无法创建临时文件: " + temp_path;
            return false;
        }
        file << json::serialize(root_);
    }

    try {
        std::filesystem::rename(temp_path, file_path_);
    } catch (const std::exception& e) {
        last_error_ = "无法替换文件: " + std::string(e.what());
        std::filesystem::remove(temp_path);
        return false;
    }

    return true;
}

}  // namespace edgelink
