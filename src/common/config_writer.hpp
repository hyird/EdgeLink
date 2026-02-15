#pragma once

#include <string>
#include <vector>
#include <optional>
#include <boost/json.hpp>

namespace edgelink {

// JSON 配置文件写入器
class JsonConfigWriter {
public:
    explicit JsonConfigWriter(const std::string& file_path);

    // 加载文件内容
    bool load();

    // 设置单个值（路径格式如 "log.level"）
    bool set_value(const std::string& path, const std::string& value);

    // 设置字符串数组
    bool set_array(const std::string& path, const std::vector<std::string>& values);

    // 保存到文件（原子写入：先写临时文件再 rename）
    bool save();

    // 获取当前值
    std::optional<std::string> get_value(const std::string& path) const;

    // 检查配置项是否存在
    bool has_key(const std::string& path) const;

    // 获取错误信息
    const std::string& last_error() const { return last_error_; }

private:
    // 解析 dot-path 为 section 和 key
    std::pair<std::string, std::string> parse_path(const std::string& path) const;

    // 获取或创建嵌套对象
    boost::json::object& ensure_section(const std::string& section);

    // 根据 config_metadata 类型信息将字符串转为正确的 JSON 值
    boost::json::value typed_value(const std::string& key, const std::string& value) const;

    std::string file_path_;
    boost::json::object root_;
    std::string last_error_;
    bool loaded_ = false;
};

}  // namespace edgelink
