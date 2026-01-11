#pragma once

#include <string>
#include <vector>
#include <optional>

namespace edgelink {

// 配置项类型
enum class ConfigType {
    String,       // 字符串
    Int,          // 整数
    Bool,         // 布尔值
    StringArray,  // 字符串数组
};

// 配置项元数据
struct ConfigMetadata {
    std::string key;           // 配置路径，如 "log.level"
    ConfigType type;           // 值类型
    std::string description;   // 描述
    bool hot_reloadable;       // 是否支持热重载
    std::string default_value; // 默认值（字符串表示）
};

// 获取所有配置元数据
const std::vector<ConfigMetadata>& get_all_config_metadata();

// 获取单个配置的元数据
std::optional<ConfigMetadata> get_config_metadata(const std::string& key);

// 判断配置项是否可热重载
bool is_hot_reloadable(const std::string& key);

// 获取配置类型的字符串表示
std::string config_type_to_string(ConfigType type);

// 验证配置值是否有效
bool validate_config_value(const std::string& key, const std::string& value);

}  // namespace edgelink
