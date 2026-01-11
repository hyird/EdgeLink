#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace edgelink {

// TOML 配置文件写入器，支持保留注释
class TomlConfigWriter {
public:
    explicit TomlConfigWriter(const std::string& file_path);

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
    // 行信息
    struct LineInfo {
        std::string text;           // 完整行文本
        std::string section;        // 所属 section（如 "log"）
        std::string key;            // key 名称（如 "level"）
        size_t value_start = 0;     // value 起始位置
        size_t value_end = 0;       // value 结束位置（不含行尾注释）
        bool is_section = false;    // 是否是 section 行
        bool is_comment = false;    // 是否是注释行
        bool is_empty = false;      // 是否是空行
        bool is_commented_out = false;  // 是否是被注释掉的配置项
    };

    // 解析文件内容
    void parse_lines();

    // 查找配置项的行号
    int find_key_line(const std::string& section, const std::string& key) const;

    // 查找 section 的最后一行
    int find_section_end(const std::string& section) const;

    // 查找或创建 section
    int find_or_create_section(const std::string& section);

    // 格式化值为 TOML 格式
    std::string format_value(const std::string& value) const;
    std::string format_array(const std::vector<std::string>& values) const;

    // 解析路径为 section 和 key
    std::pair<std::string, std::string> parse_path(const std::string& path) const;

    std::string file_path_;
    std::vector<LineInfo> lines_;
    std::string last_error_;
    bool loaded_ = false;
};

}  // namespace edgelink
