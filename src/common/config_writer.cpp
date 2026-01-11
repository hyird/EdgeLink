#include "common/config_writer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <random>

namespace edgelink {

TomlConfigWriter::TomlConfigWriter(const std::string& file_path) : file_path_(file_path) {}

bool TomlConfigWriter::load() {
    std::ifstream file(file_path_);
    if (!file.is_open()) {
        last_error_ = "无法打开文件: " + file_path_;
        return false;
    }

    lines_.clear();
    std::string line;
    while (std::getline(file, line)) {
        LineInfo info;
        info.text = line;
        lines_.push_back(std::move(info));
    }

    parse_lines();
    loaded_ = true;
    return true;
}

void TomlConfigWriter::parse_lines() {
    std::string current_section;

    for (size_t i = 0; i < lines_.size(); ++i) {
        auto& info = lines_[i];
        const std::string& line = info.text;

        // 跳过空行
        size_t first_non_space = line.find_first_not_of(" \t");
        if (first_non_space == std::string::npos) {
            info.is_empty = true;
            info.section = current_section;
            continue;
        }

        // 检查是否是注释行
        if (line[first_non_space] == '#') {
            info.is_comment = true;
            info.section = current_section;

            // 检查是否是被注释掉的配置项（如 # key = value）
            std::string comment_content = line.substr(first_non_space + 1);
            size_t eq_pos = comment_content.find('=');
            if (eq_pos != std::string::npos) {
                size_t key_start = comment_content.find_first_not_of(" \t");
                if (key_start != std::string::npos && key_start < eq_pos) {
                    size_t key_end = comment_content.find_last_not_of(" \t", eq_pos - 1);
                    if (key_end != std::string::npos && key_end >= key_start) {
                        std::string potential_key = comment_content.substr(key_start, key_end - key_start + 1);
                        // 简单验证：key 只包含字母、数字和下划线
                        bool valid_key = !potential_key.empty() && std::all_of(
                            potential_key.begin(), potential_key.end(),
                            [](char c) { return std::isalnum(c) || c == '_'; });
                        if (valid_key) {
                            info.is_commented_out = true;
                            info.key = potential_key;
                        }
                    }
                }
            }
            continue;
        }

        // 检查是否是 section 行
        if (line[first_non_space] == '[') {
            size_t end_bracket = line.find(']', first_non_space);
            if (end_bracket != std::string::npos) {
                current_section = line.substr(first_non_space + 1, end_bracket - first_non_space - 1);
                info.is_section = true;
                info.section = current_section;
                continue;
            }
        }

        // 解析 key = value
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
            // 提取 key
            size_t key_end = line.find_last_not_of(" \t", eq_pos - 1);
            if (key_end != std::string::npos && key_end >= first_non_space) {
                info.key = line.substr(first_non_space, key_end - first_non_space + 1);
            }

            info.section = current_section;

            // 找到 value 的起始和结束位置
            size_t value_start = line.find_first_not_of(" \t", eq_pos + 1);
            if (value_start != std::string::npos) {
                info.value_start = value_start;

                // 处理字符串值
                if (line[value_start] == '"') {
                    // 找到匹配的结束引号
                    size_t quote_end = value_start + 1;
                    while (quote_end < line.size()) {
                        if (line[quote_end] == '"' && line[quote_end - 1] != '\\') {
                            break;
                        }
                        ++quote_end;
                    }
                    info.value_end = quote_end < line.size() ? quote_end + 1 : line.size();
                }
                // 处理数组
                else if (line[value_start] == '[') {
                    size_t bracket_count = 1;
                    size_t pos = value_start + 1;
                    while (pos < line.size() && bracket_count > 0) {
                        if (line[pos] == '[')
                            ++bracket_count;
                        else if (line[pos] == ']')
                            --bracket_count;
                        ++pos;
                    }
                    info.value_end = pos;
                }
                // 处理其他值（数字、布尔等）
                else {
                    // 找到注释或行尾
                    size_t comment_pos = line.find('#', value_start);
                    if (comment_pos != std::string::npos) {
                        // 去掉值后面的空格
                        size_t value_end = line.find_last_not_of(" \t", comment_pos - 1);
                        info.value_end = value_end != std::string::npos ? value_end + 1 : comment_pos;
                    } else {
                        info.value_end = line.find_last_not_of(" \t\r\n") + 1;
                    }
                }
            }
        }
    }
}

std::pair<std::string, std::string> TomlConfigWriter::parse_path(const std::string& path) const {
    size_t dot_pos = path.find('.');
    if (dot_pos == std::string::npos) {
        return {"", path};  // 无 section
    }
    return {path.substr(0, dot_pos), path.substr(dot_pos + 1)};
}

int TomlConfigWriter::find_key_line(const std::string& section, const std::string& key) const {
    for (size_t i = 0; i < lines_.size(); ++i) {
        const auto& info = lines_[i];
        if (info.section == section && info.key == key && !info.is_comment) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int TomlConfigWriter::find_section_end(const std::string& section) const {
    int last_line = -1;
    bool in_section = false;

    for (size_t i = 0; i < lines_.size(); ++i) {
        const auto& info = lines_[i];
        if (info.is_section) {
            if (info.section == section) {
                in_section = true;
                last_line = static_cast<int>(i);
            } else if (in_section) {
                // 遇到下一个 section，返回上一个非空行
                break;
            }
        } else if (in_section && !info.is_empty) {
            last_line = static_cast<int>(i);
        }
    }

    return last_line;
}

int TomlConfigWriter::find_or_create_section(const std::string& section) {
    // 查找现有 section
    for (size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].is_section && lines_[i].section == section) {
            return find_section_end(section);
        }
    }

    // 创建新 section
    LineInfo empty_line;
    empty_line.is_empty = true;
    lines_.push_back(empty_line);

    LineInfo section_line;
    section_line.text = "[" + section + "]";
    section_line.section = section;
    section_line.is_section = true;
    lines_.push_back(section_line);

    return static_cast<int>(lines_.size()) - 1;
}

std::string TomlConfigWriter::format_value(const std::string& value) const {
    // 检查是否是布尔值
    if (value == "true" || value == "false") {
        return value;
    }

    // 检查是否是数字
    bool is_number = !value.empty() && std::all_of(value.begin(), value.end(), [](char c) {
        return std::isdigit(c) || c == '-' || c == '.';
    });
    if (is_number) {
        return value;
    }

    // 字符串值需要加引号
    std::string result = "\"";
    for (char c : value) {
        if (c == '"') {
            result += "\\\"";
        } else if (c == '\\') {
            result += "\\\\";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

std::string TomlConfigWriter::format_array(const std::vector<std::string>& values) const {
    if (values.empty()) {
        return "[]";
    }

    std::string result = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0)
            result += ", ";
        result += format_value(values[i]);
    }
    result += "]";
    return result;
}

bool TomlConfigWriter::set_value(const std::string& path, const std::string& value) {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    auto [section, key] = parse_path(path);
    int line_idx = find_key_line(section, key);

    std::string formatted_value = format_value(value);

    if (line_idx >= 0) {
        // 修改现有行
        auto& info = lines_[line_idx];
        std::string& line = info.text;

        // 保留行尾注释
        std::string tail;
        if (info.value_end < line.size()) {
            tail = line.substr(info.value_end);
        }

        // 重建行
        line = line.substr(0, info.value_start) + formatted_value + tail;

        // 更新 value 位置
        info.value_end = info.value_start + formatted_value.size();
    } else {
        // 添加新行
        int section_end = find_or_create_section(section);

        LineInfo new_line;
        new_line.text = key + " = " + formatted_value;
        new_line.section = section;
        new_line.key = key;
        new_line.value_start = key.size() + 3;
        new_line.value_end = new_line.text.size();

        if (section_end >= 0 && section_end < static_cast<int>(lines_.size()) - 1) {
            lines_.insert(lines_.begin() + section_end + 1, new_line);
        } else {
            lines_.push_back(new_line);
        }
    }

    return true;
}

bool TomlConfigWriter::set_array(const std::string& path, const std::vector<std::string>& values) {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    auto [section, key] = parse_path(path);
    int line_idx = find_key_line(section, key);

    std::string formatted_value = format_array(values);

    if (line_idx >= 0) {
        // 修改现有行
        auto& info = lines_[line_idx];
        std::string& line = info.text;

        // 保留行尾注释
        std::string tail;
        if (info.value_end < line.size()) {
            tail = line.substr(info.value_end);
        }

        // 重建行
        line = line.substr(0, info.value_start) + formatted_value + tail;
        info.value_end = info.value_start + formatted_value.size();
    } else {
        // 添加新行
        int section_end = find_or_create_section(section);

        LineInfo new_line;
        new_line.text = key + " = " + formatted_value;
        new_line.section = section;
        new_line.key = key;
        new_line.value_start = key.size() + 3;
        new_line.value_end = new_line.text.size();

        if (section_end >= 0 && section_end < static_cast<int>(lines_.size()) - 1) {
            lines_.insert(lines_.begin() + section_end + 1, new_line);
        } else {
            lines_.push_back(new_line);
        }
    }

    return true;
}

std::optional<std::string> TomlConfigWriter::get_value(const std::string& path) const {
    if (!loaded_) {
        return std::nullopt;
    }

    auto [section, key] = parse_path(path);
    int line_idx = find_key_line(section, key);

    if (line_idx < 0) {
        return std::nullopt;
    }

    const auto& info = lines_[line_idx];
    if (info.value_start >= info.text.size()) {
        return std::nullopt;
    }

    std::string value = info.text.substr(info.value_start, info.value_end - info.value_start);

    // 去除字符串引号
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }

    return value;
}

bool TomlConfigWriter::has_key(const std::string& path) const {
    if (!loaded_) {
        return false;
    }

    auto [section, key] = parse_path(path);
    return find_key_line(section, key) >= 0;
}

bool TomlConfigWriter::save() {
    if (!loaded_) {
        last_error_ = "文件未加载";
        return false;
    }

    // 生成临时文件名
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10000, 99999);
    std::string temp_path = file_path_ + ".tmp." + std::to_string(dis(gen));

    // 写入临时文件
    {
        std::ofstream file(temp_path);
        if (!file.is_open()) {
            last_error_ = "无法创建临时文件: " + temp_path;
            return false;
        }

        for (size_t i = 0; i < lines_.size(); ++i) {
            file << lines_[i].text;
            if (i < lines_.size() - 1) {
                file << "\n";
            }
        }
    }

    // 原子替换
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
