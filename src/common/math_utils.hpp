#pragma once

#include <cstdint>

namespace edgelink {

// 指数移动平均（Exponential Moving Average）计算
// old_value: 旧的平均值
// new_value: 新的样本值
// weight: 权重因子（默认为 7/8，即新值权重为 1/8）
template<typename T>
inline T exponential_moving_average(T old_value, T new_value, T weight = 7) {
    if (old_value == 0) {
        return new_value;
    }
    return (old_value * weight + new_value) / (weight + 1);
}

} // namespace edgelink
