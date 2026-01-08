#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>
#include <cassert>

namespace edgelink {

// ============================================================================
// Fixed-Size Block Pool
// ============================================================================

template<size_t BlockSize, size_t PoolSize = 256>
class FixedBlockPool {
public:
    FixedBlockPool() {
        // Initialize free list
        for (size_t i = 0; i < PoolSize - 1; ++i) {
            blocks_[i].next = &blocks_[i + 1];
        }
        blocks_[PoolSize - 1].next = nullptr;
        free_list_ = &blocks_[0];
    }

    void* allocate() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (free_list_ == nullptr) {
            // Pool exhausted, fall back to heap
            return ::operator new(BlockSize);
        }
        Block* block = free_list_;
        free_list_ = block->next;
        ++allocated_;
        return block->data;
    }

    void deallocate(void* ptr) {
        if (!ptr) return;

        // Check if ptr is from our pool
        auto* data = static_cast<uint8_t*>(ptr);
        bool from_pool = false;

        for (size_t i = 0; i < PoolSize; ++i) {
            if (data == blocks_[i].data) {
                from_pool = true;
                break;
            }
        }

        if (from_pool) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto* block = reinterpret_cast<Block*>(data);
            block->next = free_list_;
            free_list_ = block;
            --allocated_;
        } else {
            // Was allocated from heap
            ::operator delete(ptr);
        }
    }

    size_t allocated() const { return allocated_.load(); }
    size_t capacity() const { return PoolSize; }

private:
    union Block {
        uint8_t data[BlockSize];
        Block* next;
    };

    std::array<Block, PoolSize> blocks_;
    Block* free_list_;
    std::mutex mutex_;
    std::atomic<size_t> allocated_{0};
};

// ============================================================================
// Buffer Pool for Variable-Size Allocations
// ============================================================================

class BufferPool {
public:
    // Pool configuration
    struct Config {
        size_t small_size{256};       // Small buffer size
        size_t medium_size{1500};     // Medium (MTU) buffer size
        size_t large_size{65536};     // Large buffer size
        size_t small_count{512};      // Number of small buffers
        size_t medium_count{256};     // Number of medium buffers
        size_t large_count{64};       // Number of large buffers
    };

    explicit BufferPool(const Config& config = {}) : config_(config) {
        // Pre-allocate buffers
        small_buffers_.reserve(config_.small_count);
        medium_buffers_.reserve(config_.medium_count);
        large_buffers_.reserve(config_.large_count);

        for (size_t i = 0; i < config_.small_count; ++i) {
            small_buffers_.push_back(std::make_unique<std::vector<uint8_t>>(config_.small_size));
        }
        for (size_t i = 0; i < config_.medium_count; ++i) {
            medium_buffers_.push_back(std::make_unique<std::vector<uint8_t>>(config_.medium_size));
        }
        for (size_t i = 0; i < config_.large_count; ++i) {
            large_buffers_.push_back(std::make_unique<std::vector<uint8_t>>(config_.large_size));
        }
    }

    // Get a buffer of at least the specified size
    std::unique_ptr<std::vector<uint8_t>> acquire(size_t min_size) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (min_size <= config_.small_size && !small_buffers_.empty()) {
            auto buf = std::move(small_buffers_.back());
            small_buffers_.pop_back();
            buf->resize(min_size);
            return buf;
        }

        if (min_size <= config_.medium_size && !medium_buffers_.empty()) {
            auto buf = std::move(medium_buffers_.back());
            medium_buffers_.pop_back();
            buf->resize(min_size);
            return buf;
        }

        if (min_size <= config_.large_size && !large_buffers_.empty()) {
            auto buf = std::move(large_buffers_.back());
            large_buffers_.pop_back();
            buf->resize(min_size);
            return buf;
        }

        // Fall back to heap allocation
        ++heap_allocations_;
        return std::make_unique<std::vector<uint8_t>>(min_size);
    }

    // Return a buffer to the pool
    void release(std::unique_ptr<std::vector<uint8_t>> buffer) {
        if (!buffer) return;

        std::lock_guard<std::mutex> lock(mutex_);

        size_t capacity = buffer->capacity();

        if (capacity <= config_.small_size && small_buffers_.size() < config_.small_count) {
            buffer->clear();
            buffer->reserve(config_.small_size);
            small_buffers_.push_back(std::move(buffer));
            return;
        }

        if (capacity <= config_.medium_size && medium_buffers_.size() < config_.medium_count) {
            buffer->clear();
            buffer->reserve(config_.medium_size);
            medium_buffers_.push_back(std::move(buffer));
            return;
        }

        if (capacity <= config_.large_size && large_buffers_.size() < config_.large_count) {
            buffer->clear();
            buffer->reserve(config_.large_size);
            large_buffers_.push_back(std::move(buffer));
            return;
        }

        // Buffer doesn't fit in any pool, let it be destroyed
    }

    // Statistics
    struct Stats {
        size_t small_available;
        size_t medium_available;
        size_t large_available;
        size_t heap_allocations;
    };

    Stats stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {
            small_buffers_.size(),
            medium_buffers_.size(),
            large_buffers_.size(),
            heap_allocations_.load()
        };
    }

private:
    Config config_;
    mutable std::mutex mutex_;

    std::vector<std::unique_ptr<std::vector<uint8_t>>> small_buffers_;
    std::vector<std::unique_ptr<std::vector<uint8_t>>> medium_buffers_;
    std::vector<std::unique_ptr<std::vector<uint8_t>>> large_buffers_;

    std::atomic<size_t> heap_allocations_{0};
};

// ============================================================================
// Pooled Buffer RAII Wrapper
// ============================================================================

class PooledBuffer {
public:
    PooledBuffer() = default;

    PooledBuffer(BufferPool& pool, size_t size)
        : pool_(&pool), buffer_(pool.acquire(size)) {}

    ~PooledBuffer() {
        if (pool_ && buffer_) {
            pool_->release(std::move(buffer_));
        }
    }

    // Move only
    PooledBuffer(PooledBuffer&& other) noexcept
        : pool_(other.pool_), buffer_(std::move(other.buffer_)) {
        other.pool_ = nullptr;
    }

    PooledBuffer& operator=(PooledBuffer&& other) noexcept {
        if (this != &other) {
            if (pool_ && buffer_) {
                pool_->release(std::move(buffer_));
            }
            pool_ = other.pool_;
            buffer_ = std::move(other.buffer_);
            other.pool_ = nullptr;
        }
        return *this;
    }

    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer& operator=(const PooledBuffer&) = delete;

    // Access
    std::vector<uint8_t>* operator->() { return buffer_.get(); }
    const std::vector<uint8_t>* operator->() const { return buffer_.get(); }
    std::vector<uint8_t>& operator*() { return *buffer_; }
    const std::vector<uint8_t>& operator*() const { return *buffer_; }

    uint8_t* data() { return buffer_ ? buffer_->data() : nullptr; }
    const uint8_t* data() const { return buffer_ ? buffer_->data() : nullptr; }
    size_t size() const { return buffer_ ? buffer_->size() : 0; }

    explicit operator bool() const { return buffer_ != nullptr; }

    // Release ownership without returning to pool
    std::unique_ptr<std::vector<uint8_t>> release() {
        pool_ = nullptr;
        return std::move(buffer_);
    }

private:
    BufferPool* pool_{nullptr};
    std::unique_ptr<std::vector<uint8_t>> buffer_;
};

// ============================================================================
// Global Buffer Pool (optional)
// ============================================================================

inline BufferPool& global_buffer_pool() {
    static BufferPool instance;
    return instance;
}

} // namespace edgelink
