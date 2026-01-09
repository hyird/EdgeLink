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

// ============================================================================
// Lock-Free Block Pool
// ============================================================================

template<size_t BlockSize, size_t PoolSize = 256>
class LockFreeBlockPool {
public:
    LockFreeBlockPool() {
        // Initialize blocks array
        for (size_t i = 0; i < PoolSize; ++i) {
            blocks_[i].in_pool = true;
        }

        // Build free list using tagged pointers
        TaggedPtr initial{&blocks_[0], 0};
        for (size_t i = 0; i < PoolSize - 1; ++i) {
            blocks_[i].next.store({&blocks_[i + 1], 0}, std::memory_order_relaxed);
        }
        blocks_[PoolSize - 1].next.store({nullptr, 0}, std::memory_order_relaxed);
        free_list_.store(initial, std::memory_order_release);
    }

    void* allocate() {
        TaggedPtr old_head = free_list_.load(std::memory_order_acquire);

        while (true) {
            if (old_head.ptr == nullptr) {
                // Pool exhausted, fall back to heap
                heap_allocations_.fetch_add(1, std::memory_order_relaxed);
                return ::operator new(BlockSize);
            }

            TaggedPtr new_head = old_head.ptr->next.load(std::memory_order_relaxed);
            // Increment tag to prevent ABA problem
            new_head.tag = old_head.tag + 1;

            if (free_list_.compare_exchange_weak(old_head, new_head,
                    std::memory_order_release, std::memory_order_acquire)) {
                allocated_.fetch_add(1, std::memory_order_relaxed);
                return old_head.ptr->data;
            }
            // CAS failed, old_head was updated, retry
        }
    }

    void deallocate(void* ptr) {
        if (!ptr) return;

        // Check if ptr is from our pool
        auto* data = static_cast<uint8_t*>(ptr);
        Block* block = nullptr;

        for (size_t i = 0; i < PoolSize; ++i) {
            if (data == blocks_[i].data) {
                block = &blocks_[i];
                break;
            }
        }

        if (block) {
            // Return to pool using CAS
            TaggedPtr old_head = free_list_.load(std::memory_order_acquire);

            while (true) {
                block->next.store(old_head, std::memory_order_relaxed);
                TaggedPtr new_head{block, old_head.tag + 1};

                if (free_list_.compare_exchange_weak(old_head, new_head,
                        std::memory_order_release, std::memory_order_acquire)) {
                    allocated_.fetch_sub(1, std::memory_order_relaxed);
                    return;
                }
                // CAS failed, old_head was updated, retry
            }
        } else {
            // Was allocated from heap
            ::operator delete(ptr);
        }
    }

    size_t allocated() const { return allocated_.load(std::memory_order_relaxed); }
    size_t heap_allocations() const { return heap_allocations_.load(std::memory_order_relaxed); }
    size_t capacity() const { return PoolSize; }

private:
    // Tagged pointer to solve ABA problem
    struct TaggedPtr {
        struct Block* ptr{nullptr};
        uint64_t tag{0};

        bool operator==(const TaggedPtr& other) const {
            return ptr == other.ptr && tag == other.tag;
        }
    };

    struct Block {
        alignas(BlockSize) uint8_t data[BlockSize];
        std::atomic<TaggedPtr> next;
        bool in_pool{false};
    };

    std::array<Block, PoolSize> blocks_;
    std::atomic<TaggedPtr> free_list_;
    std::atomic<size_t> allocated_{0};
    std::atomic<size_t> heap_allocations_{0};
};

// ============================================================================
// Lock-Free MPMC Queue for Small Objects
// ============================================================================

template<typename T, size_t Capacity>
class LockFreeQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");

public:
    LockFreeQueue() : head_(0), tail_(0) {
        for (size_t i = 0; i < Capacity; ++i) {
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }

    bool try_push(const T& value) {
        Cell* cell;
        size_t pos = tail_.load(std::memory_order_relaxed);

        while (true) {
            cell = &buffer_[pos & (Capacity - 1)];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

            if (diff == 0) {
                if (tail_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                return false;  // Queue full
            } else {
                pos = tail_.load(std::memory_order_relaxed);
            }
        }

        cell->data = value;
        cell->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

    bool try_pop(T& value) {
        Cell* cell;
        size_t pos = head_.load(std::memory_order_relaxed);

        while (true) {
            cell = &buffer_[pos & (Capacity - 1)];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);

            if (diff == 0) {
                if (head_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                return false;  // Queue empty
            } else {
                pos = head_.load(std::memory_order_relaxed);
            }
        }

        value = std::move(cell->data);
        cell->sequence.store(pos + Capacity, std::memory_order_release);
        return true;
    }

    size_t size_approx() const {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        return tail >= head ? tail - head : 0;
    }

    bool empty() const {
        return size_approx() == 0;
    }

private:
    struct Cell {
        std::atomic<size_t> sequence;
        T data;
    };

    alignas(64) std::array<Cell, Capacity> buffer_;
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
};

} // namespace edgelink
