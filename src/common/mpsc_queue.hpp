#pragma once

#include <atomic>
#include <array>
#include <vector>
#include <optional>
#include <cstdint>

namespace edgelink {

/**
 * MPSCQueue - Multi-Producer Single-Consumer Lock-Free Queue
 *
 * A bounded lock-free queue optimized for the MPSC pattern where multiple
 * threads can push concurrently, but only one thread consumes.
 *
 * Design (per architecture.md Section 8.3, 8.4):
 * - Used for cross-thread message delivery
 * - Each worker thread has one inbox queue
 * - Multiple producer threads can push messages
 * - Single consumer (the owning thread) pops messages
 *
 * Implementation: Bounded ring buffer with sequence numbers for coordination.
 *
 * @tparam T Element type (must be movable)
 * @tparam Capacity Queue capacity (must be power of 2)
 */
template<typename T, size_t Capacity = 4096>
class MPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    static_assert(Capacity >= 2, "Capacity must be at least 2");

public:
    MPSCQueue() {
        for (size_t i = 0; i < Capacity; ++i) {
            cells_[i].sequence.store(i, std::memory_order_relaxed);
        }
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
    }

    ~MPSCQueue() = default;

    // Non-copyable
    MPSCQueue(const MPSCQueue&) = delete;
    MPSCQueue& operator=(const MPSCQueue&) = delete;

    /**
     * Try to push an element (multi-producer safe).
     * @param value Element to push
     * @return true if successful, false if queue is full
     */
    bool try_push(T&& value) {
        Cell* cell;
        size_t pos = tail_.load(std::memory_order_relaxed);

        for (;;) {
            cell = &cells_[pos & kMask];
            size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);

            if (diff == 0) {
                // Cell is ready for writing
                if (tail_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    break;
                }
            } else if (diff < 0) {
                // Queue is full
                return false;
            } else {
                // Another producer got this cell, try next
                pos = tail_.load(std::memory_order_relaxed);
            }
        }

        cell->data = std::move(value);
        cell->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

    /**
     * Try to push an element (copy version).
     */
    bool try_push(const T& value) {
        T copy = value;
        return try_push(std::move(copy));
    }

    /**
     * Try to pop an element (single-consumer only).
     * @param value Output parameter for popped element
     * @return true if successful, false if queue is empty
     */
    bool try_pop(T& value) {
        Cell* cell;
        size_t pos = head_.load(std::memory_order_relaxed);

        cell = &cells_[pos & kMask];
        size_t seq = cell->sequence.load(std::memory_order_acquire);
        intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);

        if (diff < 0) {
            // Queue is empty
            return false;
        }

        // Single consumer, no CAS needed
        head_.store(pos + 1, std::memory_order_relaxed);
        value = std::move(cell->data);
        cell->sequence.store(pos + Capacity, std::memory_order_release);
        return true;
    }

    /**
     * Pop multiple elements at once (single-consumer only).
     * @param out Vector to append popped elements to
     * @param max_count Maximum number of elements to pop
     * @return Number of elements actually popped
     */
    size_t pop_batch(std::vector<T>& out, size_t max_count) {
        size_t count = 0;
        T value;

        while (count < max_count && try_pop(value)) {
            out.push_back(std::move(value));
            ++count;
        }

        return count;
    }

    /**
     * Check if queue is empty.
     * Note: This is an approximation due to concurrent access.
     */
    bool empty() const {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        return head >= tail;
    }

    /**
     * Get approximate size.
     * Note: This is an approximation due to concurrent access.
     */
    size_t size_approx() const {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        return tail > head ? tail - head : 0;
    }

    /**
     * Get capacity.
     */
    constexpr size_t capacity() const { return Capacity; }

private:
    static constexpr size_t kMask = Capacity - 1;

    // Cache line padding to avoid false sharing (64 bytes is standard for x86/x64 and ARM)
    static constexpr size_t kCacheLineSize = 64;

    struct Cell {
        std::atomic<size_t> sequence;
        T data;
    };

    // Align to cache lines to avoid false sharing
    alignas(kCacheLineSize) std::array<Cell, Capacity> cells_;
    alignas(kCacheLineSize) std::atomic<size_t> tail_;  // Producers write here
    alignas(kCacheLineSize) std::atomic<size_t> head_;  // Consumer reads here
};

/**
 * CrossThreadMessage - Message structure for cross-thread communication
 *
 * Used to pass data between threads via MPSC queues.
 */
struct CrossThreadMessage {
    uint32_t src_node_id{0};       // Source node ID
    uint32_t dst_node_id{0};       // Destination node ID
    std::vector<uint8_t> data;     // Payload data
    uint64_t timestamp{0};         // Message timestamp (optional)

    CrossThreadMessage() = default;

    CrossThreadMessage(uint32_t src, uint32_t dst, std::vector<uint8_t> payload)
        : src_node_id(src), dst_node_id(dst), data(std::move(payload)) {}

    // Move-only
    CrossThreadMessage(CrossThreadMessage&&) = default;
    CrossThreadMessage& operator=(CrossThreadMessage&&) = default;
    CrossThreadMessage(const CrossThreadMessage&) = delete;
    CrossThreadMessage& operator=(const CrossThreadMessage&) = delete;
};

} // namespace edgelink
