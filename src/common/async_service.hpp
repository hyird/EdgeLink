// Async Service utilities
// Provides lightweight helpers for event-driven architecture.

#pragma once

namespace edgelink {

// ============================================================================
// overloaded helper (for std::visit with lambdas)
// ============================================================================
template<class... Ts>
struct overloaded : Ts... { using Ts::operator()...; };

} // namespace edgelink
