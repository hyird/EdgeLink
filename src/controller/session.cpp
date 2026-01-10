#include "controller/session_impl.hpp"

namespace edgelink::controller {

// ============================================================================
// Explicit template instantiations
// ============================================================================

// TLS sessions
template class SessionBase<TlsWsStream>;
template class ControlSessionImpl<TlsWsStream>;
template class RelaySessionImpl<TlsWsStream>;

// Plain sessions
template class SessionBase<PlainWsStream>;
template class ControlSessionImpl<PlainWsStream>;
template class RelaySessionImpl<PlainWsStream>;

} // namespace edgelink::controller
