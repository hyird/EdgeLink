// TUN device implementation for Windows (using WinTun)
// This is a stub - TUN functionality not yet implemented

#include <spdlog/spdlog.h>

namespace edgelink::client {

// Stub TUN implementation - to be implemented later
class TunDevice {
public:
    TunDevice() = default;
    ~TunDevice() = default;

    bool open(const std::string& name) {
        spdlog::warn("TUN device not implemented on this platform");
        return false;
    }

    void close() {}

    bool is_open() const { return false; }
};

} // namespace edgelink::client
