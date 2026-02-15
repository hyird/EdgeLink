#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

int cmd_version() {
    std::cout << "EdgeLink Client " << version::VERSION << "\n"
              << "  Build ID:   " << version::BUILD_ID << "\n"
              << "  Commit:     " << version::GIT_COMMIT << " (" << version::GIT_BRANCH << ")\n"
              << "  Built:      " << version::BUILD_TIMESTAMP << "\n"
              << "  Language:   C++23\n"
#ifdef _WIN32
              << "  Platform:   windows/"
#elif defined(__APPLE__)
              << "  Platform:   macos/"
#else
              << "  Platform:   linux/"
#endif
#if defined(__x86_64__) || defined(_M_X64)
              << "amd64\n";
#elif defined(__aarch64__) || defined(_M_ARM64)
              << "arm64\n";
#else
              << "unknown\n";
#endif
    return 0;
}
