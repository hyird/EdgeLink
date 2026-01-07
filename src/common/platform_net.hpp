#pragma once

/**
 * Cross-platform network header
 * 
 * This header provides a unified way to include network-related headers
 * that work on both Windows and Unix-like systems (Linux, macOS).
 * 
 * It provides access to:
 * - htons, htonl, ntohs, ntohl (byte order conversion)
 * - inet_pton, inet_ntop (IP address conversion)
 * - inet_addr, inet_ntoa (legacy IP conversion)
 * - Socket-related structures (sockaddr_in, in_addr, etc.)
 */

#ifdef _WIN32
    // Windows
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    // Unix-like (Linux, macOS, BSD)
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif

// For convenience, also include cstdint for fixed-width integers
#include <cstdint>

namespace edgelink {

/**
 * RAII wrapper for Windows Socket initialization
 * On Windows, this ensures WSAStartup is called before any socket operations
 * On Unix systems, this is a no-op
 */
class WinsockInitializer {
public:
#ifdef _WIN32
    WinsockInitializer() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
    ~WinsockInitializer() {
        WSACleanup();
    }
#else
    WinsockInitializer() = default;
    ~WinsockInitializer() = default;
#endif
    
    // Non-copyable
    WinsockInitializer(const WinsockInitializer&) = delete;
    WinsockInitializer& operator=(const WinsockInitializer&) = delete;
};

} // namespace edgelink
