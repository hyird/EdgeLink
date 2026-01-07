#pragma once

/**
 * Wintun Static Library Interface
 * 
 * This is a static implementation of the Wintun API that embeds the
 * official signed wintun.sys driver. It provides the same functionality
 * as wintun.dll but can be statically linked.
 * 
 * Based on Wintun source code from https://git.zx2c4.com/wintun
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifdef _WIN32

#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

#define WINTUN_MIN_RING_CAPACITY 0x20000    // 128 KiB
#define WINTUN_MAX_RING_CAPACITY 0x4000000  // 64 MiB
#define MAX_ADAPTER_NAME 128

// ============================================================================
// Types
// ============================================================================

typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

typedef enum {
    WINTUN_LOG_INFO,
    WINTUN_LOG_WARN,
    WINTUN_LOG_ERR
} WINTUN_LOGGER_LEVEL;

typedef void (CALLBACK *WINTUN_LOGGER_CALLBACK)(
    WINTUN_LOGGER_LEVEL Level,
    DWORD64 Timestamp,
    const WCHAR* Message
);

// ============================================================================
// Driver Management
// ============================================================================

/**
 * Initialize the Wintun library.
 * This extracts and installs the embedded wintun.sys driver if needed.
 * @return TRUE on success, FALSE on failure. Call GetLastError() for details.
 */
BOOL WintunInitialize(void);

/**
 * Cleanup the Wintun library.
 * Call this before program exit to clean up resources.
 */
void WintunShutdown(void);

// ============================================================================
// Adapter Management
// ============================================================================

/**
 * Creates a new Wintun adapter.
 * @param Name Requested name of the adapter (max MAX_ADAPTER_NAME-1 chars)
 * @param TunnelType Name of the adapter tunnel type (max MAX_ADAPTER_NAME-1 chars)
 * @param RequestedGUID The GUID of the created network adapter, or NULL for random
 * @return Adapter handle on success, NULL on failure
 */
WINTUN_ADAPTER_HANDLE WintunCreateAdapter(
    const WCHAR* Name,
    const WCHAR* TunnelType,
    const GUID* RequestedGUID
);

/**
 * Opens an existing Wintun adapter by name.
 * @param Name Name of the adapter to open
 * @return Adapter handle on success, NULL on failure
 */
WINTUN_ADAPTER_HANDLE WintunOpenAdapter(const WCHAR* Name);

/**
 * Releases Wintun adapter resources.
 * If adapter was created with WintunCreateAdapter, removes the adapter.
 * @param Adapter Adapter handle
 */
void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter);

/**
 * Gets the LUID of the adapter.
 * @param Adapter Adapter handle
 * @param Luid Pointer to receive LUID
 */
void WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID* Luid);

// ============================================================================
// Session Management
// ============================================================================

/**
 * Starts a Wintun session.
 * @param Adapter Adapter handle
 * @param Capacity Ring capacity (WINTUN_MIN_RING_CAPACITY to WINTUN_MAX_RING_CAPACITY)
 * @return Session handle on success, NULL on failure
 */
WINTUN_SESSION_HANDLE WintunStartSession(
    WINTUN_ADAPTER_HANDLE Adapter,
    DWORD Capacity
);

/**
 * Ends a Wintun session.
 * @param Session Session handle
 */
void WintunEndSession(WINTUN_SESSION_HANDLE Session);

/**
 * Gets event handle that is signaled when data is available.
 * @param Session Session handle
 * @return Event handle (do not close it)
 */
HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session);

// ============================================================================
// Packet I/O
// ============================================================================

/**
 * Receives a packet from the adapter.
 * @param Session Session handle
 * @param PacketSize Receives the packet size
 * @return Pointer to packet data, or NULL if no packet available
 */
BYTE* WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD* PacketSize);

/**
 * Releases a received packet back to the driver.
 * @param Session Session handle
 * @param Packet Pointer returned by WintunReceivePacket
 */
void WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);

/**
 * Allocates a buffer for sending a packet.
 * @param Session Session handle
 * @param PacketSize Size of packet to send
 * @return Pointer to buffer for packet data, or NULL on failure
 */
BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);

/**
 * Sends an allocated packet.
 * @param Session Session handle
 * @param Packet Pointer returned by WintunAllocateSendPacket
 */
void WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE* Packet);

// ============================================================================
// Utility
// ============================================================================

/**
 * Gets the version of the loaded Wintun driver.
 * @return Version number (major.minor as DWORD), or 0 on failure
 */
DWORD WintunGetRunningDriverVersion(void);

/**
 * Sets a logger callback for Wintun messages.
 * @param NewLogger Callback function, or NULL to disable logging
 */
void WintunSetLogger(WINTUN_LOGGER_CALLBACK NewLogger);

#ifdef __cplusplus
}
#endif

#endif // _WIN32
