#pragma once

/**
 * Wintun Internal Definitions
 * Based on Wintun source code from https://git.zx2c4.com/wintun
 */

#ifdef _WIN32

#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <ndisguid.h>
#include <winioctl.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

// ============================================================================
// IOCTL Definitions (from wintun driver)
// ============================================================================

#define TUN_IOCTL_REGISTER_RINGS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

// ============================================================================
// Ring Buffer Structures
// ============================================================================

#define TUN_RING_CAPACITY(Size) ((Size) - sizeof(TUN_RING) - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_SIZE(Capacity) (sizeof(TUN_RING) + (Capacity) + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_WRAP(Value, Capacity) ((Value) & ((Capacity) - 1))
#define TUN_MAX_PACKET_SIZE 65535
#define TUN_ALIGNMENT 4
#define TUN_PACKET_ALIGN(Size) (((Size) + (TUN_ALIGNMENT - 1)) & ~(TUN_ALIGNMENT - 1))

#pragma pack(push, 1)

typedef struct _TUN_PACKET {
    ULONG Size;
    UCHAR Data[]; // Flexible array member
} TUN_PACKET;

typedef struct _TUN_RING {
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[]; // Flexible array member
} TUN_RING;

typedef struct _TUN_REGISTER_RINGS {
    struct {
        ULONG RingSize;
        TUN_RING* Ring;
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;

#pragma pack(pop)

// ============================================================================
// Internal Adapter Structure
// ============================================================================

typedef struct _WINTUN_ADAPTER {
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_DEVICE_ID_LEN];
    DWORD LuidIndex;
    DWORD IfType;
    WCHAR Pool[MAX_ADAPTER_NAME];
    WCHAR Name[MAX_ADAPTER_NAME];
} WINTUN_ADAPTER;

// ============================================================================
// Internal Session Structure
// ============================================================================

typedef struct _WINTUN_SESSION {
    WINTUN_ADAPTER* Adapter;
    HANDLE Handle;
    DWORD Capacity;
    
    // Send ring
    TUN_RING* SendRing;
    HANDLE SendTailMoved;
    BYTE* SendRingMemory;
    
    // Receive ring
    TUN_RING* ReceiveRing;
    HANDLE ReceiveTailMoved;
    BYTE* ReceiveRingMemory;
    
} WINTUN_SESSION;

// ============================================================================
// Resource IDs for embedded driver
// ============================================================================

#define IDR_WINTUN_AMD64_SYS   201
#define IDR_WINTUN_AMD64_INF   202
#define IDR_WINTUN_AMD64_CAT   203
#define IDR_WINTUN_ARM64_SYS   211
#define IDR_WINTUN_ARM64_INF   212
#define IDR_WINTUN_ARM64_CAT   213

// ============================================================================
// Internal Functions
// ============================================================================

BOOL DriverInstall(void);
BOOL DriverRemove(void);
BOOL DriverIsInstalled(void);

WINTUN_ADAPTER* AdapterCreate(const WCHAR* Name, const WCHAR* TunnelType, const GUID* RequestedGUID);
WINTUN_ADAPTER* AdapterOpen(const WCHAR* Name);
void AdapterClose(WINTUN_ADAPTER* Adapter);

#endif // _WIN32
