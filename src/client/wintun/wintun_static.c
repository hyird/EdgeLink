/**
 * Wintun Static Library Implementation
 * 
 * This implements the Wintun API as a static library, embedding the
 * official signed driver.
 * 
 * Based on Wintun source code from https://git.zx2c4.com/wintun
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 * 
 * Modified for static linking by EdgeLink project.
 */

#ifdef _WIN32

#include "wintun_static.h"
#include "wintun_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <newdev.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "newdev.lib")

// ============================================================================
// Global State
// ============================================================================

static WINTUN_LOGGER_CALLBACK g_Logger = NULL;
static BOOL g_Initialized = FALSE;
static CRITICAL_SECTION g_InitLock;
static WCHAR g_DriverPath[MAX_PATH] = {0};

// ============================================================================
// Logging
// ============================================================================

static void Log(WINTUN_LOGGER_LEVEL Level, const WCHAR* Format, ...) {
    if (!g_Logger) return;
    
    WCHAR Message[1024];
    va_list Args;
    va_start(Args, Format);
    StringCchVPrintfW(Message, _countof(Message), Format, Args);
    va_end(Args);
    
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    DWORD64 Timestamp = ((DWORD64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    
    g_Logger(Level, Timestamp, Message);
}

void WintunSetLogger(WINTUN_LOGGER_CALLBACK NewLogger) {
    g_Logger = NewLogger;
}

// ============================================================================
// Driver Resource Extraction
// ============================================================================

static BOOL ExtractResource(UINT ResourceId, const WCHAR* OutputPath) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(ResourceId), RT_RCDATA);
    if (!hRes) {
        Log(WINTUN_LOG_ERR, L"FindResource failed for %u: %lu", ResourceId, GetLastError());
        return FALSE;
    }
    
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        Log(WINTUN_LOG_ERR, L"LoadResource failed: %lu", GetLastError());
        return FALSE;
    }
    
    DWORD Size = SizeofResource(NULL, hRes);
    void* Data = LockResource(hData);
    if (!Data || Size == 0) {
        Log(WINTUN_LOG_ERR, L"LockResource failed");
        return FALSE;
    }
    
    HANDLE hFile = CreateFileW(OutputPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log(WINTUN_LOG_ERR, L"CreateFile failed for %s: %lu", OutputPath, GetLastError());
        return FALSE;
    }
    
    DWORD Written;
    BOOL Success = WriteFile(hFile, Data, Size, &Written, NULL);
    CloseHandle(hFile);
    
    if (!Success || Written != Size) {
        Log(WINTUN_LOG_ERR, L"WriteFile failed: %lu", GetLastError());
        DeleteFileW(OutputPath);
        return FALSE;
    }
    
    return TRUE;
}

static BOOL ExtractDriverFiles(WCHAR* DriverDir, DWORD DriverDirLen) {
    // Get temp directory
    WCHAR TempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, TempPath) == 0) {
        return FALSE;
    }
    
    // Create unique directory
    StringCchPrintfW(DriverDir, DriverDirLen, L"%swintun_%lu", TempPath, GetCurrentProcessId());
    if (!CreateDirectoryW(DriverDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return FALSE;
    }
    
    // Determine architecture
#ifdef _M_AMD64
    UINT SysId = IDR_WINTUN_AMD64_SYS;
    UINT InfId = IDR_WINTUN_AMD64_INF;
    UINT CatId = IDR_WINTUN_AMD64_CAT;
#elif defined(_M_ARM64)
    UINT SysId = IDR_WINTUN_ARM64_SYS;
    UINT InfId = IDR_WINTUN_ARM64_INF;
    UINT CatId = IDR_WINTUN_ARM64_CAT;
#else
    #error "Unsupported architecture"
#endif
    
    WCHAR FilePath[MAX_PATH];
    
    // Check if resources are embedded
    if (!FindResourceW(NULL, MAKEINTRESOURCEW(SysId), RT_RCDATA)) {
        Log(WINTUN_LOG_WARN, L"Driver resources not embedded, will try loading from disk");
        return FALSE;
    }
    
    // Extract wintun.sys
    StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.sys", DriverDir);
    if (!ExtractResource(SysId, FilePath)) return FALSE;
    
    // Extract wintun.inf
    StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.inf", DriverDir);
    if (!ExtractResource(InfId, FilePath)) return FALSE;
    
    // Extract wintun.cat
    StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.cat", DriverDir);
    if (!ExtractResource(CatId, FilePath)) return FALSE;
    
    StringCchCopyW(g_DriverPath, MAX_PATH, DriverDir);
    Log(WINTUN_LOG_INFO, L"Extracted driver to %s", DriverDir);
    
    return TRUE;
}

// ============================================================================
// Driver Installation
// ============================================================================

BOOL DriverInstall(void) {
    if (g_DriverPath[0] == 0) {
        Log(WINTUN_LOG_ERR, L"Driver not extracted");
        return FALSE;
    }
    
    WCHAR InfPath[MAX_PATH];
    StringCchPrintfW(InfPath, MAX_PATH, L"%s\\wintun.inf", g_DriverPath);
    
    // Pre-install the driver package
    BOOL RebootRequired = FALSE;
    if (!DiInstallDriverW(NULL, InfPath, DIIRFLAG_FORCE_INF, &RebootRequired)) {
        DWORD Error = GetLastError();
        if (Error != ERROR_SUCCESS) {
            Log(WINTUN_LOG_ERR, L"DiInstallDriver failed: %lu", Error);
            return FALSE;
        }
    }
    
    Log(WINTUN_LOG_INFO, L"Driver installed successfully");
    return TRUE;
}

BOOL DriverIsInstalled(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    
    SC_HANDLE svc = OpenServiceW(scm, L"Wintun", SERVICE_QUERY_STATUS);
    BOOL installed = (svc != NULL);
    
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    
    return installed;
}

// ============================================================================
// Initialization
// ============================================================================

BOOL WintunInitialize(void) {
    static BOOL InitOnce = FALSE;
    
    if (!InitOnce) {
        InitializeCriticalSection(&g_InitLock);
        InitOnce = TRUE;
    }
    
    EnterCriticalSection(&g_InitLock);
    
    if (g_Initialized) {
        LeaveCriticalSection(&g_InitLock);
        return TRUE;
    }
    
    // Extract driver files
    WCHAR DriverDir[MAX_PATH];
    if (!ExtractDriverFiles(DriverDir, MAX_PATH)) {
        // Driver not embedded, check if already installed
        if (!DriverIsInstalled()) {
            Log(WINTUN_LOG_ERR, L"Wintun driver not installed and not embedded");
            LeaveCriticalSection(&g_InitLock);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        }
        Log(WINTUN_LOG_INFO, L"Using system-installed Wintun driver");
    } else {
        // Install the extracted driver if not already installed
        if (!DriverIsInstalled()) {
            if (!DriverInstall()) {
                LeaveCriticalSection(&g_InitLock);
                return FALSE;
            }
        }
    }
    
    g_Initialized = TRUE;
    LeaveCriticalSection(&g_InitLock);
    
    Log(WINTUN_LOG_INFO, L"Wintun initialized");
    return TRUE;
}

void WintunShutdown(void) {
    EnterCriticalSection(&g_InitLock);
    
    // Clean up extracted driver files
    if (g_DriverPath[0] != 0) {
        WCHAR FilePath[MAX_PATH];
        StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.sys", g_DriverPath);
        DeleteFileW(FilePath);
        StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.inf", g_DriverPath);
        DeleteFileW(FilePath);
        StringCchPrintfW(FilePath, MAX_PATH, L"%s\\wintun.cat", g_DriverPath);
        DeleteFileW(FilePath);
        RemoveDirectoryW(g_DriverPath);
        g_DriverPath[0] = 0;
    }
    
    g_Initialized = FALSE;
    LeaveCriticalSection(&g_InitLock);
}

// ============================================================================
// Adapter Management
// ============================================================================

WINTUN_ADAPTER_HANDLE WintunCreateAdapter(
    const WCHAR* Name,
    const WCHAR* TunnelType,
    const GUID* RequestedGUID
) {
    if (!g_Initialized && !WintunInitialize()) {
        return NULL;
    }
    
    WINTUN_ADAPTER* Adapter = (WINTUN_ADAPTER*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINTUN_ADAPTER));
    if (!Adapter) {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    
    // Generate or use provided GUID
    if (RequestedGUID) {
        Adapter->CfgInstanceID = *RequestedGUID;
    } else {
        CoCreateGuid(&Adapter->CfgInstanceID);
    }
    
    StringCchCopyW(Adapter->Name, MAX_ADAPTER_NAME, Name);
    StringCchCopyW(Adapter->Pool, MAX_ADAPTER_NAME, TunnelType);
    
    // Create device instance using SetupAPI
    HDEVINFO DevInfo = SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        Log(WINTUN_LOG_ERR, L"SetupDiCreateDeviceInfoList failed: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, Adapter);
        return NULL;
    }
    
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiCreateDeviceInfoW(DevInfo, L"Wintun", &GUID_DEVCLASS_NET, NULL, 
                                   NULL, DICD_GENERATE_ID, &DevInfoData)) {
        Log(WINTUN_LOG_ERR, L"SetupDiCreateDeviceInfo failed: %lu", GetLastError());
        SetupDiDestroyDeviceInfoList(DevInfo);
        HeapFree(GetProcessHeap(), 0, Adapter);
        return NULL;
    }
    
    // Set hardware ID
    static const WCHAR HwId[] = L"Wintun\0";
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID,
                                           (const BYTE*)HwId, sizeof(HwId))) {
        Log(WINTUN_LOG_ERR, L"SetupDiSetDeviceRegistryProperty failed: %lu", GetLastError());
        SetupDiDestroyDeviceInfoList(DevInfo);
        HeapFree(GetProcessHeap(), 0, Adapter);
        return NULL;
    }
    
    // Register and install device
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData)) {
        Log(WINTUN_LOG_ERR, L"DIF_REGISTERDEVICE failed: %lu", GetLastError());
        SetupDiDestroyDeviceInfoList(DevInfo);
        HeapFree(GetProcessHeap(), 0, Adapter);
        return NULL;
    }
    
    // Get device instance ID
    SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, Adapter->DevInstanceID,
                                MAX_DEVICE_ID_LEN, NULL);
    
    // Install device
    SP_DEVINSTALL_PARAMS_W InstallParams = { .cbSize = sizeof(InstallParams) };
    InstallParams.Flags |= DI_NEEDREBOOT;
    SetupDiSetDeviceInstallParamsW(DevInfo, &DevInfoData, &InstallParams);
    
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData)) {
        DWORD Error = GetLastError();
        if (Error != ERROR_SUCCESS) {
            Log(WINTUN_LOG_ERR, L"DIF_INSTALLDEVICE failed: %lu", Error);
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData);
            SetupDiDestroyDeviceInfoList(DevInfo);
            HeapFree(GetProcessHeap(), 0, Adapter);
            return NULL;
        }
    }
    
    SetupDiDestroyDeviceInfoList(DevInfo);
    
    // Get LUID index
    // TODO: Query from registry HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972...}
    Adapter->LuidIndex = 0;
    Adapter->IfType = IF_TYPE_PROP_VIRTUAL;
    
    Log(WINTUN_LOG_INFO, L"Created adapter: %s", Name);
    return (WINTUN_ADAPTER_HANDLE)Adapter;
}

WINTUN_ADAPTER_HANDLE WintunOpenAdapter(const WCHAR* Name) {
    if (!g_Initialized && !WintunInitialize()) {
        return NULL;
    }
    
    // Find existing adapter by name
    HDEVINFO DevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(DevInfo, i, &DevInfoData); i++) {
        WCHAR HwId[256];
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID,
                                              NULL, (BYTE*)HwId, sizeof(HwId), NULL)) {
            if (_wcsicmp(HwId, L"Wintun") == 0) {
                // Check friendly name
                WCHAR FriendlyName[MAX_ADAPTER_NAME];
                if (SetupDiGetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_FRIENDLYNAME,
                                                      NULL, (BYTE*)FriendlyName, sizeof(FriendlyName), NULL)) {
                    if (_wcsicmp(FriendlyName, Name) == 0) {
                        // Found it
                        WINTUN_ADAPTER* Adapter = (WINTUN_ADAPTER*)HeapAlloc(
                            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINTUN_ADAPTER));
                        if (Adapter) {
                            StringCchCopyW(Adapter->Name, MAX_ADAPTER_NAME, Name);
                            SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, 
                                                        Adapter->DevInstanceID, MAX_DEVICE_ID_LEN, NULL);
                            SetupDiDestroyDeviceInfoList(DevInfo);
                            return (WINTUN_ADAPTER_HANDLE)Adapter;
                        }
                    }
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(DevInfo);
    SetLastError(ERROR_FILE_NOT_FOUND);
    return NULL;
}

void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Handle) {
    WINTUN_ADAPTER* Adapter = (WINTUN_ADAPTER*)Handle;
    if (!Adapter) return;
    
    // Remove device
    HDEVINFO DevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, Adapter->DevInstanceID,
                                            NULL, DIGCF_DEVICEINTERFACE);
    if (DevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
        if (SetupDiEnumDeviceInfo(DevInfo, 0, &DevInfoData)) {
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData);
        }
        SetupDiDestroyDeviceInfoList(DevInfo);
    }
    
    Log(WINTUN_LOG_INFO, L"Closed adapter: %s", Adapter->Name);
    HeapFree(GetProcessHeap(), 0, Adapter);
}

void WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE Handle, NET_LUID* Luid) {
    WINTUN_ADAPTER* Adapter = (WINTUN_ADAPTER*)Handle;
    if (!Adapter || !Luid) return;
    
    Luid->Info.Reserved = 0;
    Luid->Info.NetLuidIndex = Adapter->LuidIndex;
    Luid->Info.IfType = Adapter->IfType;
}

// ============================================================================
// Session Management
// ============================================================================

static HANDLE OpenDeviceHandle(WINTUN_ADAPTER* Adapter) {
    // Find device path
    HDEVINFO DevInfo = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_NET, NULL, NULL,
                                            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (DevInfo == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    
    HANDLE Result = INVALID_HANDLE_VALUE;
    SP_DEVICE_INTERFACE_DATA InterfaceData = { .cbSize = sizeof(InterfaceData) };
    
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(DevInfo, NULL, &GUID_DEVINTERFACE_NET, i, &InterfaceData); i++) {
        DWORD RequiredSize;
        SetupDiGetDeviceInterfaceDetailW(DevInfo, &InterfaceData, NULL, 0, &RequiredSize, NULL);
        
        SP_DEVICE_INTERFACE_DETAIL_DATA_W* DetailData = 
            (SP_DEVICE_INTERFACE_DETAIL_DATA_W*)HeapAlloc(GetProcessHeap(), 0, RequiredSize);
        if (!DetailData) continue;
        
        DetailData->cbSize = sizeof(*DetailData);
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
        
        if (SetupDiGetDeviceInterfaceDetailW(DevInfo, &InterfaceData, DetailData, RequiredSize, NULL, &DevInfoData)) {
            WCHAR DevInstanceID[MAX_DEVICE_ID_LEN];
            if (SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, DevInstanceID, MAX_DEVICE_ID_LEN, NULL)) {
                if (_wcsicmp(DevInstanceID, Adapter->DevInstanceID) == 0) {
                    Result = CreateFileW(DetailData->DevicePath, 
                                        GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        NULL, OPEN_EXISTING, 0, NULL);
                    HeapFree(GetProcessHeap(), 0, DetailData);
                    break;
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, DetailData);
    }
    
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Handle, DWORD Capacity) {
    WINTUN_ADAPTER* Adapter = (WINTUN_ADAPTER*)Handle;
    if (!Adapter) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    if (Capacity < WINTUN_MIN_RING_CAPACITY || Capacity > WINTUN_MAX_RING_CAPACITY ||
        (Capacity & (Capacity - 1)) != 0) {  // Must be power of 2
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    WINTUN_SESSION* Session = (WINTUN_SESSION*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINTUN_SESSION));
    if (!Session) {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    
    Session->Adapter = Adapter;
    Session->Capacity = Capacity;
    
    // Open device handle
    Session->Handle = OpenDeviceHandle(Adapter);
    if (Session->Handle == INVALID_HANDLE_VALUE) {
        Log(WINTUN_LOG_ERR, L"Failed to open device handle: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, Session);
        return NULL;
    }
    
    // Calculate ring sizes
    DWORD RingSize = TUN_RING_SIZE(Capacity);
    
    // Allocate send ring
    Session->SendRingMemory = (BYTE*)VirtualAlloc(NULL, RingSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Session->SendRingMemory) {
        Log(WINTUN_LOG_ERR, L"Failed to allocate send ring");
        goto cleanup;
    }
    Session->SendRing = (TUN_RING*)Session->SendRingMemory;
    Session->SendTailMoved = CreateEventW(NULL, FALSE, FALSE, NULL);
    
    // Allocate receive ring
    Session->ReceiveRingMemory = (BYTE*)VirtualAlloc(NULL, RingSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!Session->ReceiveRingMemory) {
        Log(WINTUN_LOG_ERR, L"Failed to allocate receive ring");
        goto cleanup;
    }
    Session->ReceiveRing = (TUN_RING*)Session->ReceiveRingMemory;
    Session->ReceiveTailMoved = CreateEventW(NULL, FALSE, FALSE, NULL);
    
    // Register rings with driver
    TUN_REGISTER_RINGS Rings = {
        .Send = {
            .RingSize = RingSize,
            .Ring = Session->SendRing,
            .TailMoved = Session->SendTailMoved
        },
        .Receive = {
            .RingSize = RingSize,
            .Ring = Session->ReceiveRing,
            .TailMoved = Session->ReceiveTailMoved
        }
    };
    
    DWORD BytesReturned;
    if (!DeviceIoControl(Session->Handle, TUN_IOCTL_REGISTER_RINGS,
                         &Rings, sizeof(Rings), NULL, 0, &BytesReturned, NULL)) {
        Log(WINTUN_LOG_ERR, L"TUN_IOCTL_REGISTER_RINGS failed: %lu", GetLastError());
        goto cleanup;
    }
    
    Log(WINTUN_LOG_INFO, L"Session started with capacity %lu", Capacity);
    return (WINTUN_SESSION_HANDLE)Session;
    
cleanup:
    if (Session->SendTailMoved) CloseHandle(Session->SendTailMoved);
    if (Session->ReceiveTailMoved) CloseHandle(Session->ReceiveTailMoved);
    if (Session->SendRingMemory) VirtualFree(Session->SendRingMemory, 0, MEM_RELEASE);
    if (Session->ReceiveRingMemory) VirtualFree(Session->ReceiveRingMemory, 0, MEM_RELEASE);
    if (Session->Handle != INVALID_HANDLE_VALUE) CloseHandle(Session->Handle);
    HeapFree(GetProcessHeap(), 0, Session);
    return NULL;
}

void WintunEndSession(WINTUN_SESSION_HANDLE Handle) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    if (!Session) return;
    
    // Signal shutdown
    if (Session->SendRing) {
        InterlockedExchange((LONG*)&Session->SendRing->Tail, 0xFFFFFFFF);
    }
    if (Session->ReceiveRing) {
        InterlockedExchange((LONG*)&Session->ReceiveRing->Head, 0xFFFFFFFF);
    }
    
    if (Session->Handle != INVALID_HANDLE_VALUE) {
        CloseHandle(Session->Handle);
    }
    
    if (Session->SendTailMoved) CloseHandle(Session->SendTailMoved);
    if (Session->ReceiveTailMoved) CloseHandle(Session->ReceiveTailMoved);
    if (Session->SendRingMemory) VirtualFree(Session->SendRingMemory, 0, MEM_RELEASE);
    if (Session->ReceiveRingMemory) VirtualFree(Session->ReceiveRingMemory, 0, MEM_RELEASE);
    
    HeapFree(GetProcessHeap(), 0, Session);
    Log(WINTUN_LOG_INFO, L"Session ended");
}

HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Handle) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    return Session ? Session->SendTailMoved : NULL;
}

// ============================================================================
// Packet I/O
// ============================================================================

BYTE* WintunReceivePacket(WINTUN_SESSION_HANDLE Handle, DWORD* PacketSize) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    if (!Session || !PacketSize) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    TUN_RING* Ring = Session->SendRing;  // Driver sends to us via SendRing
    DWORD Capacity = Session->Capacity;
    
    ULONG Head = Ring->Head;
    ULONG Tail = Ring->Tail;
    
    if (Head == 0xFFFFFFFF || Tail == 0xFFFFFFFF) {
        SetLastError(ERROR_HANDLE_EOF);
        return NULL;
    }
    
    if (Head == Tail) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        return NULL;
    }
    
    // Get packet from ring
    ULONG PacketOffset = TUN_RING_WRAP(Head, Capacity);
    TUN_PACKET* Packet = (TUN_PACKET*)(Ring->Data + PacketOffset);
    
    if (Packet->Size > TUN_MAX_PACKET_SIZE) {
        SetLastError(ERROR_INVALID_DATA);
        return NULL;
    }
    
    *PacketSize = Packet->Size;
    return Packet->Data;
}

void WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Handle, const BYTE* Packet) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    if (!Session || !Packet) return;
    
    TUN_RING* Ring = Session->SendRing;
    DWORD Capacity = Session->Capacity;
    
    // Calculate packet start
    TUN_PACKET* TunPacket = (TUN_PACKET*)((BYTE*)Packet - offsetof(TUN_PACKET, Data));
    ULONG PacketSize = TUN_PACKET_ALIGN(sizeof(TUN_PACKET) + TunPacket->Size);
    
    // Advance head
    ULONG Head = Ring->Head;
    ULONG NewHead = TUN_RING_WRAP(Head + PacketSize, Capacity);
    InterlockedExchange((LONG*)&Ring->Head, NewHead);
}

BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Handle, DWORD PacketSize) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    if (!Session) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    if (PacketSize > TUN_MAX_PACKET_SIZE) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    
    TUN_RING* Ring = Session->ReceiveRing;  // We send to driver via ReceiveRing
    DWORD Capacity = Session->Capacity;
    
    ULONG Head = Ring->Head;
    ULONG Tail = Ring->Tail;
    
    if (Head == 0xFFFFFFFF || Tail == 0xFFFFFFFF) {
        SetLastError(ERROR_HANDLE_EOF);
        return NULL;
    }
    
    ULONG AlignedSize = TUN_PACKET_ALIGN(sizeof(TUN_PACKET) + PacketSize);
    ULONG Available = TUN_RING_WRAP(Head - Tail - 1, Capacity);
    
    if (AlignedSize > Available) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return NULL;
    }
    
    // Get packet slot
    ULONG PacketOffset = TUN_RING_WRAP(Tail, Capacity);
    TUN_PACKET* Packet = (TUN_PACKET*)(Ring->Data + PacketOffset);
    Packet->Size = PacketSize;
    
    return Packet->Data;
}

void WintunSendPacket(WINTUN_SESSION_HANDLE Handle, const BYTE* Packet) {
    WINTUN_SESSION* Session = (WINTUN_SESSION*)Handle;
    if (!Session || !Packet) return;
    
    TUN_RING* Ring = Session->ReceiveRing;
    DWORD Capacity = Session->Capacity;
    
    // Calculate packet start
    TUN_PACKET* TunPacket = (TUN_PACKET*)((BYTE*)Packet - offsetof(TUN_PACKET, Data));
    ULONG PacketSize = TUN_PACKET_ALIGN(sizeof(TUN_PACKET) + TunPacket->Size);
    
    // Advance tail
    ULONG Tail = Ring->Tail;
    ULONG NewTail = TUN_RING_WRAP(Tail + PacketSize, Capacity);
    InterlockedExchange((LONG*)&Ring->Tail, NewTail);
    
    // Signal driver if alertable
    if (Ring->Alertable) {
        SetEvent(Session->ReceiveTailMoved);
    }
}

// ============================================================================
// Utility
// ============================================================================

DWORD WintunGetRunningDriverVersion(void) {
    // Query driver version from registry or service
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                      L"SYSTEM\\CurrentControlSet\\Services\\Wintun",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    
    DWORD Version = 0;
    DWORD Size = sizeof(Version);
    RegQueryValueExW(hKey, L"Version", NULL, NULL, (BYTE*)&Version, &Size);
    RegCloseKey(hKey);
    
    if (Version == 0) {
        // Default to 0.14 if not found
        Version = (0 << 16) | 14;
    }
    
    return Version;
}

#endif // _WIN32
