/* SPDX-License-Identifier: GPL-2.0 OR MIT
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION *WINTUN_SESSION_HANDLE;

#define WINTUN_MAX_POOL 256
#define WINTUN_MIN_RING_CAPACITY 0x20000
#define WINTUN_MAX_RING_CAPACITY 0x4000000
#define WINTUN_MAX_IP_PACKET_SIZE 0xFFFF

typedef BOOL(CALLBACK *WINTUN_ENUM_CALLBACK)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ LPARAM Param);

typedef _Return_type_success_(return != NULL)
    WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
        _In_z_ LPCWSTR Name, _In_z_ LPCWSTR TunnelType, _In_opt_ const GUID *RequestedGUID);

typedef _Return_type_success_(return != NULL)
    WINTUN_ADAPTER_HANDLE(WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(_In_z_ LPCWSTR Name);

typedef void(WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(_In_opt_ WINTUN_ADAPTER_HANDLE Adapter);

typedef _Return_type_success_(return != FALSE)
    BOOL(WINAPI *WINTUN_DELETE_DRIVER_FUNC)(void);

typedef void(WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid);

typedef DWORD(WINAPI *WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)(void);

typedef enum {
    WINTUN_LOG_INFO,
    WINTUN_LOG_WARN,
    WINTUN_LOG_ERR
} WINTUN_LOGGER_LEVEL;

typedef void(CALLBACK *WINTUN_LOGGER_CALLBACK)(
    _In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ LPCWSTR Message);

typedef void(WINAPI *WINTUN_SET_LOGGER_FUNC)(_In_ WINTUN_LOGGER_CALLBACK NewLogger);

typedef _Return_type_success_(return != NULL)
    WINTUN_SESSION_HANDLE(WINAPI *WINTUN_START_SESSION_FUNC)(
        _In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ DWORD Capacity);

typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

typedef HANDLE(WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

typedef _Return_type_success_(return != NULL) _Ret_bytecount_(*PacketSize)
    BYTE *(WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(
        _In_ WINTUN_SESSION_HANDLE Session, _Out_ DWORD *PacketSize);

typedef void(WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

typedef _Return_type_success_(return != NULL) _Ret_bytecount_(PacketSize)
    BYTE *(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
        _In_ WINTUN_SESSION_HANDLE Session, _In_ DWORD PacketSize);

typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

#ifdef __cplusplus
}
#endif
