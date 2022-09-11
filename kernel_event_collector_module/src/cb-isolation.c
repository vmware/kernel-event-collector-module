// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/inet.h>
#include "priv.h"
#include "mem-alloc.h"
#include "cb-spinlock.h"
#include "netfilter.h"

#include "cb-isolation.h"

CB_ISOLATION_STATS  g_cbIsolationStats;

static CB_ISOLATION_MODE             CBIsolationMode = IsolationModeOff;
static PCB_ISOLATION_MODE_CONTROL   _pCurrentCbIsolationModeControl;
uint64_t                            _pControlLock;
static BOOLEAN                      _isInitialized = FALSE;

BOOLEAN ACQUIRE_RESOURCE(ProcessContext *context)
{
    if (_isInitialized == FALSE)
    {
        return FALSE;
    }

    ec_write_lock(&_pControlLock, context);
    return TRUE;
}

VOID RELEASE_RESOURCE(ProcessContext *context)
{
    ec_write_unlock(&_pControlLock, context);
}

bool ec_InitializeNetworkIsolation(ProcessContext *context)
{
    ec_spinlock_init(&_pControlLock, context);
    CBIsolationMode = IsolationModeOff;
    _isInitialized = TRUE;
    return true;
}

VOID ec_DestroyNetworkIsolation(ProcessContext *context)
{
    _isInitialized = FALSE;
    CBIsolationMode = IsolationModeOff;

    if (ACQUIRE_RESOURCE(context))
    {
        if (_pCurrentCbIsolationModeControl)
        {
            ec_mem_free(_pCurrentCbIsolationModeControl);
            _pCurrentCbIsolationModeControl = NULL;
        }

        RELEASE_RESOURCE(context);
    }

    ec_spinlock_destroy(&_pControlLock, context);
}

VOID ec_SetNetworkIsolationMode(ProcessContext *context, CB_ISOLATION_MODE isolationMode)
{
    CBIsolationMode = isolationMode;
    g_cbIsolationStats.isolationEnabled = isolationMode == IsolationModeOn;

    if (g_cbIsolationStats.isolationEnabled)
    {
        ec_netfilter_enable(context);
    } else
    {
        ec_netfilter_disable(context);
    }

    TRACE(DL_INIT, "CB ISOLATION MODE: %s", isolationMode == IsolationModeOff ? "DISABLED" : "ENABLED");
}

VOID ec_DisableNetworkIsolation(ProcessContext *context)
{
    CBIsolationMode = IsolationModeOff;
    g_cbIsolationStats.isolationEnabled = FALSE;
    ec_netfilter_disable(context);

    TRACE(DL_INFO, "CB ISOLATION MODE: DISABLED");
}

NTSTATUS ec_ProcessIsolationIoctl(
    ProcessContext *context,
    ULONG IoControlCode,
    PVOID pBuf,
    DWORD InputBufLen)
{
    NTSTATUS                   xcode                   = STATUS_SUCCESS;
    PCB_ISOLATION_MODE_CONTROL tmpIsolationModeControl = NULL;
    DWORD                      ExpectedBufLen;

    TRY_SET_MSG(IoControlCode == IOCTL_SET_ISOLATION_MODE, STATUS_INVALID_PARAMETER_4,
                 DL_WARNING, "CB_ISOLATION_MODE_CONTROL size is invalid");

    tmpIsolationModeControl = (PCB_ISOLATION_MODE_CONTROL)ec_mem_alloc(InputBufLen, context);

    TRY_SET_MSG(tmpIsolationModeControl, STATUS_INSUFFICIENT_RESOURCES,
                 DL_ERROR, "%s: failed to allocate memory for network isolation control\n", __func__);

    TRY_STEP_SET_MSG(RESOURCE, !copy_from_user(tmpIsolationModeControl, pBuf, InputBufLen),
                      STATUS_INSUFFICIENT_RESOURCES,
                      DL_ERROR, "%s: failed to copy arg\n", __func__);

    // Calculate the size of the buffer we should have hold the number of addresses that user space claims is
    //  present.  This prevents us from reading past the buffer later. (CB-8236)
    ExpectedBufLen = sizeof(CB_ISOLATION_MODE_CONTROL) + (sizeof(DWORD) * (tmpIsolationModeControl->numberOfAllowedIpAddresses - 1));
    TRY_SET_MSG(ExpectedBufLen <= InputBufLen, STATUS_INVALID_PARAMETER_4,
                 DL_ERROR, "%s: the expected buffer is larger than what we received. (%d > %d)\n", __func__, ExpectedBufLen, InputBufLen);

    TRY_SET_MSG(ACQUIRE_RESOURCE(context), STATUS_INSUFFICIENT_RESOURCES,
                 DL_WARNING, "Network Isolation can't process IOCTL in uninitialized state.");

    if (_pCurrentCbIsolationModeControl)
    {
        ec_mem_free(_pCurrentCbIsolationModeControl);
    }

    _pCurrentCbIsolationModeControl = tmpIsolationModeControl;
    tmpIsolationModeControl         = NULL;
    ec_SetNetworkIsolationMode(context, _pCurrentCbIsolationModeControl->isolationMode);

    if (_pCurrentCbIsolationModeControl->isolationMode == IsolationModeOn)
    {
        char           str[INET_ADDRSTRLEN];
        unsigned char *addr, i;

        // Suppressing false positive coverity issue reporting that we are using tainted variable
        // "_pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses" as a loop boundary.
        // The "allowedIpAddresses" array is allocated to accommodate "numberOfAllowedIpAddresses" entries.

        // coverity[tainted_data:SUPPRESS]
        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; ++i)
        {
            addr = (unsigned char *)&_pCurrentCbIsolationModeControl->allowedIpAddresses[i];
            snprintf(str, INET_ADDRSTRLEN, "%d.%d.%d.%d", addr[3], addr[2], addr[1], addr[0]);
            TRACE(DL_INFO, "%s: isolation ON IP: %s\n", __func__, str);
        }
    }

CATCH_RESOURCE:
    RELEASE_RESOURCE(context);

CATCH_DEFAULT:
    ec_mem_free(tmpIsolationModeControl);
    return xcode;
}

CB_ISOLATION_MODE ec_GetCurrentIsolationMode(ProcessContext *context)
{
    return CBIsolationMode;
}

VOID ec_IsolationIntercept(ProcessContext *context,
                          ULONG remoteIpAddress,
                          CB_ISOLATION_INTERCEPT_RESULT *isolationResult)
{

    // immediate allow if isolation mode is not on
    if (CBIsolationMode == IsolationModeOff)
    {
        isolationResult->isolationAction = IsolationActionDisabled;
        return;
    }

    // acquire shared resource
    if (ACQUIRE_RESOURCE(context))
    {
        ULONG i;

        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; i++)
        {
            ULONG allowedIpAddress = _pCurrentCbIsolationModeControl->allowedIpAddresses[i];

            if (allowedIpAddress && remoteIpAddress == allowedIpAddress)
            {
                TRACE(DL_INFO, "ISOLATION ALLOWED: ADDR: 0x%08x", remoteIpAddress);
                isolationResult->isolationAction = IsolationActionAllow;
                RELEASE_RESOURCE(context);
                return;
            }
        }
        RELEASE_RESOURCE(context);
    }

    TRACE(DL_INFO, "ISOLATION BLOCKED: ADDR: 0x%08x", remoteIpAddress);
    isolationResult->isolationAction = IsolationActionBlock;
}

VOID ec_IsolationInterceptByAddrProtoPort(
    ProcessContext                *context,
    UINT32                         protocol,
    CB_SOCK_ADDR                  *remoteAddr,
    CB_ISOLATION_INTERCEPT_RESULT *isolationResult)
{
    bool   isIpV4 = remoteAddr->sa_addr.sa_family == AF_INET;
    ULONG  remoteIpAddress;
    UINT16 port;

    // immediate allow if isolation mode is not on
    if (CBIsolationMode == IsolationModeOff)
    {
        isolationResult->isolationAction = IsolationActionDisabled;
        return;
    }

    if (isIpV4)
    {
        remoteIpAddress = ntohl(remoteAddr->as_in4.sin_addr.s_addr);
        port = remoteAddr->as_in4.sin_port;
    } else
    {
        // it doesn't really matter what remoteIpAddress is set for IP6 since all IP6 addresses are blocked
        remoteIpAddress = ntohl(*(uint32_t *)&remoteAddr->as_in6.sin6_addr.s6_addr32[0]);
        port = remoteAddr->as_in6.sin6_port;
    }

    if (protocol == IPPROTO_UDP && (((isIpV4 == true) && (port == DHCP_CLIENT_PORT_V4 || port == DHCP_SERVER_PORT_V4)) ||
        ((isIpV4 == false) && (port == DHCP_CLIENT_PORT_V6 || port == DHCP_SERVER_PORT_V6)) ||
        port == DNS_SERVER_PORT))
    {
        TRACE(DL_INFO, "ISOLATION ALLOWED: %s ADDR: 0x%08x PROTO: %s PORT: %u",
            (isIpV4?"IPv4":"IPv6"),
            remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
        isolationResult->isolationAction = IsolationActionAllow;
        return;
    }

    // Our list of allowed addresses is IPv4, so just block IPv6 addresses
    // acquire shared resource
    if (isIpV4 && ACQUIRE_RESOURCE(context))
    {
        ULONG i;

        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; i++)
        {
            ULONG allowedIpAddress = _pCurrentCbIsolationModeControl->allowedIpAddresses[i];

            if (allowedIpAddress && remoteIpAddress == allowedIpAddress)
            {
                TRACE(DL_INFO, "ISOLATION ALLOWED: By %s ADDR: 0x%08x PROTO: %s PORT: %u",
                    (isIpV4?"IPv4":"IPv6"),
                    remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
                isolationResult->isolationAction = IsolationActionAllow;
                RELEASE_RESOURCE(context);
                return;
            }
        }
        RELEASE_RESOURCE(context);
    }

    TRACE(DL_INFO, "ISOLATION BLOCKED: %s ADDR: 0x%08x PROTO: %s PORT: %u",
        (isIpV4?"IPv4":"IPv6"),
        remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
    isolationResult->isolationAction = IsolationActionBlock;
}
