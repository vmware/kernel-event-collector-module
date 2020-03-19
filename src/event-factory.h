/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-tracking.h"

void event_send_start(ProcessTracking * procp,
                      uid_t            uid,
                      int              start_action,
                      ProcessContext  *context);

void event_send_last_exit(PCB_EVENT        event,
                          ProcessContext  *context);

void event_send_exit(ProcessTracking *procp,
                     bool             was_last_active_process,
                     ProcessContext  *context);

void event_send_block(ProcessTracking  *procp,
                      uint32_t          type,
                      uint32_t          reason,
                      uint32_t          details,
                      uid_t             uid,
                      char             *cmdline,
                      ProcessContext *context);

void event_send_file(ProcessTracking *procp,
                     CB_EVENT_TYPE    event_type,
                     uint64_t         device,
                     uint64_t         inode,
                     CB_FILE_TYPE     file_type,
                     const char *path,
                     ProcessContext *context);

void event_send_modload(ProcessTracking *procp,
                        CB_EVENT_TYPE    event_type,
                        uint64_t         device,
                        uint64_t         inode,
                        int64_t          base_address,
                        char *path,
                        ProcessContext *context);
#
void event_send_net(ProcessTracking *procp,
                    char            *msg,
                    CB_EVENT_TYPE    net_event_type,
                    CB_SOCK_ADDR * localAddr,
                    CB_SOCK_ADDR * remoteAddr,
                    int               protocol,
                    void             *sk,
                    ProcessContext   *context);

void event_send_net_proxy(ProcessTracking *procp,
                          char            *msg,
                          CB_EVENT_TYPE    net_event_type,
                          CB_SOCK_ADDR     *localAddr,
                          CB_SOCK_ADDR     *remoteAddr,
                          int               protocol,
                          char             *actual_server,
                          uint16_t          actual_port,
                          void             *sk,
                          ProcessContext   *context);

void event_send_dns(CB_EVENT_TYPE   net_event_type,
                    char           *data,
                    uint32_t        len,
                    ProcessContext *context);
