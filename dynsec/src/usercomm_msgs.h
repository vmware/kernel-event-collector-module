/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/// @file    usercomm_msgs.h
///
/// @brief   Declarations of types used to communicate between kernel and
///          usermode.
///
/// @copyright (c) 2019 Carbon Black, Inc. All rights reserved.
///

#pragma once


// Base header type
struct kmsg_hdr {
    int msg_type;
};

// Response from usermode
struct kmsg_response {
    int msg_type;
    int response;
    int req_id;
};

// Request to usermode
struct kmsg_request {
    int msg_type;
    int req_id;
    int op;
    int pid;
    int uid;
    int euid;
    uint64_t ino;
    uint32_t dev;
    int path_index;
    char path[512];
};


