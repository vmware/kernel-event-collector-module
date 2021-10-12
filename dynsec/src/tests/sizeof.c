// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "dynsec.h"

// 
// Use to compare against python wrapper classes.
//
// Print out sizes of ctype version of structs
// in the same print format and then diff externally.
//

#define print_sizeof(obj) ({printf("sizeof(" #obj "):%lu\n", sizeof(obj));})

int main(int argc, const char *argv[])
{
    // Generic Event Objects
    print_sizeof(struct dynsec_msg_hdr);
    print_sizeof(struct dynsec_cred);
    print_sizeof(struct dynsec_task_ctx);
    print_sizeof(struct dynsec_blob);
    print_sizeof(struct dynsec_file);

    // Event Specific Objects
    print_sizeof(struct dynsec_exec_umsg);
    print_sizeof(struct dynsec_unlink_umsg);
    print_sizeof(struct dynsec_rename_umsg);
    print_sizeof(struct dynsec_setattr_umsg);
    print_sizeof(struct dynsec_create_umsg);
    print_sizeof(struct dynsec_file_umsg);
    print_sizeof(struct dynsec_link_umsg);
    print_sizeof(struct dynsec_symlink_umsg);
    print_sizeof(struct dynsec_mmap_umsg);
    print_sizeof(struct dynsec_ptrace_umsg);
    print_sizeof(struct dynsec_signal_umsg);
    print_sizeof(struct dynsec_task_umsg);
    print_sizeof(struct dynsec_task_dump_umsg);

    // Cmds and Ioctl Objects

    return 0;
}
