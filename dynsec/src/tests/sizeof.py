# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0
import ctypes
from dynsec import *

# Primary goal is to print exactly like the
# C variant to detect size changes in structures.
# Won't detect member reorder or renaming if sizes don't change.

if __name__ == '__main__':
    def print_sizeof(dynsec_type):
        print("sizeof(struct %s):%d" % (
            dynsec_type.__name__,
            ctypes.sizeof(dynsec_type),
        ))

    # Generic Event Objects
    print_sizeof(dynsec_msg_hdr)
    print_sizeof(dynsec_cred)
    print_sizeof(dynsec_task_ctx)
    print_sizeof(dynsec_blob)
    print_sizeof(dynsec_file)

    # Event Specific Objects
    print_sizeof(dynsec_exec_umsg)
    print_sizeof(dynsec_unlink_umsg)
    print_sizeof(dynsec_rename_umsg)
    print_sizeof(dynsec_setattr_umsg)
    print_sizeof(dynsec_create_umsg)
    print_sizeof(dynsec_file_umsg)
    print_sizeof(dynsec_link_umsg)
    print_sizeof(dynsec_symlink_umsg)
    print_sizeof(dynsec_mmap_umsg)
    print_sizeof(dynsec_ptrace_umsg)
    print_sizeof(dynsec_signal_umsg)
    print_sizeof(dynsec_task_umsg)
    print_sizeof(dynsec_task_dump_umsg)

