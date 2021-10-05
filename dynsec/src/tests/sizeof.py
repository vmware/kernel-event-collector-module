# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0
import ctypes
from dynsec import *

# Primary goal is to print exactly like the
# C variant to detect size changes in structures.
# Won't detect member reorder or renaming if sizes don't change.

if __name__ == '__main__':
    print("sizeof(struct dynsec_msg_hdr):%d" % (
          ctypes.sizeof(dynsec_msg_hdr)))
    print("sizeof(struct dynsec_task_ctx):%d" % (
          ctypes.sizeof(dynsec_task_ctx)))
    print("sizeof(struct dynsec_file):%d" % (
          ctypes.sizeof(dynsec_file)))
    print("sizeof(struct dynsec_rename_umsg):%d" % (
          ctypes.sizeof(dynsec_rename_umsg)))

