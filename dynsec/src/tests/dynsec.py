# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0
import ctypes

#######################
# dynsec.h Definitions
#######################


class DYNSEC_EVENT_TYPE:
    EXEC = 0
    RENAME = 1
    UNLINK = 2
    RMDIR = 3
    MKDIR = 4
    CREATE = 5
    SETATTR = 6
    OPEN = 7
    CLOSE = 8
    LINK = 9
    SYMLINK = 10
    SIGNAL = 11
    PTRACE = 12
    MMAP = 13
    CLONE = 14
    EXIT = 15
    TASK_DUMP = 16

class DYNSEC_REPORT_FLAGS:
    STALL         = 0x0001
    INTENT        = 0x0002
    AUDIT         = 0x0004
    CACHED        = 0x0008
    SELF          = 0x0020
    HI_PRI        = 0x0040
    LO_PRI        = 0x0080
    INTENT_FOUND  = 0x0200

    STALL_OR_CACHED = (STALL|CACHED)

    MASK = (STALL|INTENT|AUDIT|CACHED|SELF|HI_PRI|LO_PRI|INTENT_FOUND)

    @staticmethod
    def name(report_flags):
        name_str = ""
        # Primary report flag types
        if report_flags & DYNSEC_REPORT_FLAGS.STALL:
            name_str += "STALL "
        if report_flags & DYNSEC_REPORT_FLAGS.INTENT:
            name_str += "INTENT "
        if report_flags & DYNSEC_REPORT_FLAGS.CACHED:
            name_str += "CACHED "
        if report_flags & DYNSEC_REPORT_FLAGS.SELF:
            name_str += "SELF "

        # Secondary report flag types
        if report_flags & DYNSEC_REPORT_FLAGS.INTENT_FOUND:
            name_str += "INTENT_FOUND "

        # Internal to Kmod
        if report_flags & DYNSEC_REPORT_FLAGS.AUDIT:
            name_str += "AUDIT "
        if report_flags & DYNSEC_REPORT_FLAGS.HI_PRI:
            name_str += "HI_PRI "
        if report_flags & DYNSEC_REPORT_FLAGS.LO_PRI:
            name_str += "LO_PRI "

        # Print bitmap fields not yet known
        if report_flags != (report_flags & DYNSEC_REPORT_FLAGS.MASK):
            name_str += "UNKNOWN%#x " % (
                report_flags & (~DYNSEC_REPORT_FLAGS.MASK)
            )

        return name_str

# struct dynsec_msg_hdr
class dynsec_msg_hdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('payload', ctypes.c_uint16),
        ('report_flags', ctypes.c_uint16),
        ('hook_type', ctypes.c_uint32),
        ('tid', ctypes.c_uint32),
        ('req_id', ctypes.c_uint64),
        ('intent_req_id', ctypes.c_uint64),
        ('event_type', ctypes.c_int),
    ]

class dynsec_cred(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('uid', ctypes.c_uint32),
        ('euid', ctypes.c_uint32),
        ('gid', ctypes.c_uint32),
        ('egid', ctypes.c_uint32),
        ('fsuid', ctypes.c_uint32),
        ('fsgid', ctypes.c_uint32),
        ('securebits', ctypes.c_uint32),
    ]

class dynsec_task_ctx(ctypes.Structure):
    _pack_ = 1
    DYNSEC_TASK_COMM_LEN = 16
    _fields_ = [
        ('tid', ctypes.c_uint32),
        ('pid', ctypes.c_uint32),
        ('ppid', ctypes.c_uint32),
        ('real_parent_id', ctypes.c_uint32),
        ('uid', ctypes.c_uint32),
        ('euid', ctypes.c_uint32),
        ('gid', ctypes.c_uint32),
        ('egid', ctypes.c_uint32),
        ('mnt_ns', ctypes.c_uint32),
        ('flags', ctypes.c_uint32),
        ('start_time', ctypes.c_uint64),
        ('extra_ctx', ctypes.c_uint16),
        ('comm', ctypes.c_char * DYNSEC_TASK_COMM_LEN)
    ]

class dynsec_file(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('attr_mask', ctypes.c_uint16),
        ('ino', ctypes.c_uint64),
        ('dev', ctypes.c_uint32),
        ('umode', ctypes.c_uint16),
        ('uid', ctypes.c_uint32),
        ('gid', ctypes.c_uint32),
        ('size', ctypes.c_uint64),
        ('nlink', ctypes.c_uint32),
        ('count', ctypes.c_uint32),
        ('sb_magic', ctypes.c_uint64),
        ('parent_ino', ctypes.c_uint64),
        ('parent_dev', ctypes.c_uint32),
        ('parent_uid', ctypes.c_uint32),
        ('parent_gid', ctypes.c_uint32),
        ('parent_umode', ctypes.c_uint16),
        ('path_offset', ctypes.c_uint16),
        ('path_size', ctypes.c_uint16),
    ]

class dynsec_rename_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('old_file', dynsec_file),
        ('new_file', dynsec_file),
    ]

class dynsec_rename_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_rename_msg)
    ]

