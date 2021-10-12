# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0
import ctypes
import json

#######################
# dynsec.h Definitions
#######################


#########################
# Generic Object Structs
#########################

# struct dynsec_config
class dynsec_config(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('bypass_mode', ctypes.c_uint32),
        ('stall_mode', ctypes.c_uint32),
        ('stall_timeout', ctypes.c_uint32),
        ('lazy_notifier', ctypes.c_uint32),
        ('queue_threshold', ctypes.c_uint32),
        ('notify_threshold', ctypes.c_uint32),
        ('lsm_hooks', ctypes.c_uint64),
        ('process_hooks', ctypes.c_uint64),
        ('preaction_hooks', ctypes.c_uint64),
    ]

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

class dynsec_blob(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('offset', ctypes.c_uint16),
        ('size', ctypes.c_uint16),
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

###################################
# Structs for specific event types
###################################

# EXEC Internal struct
class dynsec_exec_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('new_cred', dynsec_cred),
        ('file', dynsec_file),
    ]
class dynsec_exec_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_exec_msg)
    ]

# UNLINK Internal struct
class dynsec_unlink_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('file', dynsec_file),
    ]
class dynsec_unlink_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_unlink_msg)
    ]

# RENAME Internal struct
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

# SETATTR Internal struct
class dynsec_setattr_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('attr_mask', ctypes.c_uint32),
        ('attr_umode', ctypes.c_uint16),
        ('attr_uid', ctypes.c_uint32),
        ('attr_gid', ctypes.c_uint32),
        ('attr_size', ctypes.c_uint64),
        ('file', dynsec_file),
    ]
class dynsec_setattr_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_setattr_msg)
    ]

# CREATE Internal struct
class dynsec_create_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('file', dynsec_file),
    ]
class dynsec_create_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_create_msg)
    ]

# FILE Internal struct (open/close events)
class dynsec_file_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('f_mode', ctypes.c_uint32),
        ('f_flags', ctypes.c_uint32),
        ('file', dynsec_file),
    ]
class dynsec_file_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_file_msg)
    ]

# LINK Internal struct
class dynsec_link_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('old_file', dynsec_file),
        ('new_file', dynsec_file),
    ]
class dynsec_link_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_link_msg)
    ]


# SYMLINK Internal struct
class dynsec_symlink_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('file', dynsec_file), # Actual symlink file
        ('target', dynsec_blob), # symlink file contents
    ]
class dynsec_symlink_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_symlink_msg)
    ]

# MMAP
class dynsec_mmap_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('mmap_prot', ctypes.c_uint64),
        ('mmap_flags', ctypes.c_uint64),
        ('f_mode', ctypes.c_uint32),
        ('f_flags', ctypes.c_uint32),
        ('file', dynsec_file),
    ]
class dynsec_mmap_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_mmap_msg)
    ]

# PTRACE
class dynsec_ptrace_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('source', dynsec_task_ctx),
        ('target', dynsec_task_ctx),
    ]
class dynsec_ptrace_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_ptrace_msg)
    ]

# SIGNAL
class dynsec_signal_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('source', dynsec_task_ctx),
        ('signal', ctypes.c_int32),
        ('target', dynsec_task_ctx),
    ]
class dynsec_signal_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_signal_msg)
    ]

# TASK Internal struct for CLONE/EXIT events
# May split up into clone and exit structs
class dynsec_task_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('exec_file', dynsec_file), # Unused on exit events
    ]
class dynsec_task_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_task_msg)
    ]


# TASK_DUMP - May start dumping more fields
class dynsec_task_dump_msg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('task', dynsec_task_ctx),
        ('exec_file', dynsec_file),
    ]
class dynsec_task_dump_umsg(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('hdr', dynsec_msg_hdr),
        ('msg', dynsec_task_dump_msg)
    ]


########################
# Helper Python Classes
########################

class DYNSEC_HOOK_TYPE:
    EXEC = 0x00000001
    RENAME = 0x00000002
    UNLINK = 0x00000004
    RMDIR = 0x00000008
    MKDIR = 0x00000010
    CREATE = 0x00000020
    SETATTR = 0x00000040
    OPEN = 0x00000080
    LINK = 0x00000100
    SYMLINK = 0x00000200
    SIGNAL = 0x00000400
    PTRACE = 0x00000800
    MMAP = 0x00001000
    CLOSE = 0x00002000
    TASK_FREE = 0x00004000
    EXIT = 0x00008000
    CLONE = 0x00010000

    name_map = {
        EXEC: "EXEC",
        RENAME: "RENAME",
        UNLINK: "UNLINK",
        RMDIR: "RMDIR",
        MKDIR: "MKDIR",
        CREATE: "CREATE",
        SETATTR: "SETATTR",
        OPEN: "OPEN",
        LINK: "LINK",
        SYMLINK: "SYMLINK",
        SIGNAL: "SIGNAL",
        PTRACE: "PTRACE",
        MMAP: "MMAP",
        CLOSE: "CLOSE",
        TASK_FREE: "TASK_FREE",
        EXIT: "EXIT",
        CLONE: "CLONE",
    }

    def __init__(self):
        self.MASK = 0
        for mask in self.name_map:
            self.MASK |= mask

    def name(self, hooks):
        name_str = ""
        if hooks & self.MASK:
            for mask in self.name_map:
                if mask & hooks:
                    hooks &= ~mask
                    name_str += self.name_map[mask]
                    # Append separator
                    if hooks:
                        name_str += ","
        if hooks:
            name_str += "UNKNOWN:%#x" % (hooks,)
        return name_str


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

    name_map = {
        EXEC: "EXEC",
        RENAME: "RENAME",
        UNLINK: "UNLINK",
        RMDIR: "RMDIR",
        MKDIR: "MKDIR",
        CREATE: "CREATE",
        SETATTR: "SETATTR",
        OPEN: "OPEN",
        CLOSE: "CLOSE",
        LINK: "LINK",
        SYMLINK: "SYMLINK",
        SIGNAL: "SIGNAL",
        PTRACE: "PTRACE",
        MMAP: "MMAP",
        CLONE: "CLONE",
        EXIT: "EXIT",
        TASK_DUMP: "TASK_DUMP",
    }

    cast_map = {
        EXEC: dynsec_exec_umsg,
        RENAME: dynsec_rename_umsg,
        UNLINK: dynsec_unlink_umsg,
        RMDIR: dynsec_unlink_umsg,
        MKDIR: dynsec_create_umsg,
        CREATE: dynsec_create_umsg,
        SETATTR: dynsec_setattr_umsg,
        OPEN: dynsec_file_umsg,
        CLOSE: dynsec_file_umsg,
        LINK: dynsec_link_umsg,
        SYMLINK: dynsec_symlink_umsg,
        SIGNAL: dynsec_signal_umsg,
        PTRACE:  dynsec_ptrace_umsg,
        MMAP: dynsec_mmap_umsg,
        CLONE: dynsec_task_umsg,
        EXIT: dynsec_task_umsg,
        TASK_DUMP: dynsec_task_dump_umsg,
    }

    def name(self, event_type):
        if event_type in name_map:
            return name_map[event_type]
        else:
            return "event_type:%d" % (event_type,)

    def cast(self, hdr):
        if isinstance(hdr, dynsec_msg_hdr):
            if hdr.event_type in self.cast_map:
                return ctypes.cast(hdr, self.cast_map[hdr.event_type])
        elif isinstance(hdr, ctypes.POINTER(dynsec_msg_hdr)):
            if hdr.contents.event_type in self.cast_map:
                return ctypes.cast(hdr,
                    ctypes.POINTER(self.cast_map[hdr.contents.event_type]))
        return hdr


class DYNSEC_REPORT_FLAGS:
    STALL         = 0x0001
    INTENT        = 0x0002
    AUDIT         = 0x0004
    CACHED        = 0x0008
    SELF          = 0x0020
    HI_PRI        = 0x0040
    LO_PRI        = 0x0080
    INTENT_FOUND  = 0x0200

    name_map = {
        STALL: "STALL",
        INTENT: "INTENT",
        AUDIT: "AUDIT",
        CACHED: "CACHED",
        SELF: "SELF",
        HI_PRI: "HI_PRI",
        LO_PRI: "LO_PRI",
        INTENT_FOUND: "INTENT_FOUND",
    }

    STALL_OR_CACHED = (STALL|CACHED)

    def __init__(self):
        self.MASK = 0
        for mask in self.name_map:
            self.MASK |= mask

    def name(self, report_flags):
        name_str = ""
        if report_flags & self.MASK:
            for mask in self.name_map:
                if mask & report_flags:
                    report_flags &= ~mask
                    name_str += self.name_map[mask]
                    # Append separator
                    if report_flags:
                        name_str += ","
        if report_flags:
            name_str += "UNKNOWN:%#x" % (report_flags,)
        return name_str

# Wrap the helper classes that stringify and casting
class DynSec(object):
    def __init__(self):
        self.HOOK_TYPE = DYNSEC_HOOK_TYPE()
        self.EVENT_TYPE = DYNSEC_EVENT_TYPE()
        self.REPORT_FLAGS = DYNSEC_REPORT_FLAGS()

    def hook_type_name(self, hooks):
        return self.HOOK_TYPE.name(hooks)
    
    def event_type_name(self, event_type):
        return self.EVENT_TYPE.name(event_type)

    def report_flags_name(self, report_flags):
        return self.REPORT_FLAGS.name(report_flags)

    def cast(self, hdr):
        return self.EVENT_TYPE.cast(hdr)


#####################
# JSON Encoder Stuff
#####################

def encode_dynsec_file(dynsec_file, base_addr):
    file_path = ""
    if base_addr and dynsec_file.path_size and dynsec_file.path_offset > 1:
        file_path = ctypes.string_at(base_addr + dynsec_file.path_offset,
                        dynsec_file.path_size -1).decode('utf-8')
    return file_path

def encode_dynsec_blob(dynsec_blob, base_addr):
    blob = None
    if base_addr and dynsec_file.path_size and dynsec_blob.offset > 1:
        blob = ctypes.string_at(base_addr + dynsec_blob.offset,
                        dynsec_blob.size -1).decode('utf-8')
    return blob

class RawDynSecJSONEncoder(json.JSONEncoder):
    base_addr = 0

    def default(self, obj):
        if isinstance(obj, (ctypes.Array, list)):
            li = []
            for entry in obj:
                li.append(self.default(entry))
            return li

        if isinstance(obj, ctypes._Pointer):
            if obj:
                return self.default(obj.contents)
            return None

        if isinstance(obj, ctypes._SimpleCData):
            return self.default(obj.value)

        if isinstance(obj, bytes):
            return obj.decode('utf-8')

        if isinstance(obj, (bool, int, float, str)):
            return obj

        if obj is None:
            return obj

        if isinstance(obj, (ctypes.Structure, ctypes.Union)):
            result = {}

            # May be used for base_addr
            if isinstance(obj, dynsec_msg_hdr):
                self.base_addr = ctypes.addressof(obj)

            anonymous = getattr(obj, '_anonymous_', [])
            for key, *_ in getattr(obj, '_fields_', []):
                value = getattr(obj, key)
                if key in anonymous:
                    result.update(self.default(value))
                else:
                    result[key] = self.default(value)

                # Insert dynsec_file's path by name of field
                if isinstance(value, dynsec_file):
                    file_path_key = key + "_path"
                    result[file_path_key] = encode_dynsec_file(value, self.base_addr)
                if isinstance(value, dynsec_blob):
                    blob_key = key + "_blob"
                    result[blob_key] = encode_dynsec_blob(value, self.base_addr)

            return result

        return json.JSONEncoder.default(self, obj)
