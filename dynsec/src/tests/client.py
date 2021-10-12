# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0
import ctypes
from dynsec import *


#################################
# libdynsecclient.so Definitions
#################################

# Enum Helper Class for Event Hooks
class DYNSEC_EAT:
    ERROR = -1
    DEFAULT = 0
    DISCARD = 1
    KEEP = 2
    SHUTDOWN = 3

# struct client_tracking
class client_tracking(ctypes.Structure):
    MAX_TRACK_PIDS = 256
    _fields_ = [
        ('verbosity', ctypes.c_int),
        ('debug', ctypes.c_int),
        ('shutdown', ctypes.c_bool),
        ('follow_progeny', ctypes.c_bool),
        ('is_tracing', ctypes.c_bool),
        ('progeny', ctypes.c_int * MAX_TRACK_PIDS),
        ('max_index', ctypes.c_int)
    ]

# struct client_device
class client_device(ctypes.Structure):
    MAX_KMOD_NAME_LEN = 100
    _fields_ = [
        ('major', ctypes.c_uint),
        ('minor', ctypes.c_uint),
        ('proc_file', ctypes.c_char_p),
        ('kmod_search_str', ctypes.c_char_p),
        ('kmod_name', ctypes.c_char * MAX_KMOD_NAME_LEN)
    ]

# Prototype `struct dynsec_client`
class dynsec_client(ctypes.Structure):
    MAX_BUF_SZ = (1 << 15)
    pass

# function pointer to regular event callback
DYNSEC_EVENT_HOOK = ctypes.CFUNCTYPE(
    ctypes.c_int, # returns enum DYNSEC_EAT
    ctypes.POINTER(dynsec_client),
    ctypes.POINTER(dynsec_msg_hdr)
)

# function pointer to discarded event hook
DYNSEC_EVENT_DISCARD_HOOK = ctypes.CFUNCTYPE(
    ctypes.c_int, # returns enum DYNSEC_EAT
    ctypes.POINTER(dynsec_client),
    ctypes.POINTER(dynsec_msg_hdr),
    ctypes.c_bool # bool may_override
)

# function pointer to relase_hook
DYNSEC_RELEASE_HOOK = ctypes.CFUNCTYPE(
    None, # void
    ctypes.POINTER(dynsec_client)
)

# struct dynsec_client_ops
class dynsec_client_ops(ctypes.Structure):
    _fields_ = [
        ('event_hook', DYNSEC_EVENT_HOOK),
        ('event_discarded_hook', DYNSEC_EVENT_DISCARD_HOOK),
        ('release_hook', DYNSEC_RELEASE_HOOK)
    ]

# Define the _fields_ later for class dynsec_client
dynsec_client._fields_ = [
        ('fd', ctypes.c_int),
        ('buf', ctypes.c_char * dynsec_client.MAX_BUF_SZ),
        ('tracking', client_tracking),
        ('device', client_device),
        ('cache_flags', ctypes.c_uint32),
        ('ops', dynsec_client_ops),
        ('private_data', ctypes.c_void_p),
    ]

lib = ctypes.CDLL("./libdynsecclient.so", use_errno=True)

#
# Basic wrappers and ctype function constraints to C functions
#

# void dynsec_client_register(
#     struct dynsec_client *client,
#     uint32_t default_cache_flags,
#     const struct dynsec_client_ops *ops,
#     void *private_data);
lib.dynsec_client_register.restype = None
lib.dynsec_client_register.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_uint32,
    ctypes.POINTER(dynsec_client_ops),
    ctypes.c_void_p
]
def dynsec_client_register(client, cache_flags=0, ops=None, private_data=None):
    lib.dynsec_client_register(client, cache_flags, ops, private_data)

lib.dynsec_client_shutdown.restype = None
lib.dynsec_client_shutdown.argtypes = [ctypes.POINTER(dynsec_client)]
def dynsec_client_shutdown(client):
        return lib.dynsec_client_shutdown(client)

#int dynsec_client_connect(
#    struct dynsec_client *client,
#    int verbosity,
#    int debug,
#    bool is_tracing);
lib.dynsec_client_connect.restype = ctypes.c_int
lib.dynsec_client_connect.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_int,  # verbosity
    ctypes.c_int,  # debug
    ctypes.c_bool, # is_tracing
]
def dynsec_client_connect(client, verbosity=0, debug=0, is_tracing=False):
    return lib.dynsec_client_connect(client, 0, 0, False)

lib.dynsec_client_read_events.restype = ctypes.c_int
lib.dynsec_client_read_events.argtypes = [ctypes.POINTER(dynsec_client)]
def dynsec_client_read_events(client):
    return lib.dynsec_client_read_events(client)

#void dynsec_client_track_pid(
#    struct dynsec_client *client,
#    pid_t pid,
#    bool follow_progeny);
lib.dynsec_client_track_pid.restype = None
lib.dynsec_client_track_pid.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_int,  # pid
    ctypes.c_bool, # follow_progeny
]
def dynsec_client_track_pid(client, pid, follow_progeny=False):
    return lib.dynsec_client_track_pid(client, pid, follow_progeny)


# This is just helper to debug Python. Not ideal for regular use.
# void print_raw_event(struct dynsec_msg_hdr * hdr);
lib.print_event_raw.restype = None
lib.print_event_raw.argtypes = [ctypes.POINTER(dynsec_msg_hdr)]
def print_event_raw(hdr):
    lib.print_event_raw(hdr.contents)

# Config Getters and Setters
#int dynsec_client_get_config(
# struct dynsec_client *client,
# struct dynsec_config *config);
lib.dynsec_client_get_config.restype = ctypes.c_int
lib.dynsec_client_get_config.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.POINTER(dynsec_config),
]
def dynsec_client_get_config(client, config_ptr):
    config = dynsec_config()
    ret = lib.dynsec_client_get_config(client, config_ptr)
    return ret

# int dynsec_client_disable_bypass_mode(
# struct dynsec_client *client);
lib.dynsec_client_disable_bypass_mode.restype = ctypes.c_int
lib.dynsec_client_disable_bypass_mode.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_bypass_mode(client):
    return lib.dynsec_client_disable_bypass_mode(client)

# int dynsec_client_enable_bypass_mode(
# struct dynsec_client *client);
lib.dynsec_client_enable_bypass_mode.restype = ctypes.c_int
lib.dynsec_client_enable_bypass_mode.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_bypass_mode(client):
    return lib.dynsec_client_enable_bypass_mode(client)

# int dynsec_client_disable_stalling(
# struct dynsec_client *client);
lib.dynsec_client_disable_stalling.restype = ctypes.c_int
lib.dynsec_client_disable_stalling.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_bypass_mode(client):
    return lib.dynsec_client_disable_stalling(client)

# int dynsec_client_enable_stalling(
# struct dynsec_client *client);
lib.dynsec_client_enable_stalling.restype = ctypes.c_int
lib.dynsec_client_enable_stalling.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_enable_stalling(client):
    return lib.dynsec_client_enable_stalling(client)

# int dynsec_client_set_queue_options(
# struct dynsec_client *client,
# struct dynsec_config *config);
lib.dynsec_client_set_queue_options.restype = ctypes.c_int
lib.dynsec_client_set_queue_options.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.POINTER(dynsec_config),
]
def dynsec_client_set_queue_options(client, config_ptr):
    return lib.dynsec_client_set_queue_options(client, config_ptr)

# int dynsec_client_disable_lazy_notifier(
# struct dynsec_client *client);
lib.dynsec_client_disable_lazy_notifier.restype = ctypes.c_int
lib.dynsec_client_disable_lazy_notifier.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_lazy_notifier(client, config_ptr):
    return lib.dynsec_client_disable_lazy_notifier(client, config_ptr)

# int dynsec_client_enable_lazy_notifier(
# struct dynsec_client *client);
lib.dynsec_client_enable_stalling.restype = ctypes.c_int
lib.dynsec_client_enable_stalling.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_enable_stalling(client, config_ptr):
    return lib.dynsec_client_enable_stalling(client, config_ptr)


# int dynsec_client_set_notify_threshold(
# struct dynsec_client *client,
# uint32_t threshold);
lib.dynsec_client_set_notify_threshold.restype = ctypes.c_int
lib.dynsec_client_set_notify_threshold.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_uint32,
]
def dynsec_client_set_notify_threshold(client, threshold):
    return lib.dynsec_client_set_notify_threshold(client, threshold)

#int dynsec_client_disable_notify_threshold(struct dynsec_client *client)
lib.dynsec_client_disable_notify_threshold.restype = ctypes.c_int
lib.dynsec_client_disable_notify_threshold.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_notify_threshold(client):
    return lib.dynsec_client_disable_notify_threshold(client)

# int dynsec_client_set_queue_threshold(
# struct dynsec_client *client,
# uint32_t threshold);
lib.dynsec_client_set_queue_threshold.restype = ctypes.c_int
lib.dynsec_client_set_queue_threshold.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_uint32,
]
def dynsec_client_set_queue_threshold(client, threshold):
    return lib.dynsec_client_set_queue_threshold(client)

#int dynsec_client_disable_queue_threshold(struct dynsec_client *client)
lib.dynsec_client_disable_queue_threshold.restype = ctypes.c_int
lib.dynsec_client_disable_queue_threshold.argtypes = [
    ctypes.POINTER(dynsec_client),
]
def dynsec_client_disable_queue_threshold(client):
    return lib.dynsec_client_disable_queue_threshold(client)

#int dynsec_client_set_stall_timeout(
#struct dynsec_client *client,
#unsigned int timeout_ms);
lib.dynsec_client_set_stall_timeout.restype = ctypes.c_int
lib.dynsec_client_set_stall_timeout.argtypes = [
    ctypes.POINTER(dynsec_client),
    ctypes.c_uint,
]
def dynsec_client_set_stall_timeout(client, timeout_ms):
    return lib.dynsec_client_set_stall_timeout(client, timeout_ms)


# Below is a rough and dirty approach to testing RENAME
# within the connected client's THREAD GROUP. Event processing
# and event generating is performed in seperate thread from the
# main thread of the process.
# It provides an example of way of how to track very specific
# threads withing the client's thread group in only python.
if __name__ == '__main__':
    import os
    import sys
    import threading
    import json

    # Helper for tracking threads we just spawned of ourself
    _libc = ctypes.CDLL('libc.so.6')
    def get_tid():
        return _libc.syscall(186)

    OUR_SELF = []

    # Helper class to wrap some classes together
    dynsec = DynSec()

    # Thread to read events
    def read_events(client):
        OUR_SELF.append(get_tid())
        dynsec_client_read_events(client)

    # Thread to generate a rename event
    def rename_file(oldpath, newpath):
        OUR_SELF.append(get_tid())
        os.rename(oldpath, newpath)

    # We only care about events from ourself and child threads
    OUR_SELF.append(os.getpid())
    # Extra tracking to shutdown on failure of matching expected events
    OBSERVED_INTENT = False

    def only_print_ourself(client, hdr):
        global OBSERVED_INTENT

        # only care about ourself and RENAME events
        if hdr.contents.tid in OUR_SELF:
            if (hdr.contents.event_type == dynsec.EVENT_TYPE.RENAME):
                print("RENAME: report_flags:%s[%#x]" % (
                    dynsec.report_flags_name(hdr.contents.report_flags),
                    hdr.contents.report_flags,
                ))
                #print_event_raw(hdr)
                print(json.dumps(dynsec.cast(hdr), indent=1, cls=RawDynSecJSONEncoder))

                if (hdr.contents.report_flags & dynsec.REPORT_FLAGS.INTENT):
                    OBSERVED_INTENT = True
                # Shutdown Client. SELF
                # INTENT_FOUND is EXPECTED to be set in report_flags
                elif (OBSERVED_INTENT or
                      (hdr.contents.report_flags & dynsec.REPORT_FLAGS.INTENT_FOUND)):
                    return DYNSEC_EAT.SHUTDOWN

            return DYNSEC_EAT.DEFAULT

        # Drop the event
        return DYNSEC_EAT.DISCARD

    def discard(client, hdr, may_override):
        return DYNSEC_EAT.DEFAULT

    def release_cb(client):
        return None



    ##############
    # Actual Test
    ##############

    test_path = "foo"
    test_newpath = "bar"

    # Python allocates a `struct dynsec_client`
    client = dynsec_client()
    # Interfaces require a ptr, however byref might work better?
    client_ptr = ctypes.pointer(client)

    # Instantiate a `struct dynsec_client_ops`
    client_ops = dynsec_client_ops(
        DYNSEC_EVENT_HOOK(only_print_ourself),
        DYNSEC_EVENT_DISCARD_HOOK(discard),
        DYNSEC_RELEASE_HOOK(release_cb),
    )

    # Create test resources
    with open(test_path, 'w'):
        pass

    # Setup test infra
    read_thread = threading.Thread(target=read_events,
                                   args=(client_ptr,))
    rename_thread = threading.Thread(target=rename_file,
                                     args=(test_path, test_newpath,))
    dynsec_client_register(client_ptr, cache_flags=0,
                           ops=ctypes.byref(client_ops))

    # Run tests if client has a connection
    if dynsec_client_connect(client_ptr) >= 0:
        config = dynsec_config()
        ret = dynsec_client_get_config(client_ptr, ctypes.byref(config))
        if ret == 0:
            print("LSM Hooks Enabled: %s" %
                  (dynsec.hook_type_name(config.lsm_hooks)))
            print("Process Hooks Enabled: %s" %
                  ((dynsec.hook_type_name(config.process_hooks))))
            print("PreAction Hooks Enabled: %s" %
                  ((dynsec.hook_type_name(config.preaction_hooks))))

        read_thread.start()

        # Trigger events
        rename_thread.start()
        # Cleanup event generation thread
        rename_thread.join()
        # Cleanup event loop thread
        read_thread.join()

        # Destroy result resources
        os.unlink(test_newpath)
    else:
        # Remove setup resources
        os.unlink(test_path)
