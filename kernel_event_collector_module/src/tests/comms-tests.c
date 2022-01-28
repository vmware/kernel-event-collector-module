/* Copyright 2022 VMWare, Inc.  All rights reserved. */

#include "process-tracking.h"
#include "event-factory.h"
#include "path-buffers.h"
#include "dns-parser-private.h"
#include "mem-alloc.h"

#include "run-tests.h"

int ec_obtain_next_cbevent(struct CB_EVENT **cb_event, size_t count, ProcessContext *context);
bool __ec_connect_reader(ProcessContext *context);
void ec_user_comm_clear_queue(ProcessContext *context);

bool __init test__oversize_payload(ProcessContext *context);
bool __init test__normal_payload(ProcessContext *context);
bool __init test__parse_large_dns(ProcessContext *context);


bool __init test__comms(ProcessContext *context)
{
    DECLARE_TEST();

    uint32_t origTraceLevel = g_traceLevel;

    g_traceLevel |= (uint32_t) DL_COMMS;

    TRACE(DL_ERROR, "trace level: %xd", g_traceLevel);

    RUN_TEST(test__oversize_payload(context));
    RUN_TEST(test__normal_payload(context));
    RUN_TEST(test__parse_large_dns(context));

    g_traceLevel = origTraceLevel;

    RETURN_RESULT();
}

bool __init test__oversize_payload(ProcessContext *context)
{
    bool               passed     = false;
    struct task_struct *task      = current;
    pid_t              pid        = ec_getpid(task);
    pid_t              tid        = ec_gettid(task);
    uid_t              uid        = GET_UID();
    uid_t              euid       = GET_EUID();
    struct CB_EVENT    *msg       = NULL;
    uint64_t           device     = 0;
    uint64_t           inode      = 0;
    uint64_t           fs_magic   = 0;
    struct timespec    start_time = { 0, 0 };
    char               *pathname  = NULL;
    PathData           *path_data = NULL;
    ProcessHandle      *proch     = NULL;
    int                rc;

    pathname = ec_mem_alloc(PATH_MAX + 1, context);
    ASSERT_TRY(pathname);

    // Path with \0 will be PATH_MAX + 1
    memset(pathname, 'a', PATH_MAX);
    pathname[PATH_MAX] = 0;

    path_data = ec_path_cache_add(0, device, inode, pathname, fs_magic, context);
    ASSERT_TRY(path_data);

    proch = ec_process_tracking_update_process(
        pid,
        tid,
        uid,
        euid,
        path_data,
        ec_to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);

    ASSERT_TRY(proch);

    ec_process_tracking_set_proc_cmdline(proch, pathname, context);

    ENABLE_SEND_EVENTS(context);
    __ec_connect_reader(context);

    // With path and cmdline set to PATH_MAX + 1 this event should exceed the max event size and not get queued
    ec_event_send_file(
        proch,
        CB_EVENT_TYPE_FILE_WRITE,
        path_data,
        context);

    ec_disconnect_reader(context->pid, context);
    DISABLE_SEND_EVENTS(context);

    rc = ec_obtain_next_cbevent(&msg, sizeof(struct CB_EVENT_UM_BLOB), context);
    ASSERT_TRY_MSG(rc == -EAGAIN, "%d", rc);

    passed = true;

CATCH_DEFAULT:
    ec_process_tracking_remove_process(proch, context);
    ec_process_tracking_put_handle(proch, context);
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);
    ec_mem_put(pathname);
    ec_free_event(msg, context);
    ec_user_comm_clear_queue(context);

    return passed;
}

bool __init test__normal_payload(ProcessContext *context)
{
    bool               passed     = false;
    struct task_struct *task      = current;
    pid_t              pid        = ec_getpid(task);
    pid_t              tid        = ec_gettid(task);
    uid_t              uid        = GET_UID();
    uid_t              euid       = GET_EUID();
    struct CB_EVENT    *msg       = NULL;
    uint64_t           device     = 0;
    uint64_t           inode      = 0;
    uint64_t           fs_magic   = 0;
    struct timespec    start_time = { 0, 0 };
    char               *pathname  = NULL;
    PathData           *path_data = NULL;
    ProcessHandle      *proch     = NULL;
    int                rc;

    pathname = ec_mem_alloc(PATH_MAX, context);
    ASSERT_TRY(pathname);

    // path is PATH_MAX - 1
    memset(pathname, 'a', PATH_MAX - 2);
    pathname[PATH_MAX - 1] = 0;

    path_data = ec_path_cache_add(0, device, inode, pathname, fs_magic, context);
    ASSERT_TRY(path_data);

    proch = ec_process_tracking_update_process(
        pid,
        tid,
        uid,
        euid,
        path_data,
        ec_to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);

    ASSERT_TRY(proch);

    ec_process_tracking_set_proc_cmdline(proch, pathname, context);

    ENABLE_SEND_EVENTS(context);
    __ec_connect_reader(context);

    ec_event_send_file(
        proch,
        CB_EVENT_TYPE_FILE_WRITE,
        path_data,
        context);

    ec_disconnect_reader(context->pid, context);
    DISABLE_SEND_EVENTS(context);

    rc = ec_obtain_next_cbevent(&msg, sizeof(struct CB_EVENT_UM_BLOB), context);

    ASSERT_TRY_MSG(rc == sizeof(struct CB_EVENT_UM_BLOB), "%d", rc);

    passed = true;

CATCH_DEFAULT:
    ec_process_tracking_remove_process(proch, context);
    ec_process_tracking_put_handle(proch, context);
    ec_path_cache_delete(path_data, context);
    ec_path_cache_put(path_data, context);
    ec_mem_put(pathname);
    ec_free_event(msg, context);
    ec_user_comm_clear_queue(context);

    return passed;
}

bool __init test__parse_large_dns(ProcessContext *context)
{
    bool passed = false;
    const int reply_count = 10;
    dns_header_t   header = {
        .qdcount = htons(1),
        .ancount = htons(reply_count),
        .is_response = 1,
        .response_code = 0
    };
    const char *dns_name = "host";
    const size_t dns_name_size = strlen(dns_name);
    char *dns_data = NULL;
    CB_EVENT_DNS_RESPONSE  response = { 0 };
    int pos = 0;
    int i;
    size_t dns_data_size;
    int rc;

    // We want to verify we can handle a total size greater than the allowed size of PATH_MAX
    ASSERT_TRY(header.ancount * sizeof(CB_DNS_RECORD) > PATH_MAX);

    dns_data_size = sizeof(dns_header_t)
                    + 1 + dns_name_size + 1
                    + sizeof(dns_question_t)
                    + (1 + dns_name_size + 1 + sizeof(dns_resource_info_t) + sizeof(struct in_addr)) * reply_count;

    dns_data = ec_mem_alloc(dns_data_size, context);
    ASSERT_TRY(dns_data);

    memcpy(dns_data, &header, sizeof(dns_header_t));
    pos += sizeof(dns_header_t);

    // first byte is size
    dns_data[pos++] = dns_name_size;
    memcpy(&dns_data[pos], dns_name, dns_name_size);
    pos += dns_name_size;
    // end of name
    dns_data[pos++] = 0;

    pos += sizeof(dns_question_t);

    for (i = 0;i < reply_count;i++)
    {
        dns_resource_info_t *resource_info;
        struct in_addr *addr;

        ASSERT_TRY(pos < dns_data_size);

        // first byte is size
        dns_data[pos++] = dns_name_size;
        memcpy(&dns_data[pos], dns_name, dns_name_size);
        pos += dns_name_size;
        // end of name
        dns_data[pos++] = 0;

        resource_info = (dns_resource_info_t *)&dns_data[pos];
        resource_info->dnstype = htons(QT_A);
        resource_info->length = htons(sizeof(dns_resource_info_t) + sizeof(struct in_addr));
        pos += sizeof(dns_resource_info_t);
        addr = (struct in_addr *)&dns_data[pos];
        addr->s_addr = 0;
        pos += sizeof(struct in_addr);
    }

    rc = ec_dns_parse_data(dns_data, pos, &response, context);

    ASSERT_TRY_MSG(rc == 0, "rc: %d", rc);

    ASSERT_TRY_MSG(response.record_count > 0 && response.record_count * sizeof(CB_DNS_RECORD) <= PATH_MAX,
                   "record_count: %d, total: %zu", response.record_count, response.record_count * sizeof(CB_DNS_RECORD));

    passed = true;

CATCH_DEFAULT:
    ec_mem_free(dns_data);
    ec_mem_free(response.records);
    ec_user_comm_clear_queue(context);

    return passed;
}
