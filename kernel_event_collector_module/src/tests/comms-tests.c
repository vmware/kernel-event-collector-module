/* Copyright 2022 VMWare, Inc.  All rights reserved. */

#include "process-tracking.h"
#include "event-factory.h"
#include "path-buffers.h"
#include "run-tests.h"
#include "dns-parser-private.h"

int ec_obtain_next_cbevent(struct CB_EVENT **cb_event, size_t count, ProcessContext *context);
bool __ec_connect_reader(ProcessContext *context);
unsigned int ec_device_poll(struct file *filp, struct poll_table_struct *pts);
void ec_user_comm_clear_queues(ProcessContext *context);

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
    struct timespec    start_time = { 0, 0 };
    char               *pathname  = ec_get_path_buffer(context);
    ProcessTracking    *procp     = NULL;
    int                rc;

    ASSERT_TRY(pathname);

    // Path with \0 will be PATH_MAX + 1
    memset(pathname, 'a', PATH_MAX);
    pathname[PATH_MAX] = 0;

    procp = ec_process_tracking_update_process(
        pid,
        tid,
        uid,
        euid,
        device,
        inode,
        pathname,
        true,
        ec_to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);

    ASSERT_TRY(procp);

    ec_process_tracking_set_cmdline(procp, pathname, context);

    ENABLE_SEND_EVENTS(context);
    __ec_connect_reader(context);

    ec_event_send_file(
        procp,
        CB_EVENT_TYPE_FILE_WRITE,
        INTENT_REPORT,
        device,
        inode,
        pathname,
        context);

    ec_disconnect_reader(context->pid);
    DISABLE_SEND_EVENTS(context);

    // With path and cmdline set to PATH_MAX + 1 this event should exceed the max event size
    // so poll should return 0 since the event will have failed to insert
    ASSERT_TRY(ec_device_poll(NULL, NULL) == 0);

    rc = ec_obtain_next_cbevent(&msg, sizeof(struct CB_EVENT_UM_BLOB), context);

    ASSERT_TRY(rc == -ENOMEM);

    // poll should return 0 since the queue should now be empty
    ASSERT_TRY(ec_device_poll(NULL, NULL) == 0);

    passed = true;

CATCH_DEFAULT:
    ec_put_path_buffer(pathname);
    ec_process_tracking_remove_process(procp, context);
    ec_process_tracking_put_process(procp, context);
    //ec_process_tracking_report_exit(pid, context);
    ec_free_event(msg, context);
    ec_user_comm_clear_queues(context);

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
    struct timespec    start_time = { 0, 0 };
    char               *pathname  = ec_get_path_buffer(context);
    ProcessTracking    *procp     = NULL;
    int                rc;

    ASSERT_TRY(pathname);

    // path is PATH_MAX - 1
    memset(pathname, 'a', PATH_MAX - 2);
    pathname[PATH_MAX - 1] = 0;

    procp = ec_process_tracking_update_process(
        pid,
        tid,
        uid,
        euid,
        device,
        inode,
        pathname,
        true,
        ec_to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_EXEC,
        task,
        CB_EVENT_TYPE_PROCESS_START_EXEC,
        FAKE_START,
        context);

    ASSERT_TRY(procp);

    ec_process_tracking_set_cmdline(procp, pathname, context);

    ENABLE_SEND_EVENTS(context);
    __ec_connect_reader(context);

    ec_event_send_file(
        procp,
        CB_EVENT_TYPE_FILE_WRITE,
        INTENT_REPORT,
        device,
        inode,
        pathname,
        context);

    ec_disconnect_reader(context->pid);
    DISABLE_SEND_EVENTS(context);

    // poll should return non-zero since the queue should not be empty
    ASSERT_TRY(ec_device_poll(NULL, NULL) != 0);

    rc = ec_obtain_next_cbevent(&msg, sizeof(struct CB_EVENT_UM_BLOB), context);

    ASSERT_TRY(rc == sizeof(struct CB_EVENT_UM_BLOB));

    // poll should return 0 since the queue should now be empty
    ASSERT_TRY(ec_device_poll(NULL, NULL) == 0);

    passed = true;

CATCH_DEFAULT:
    ec_process_tracking_remove_process(procp, context);
    ec_process_tracking_put_process(procp, context);
    //ec_process_tracking_report_exit(pid, context);
    ec_put_path_buffer(pathname);
    ec_free_event(msg, context);
    ec_user_comm_clear_queues(context);

    return passed;
}

bool __init test__parse_dns(ProcessContext *context)
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

    ASSERT_TRY(header.ancount * sizeof(CB_DNS_RECORD) > PATH_MAX);

    dns_data_size = sizeof(dns_header_t)
                    + 1 + dns_name_size + 1
                    + sizeof(dns_question_t)
                    + (1 + dns_name_size + 1 + sizeof(dns_resource_info_t) + sizeof(struct in_addr)) * reply_count;

    dns_data = ec_mem_cache_alloc_generic(dns_data_size, context);
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
    ec_mem_cache_free_generic(dns_data);
    ec_user_comm_clear_queues(context);

    return passed;
}
