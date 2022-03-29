// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "net-tracking.h"
#include "net-helper.h"
#include "hash-table.h"
#include "cb-spinlock.h"

#include <linux/inet.h>

typedef struct table_key {
    uint32_t        pid;
    uint16_t        proto;
    CB_SOCK_ADDR    laddr;
    CB_SOCK_ADDR    raddr;
} NET_TBL_KEY;

typedef struct table_value {
    struct timespec  last_seen;
    uint64_t         count;
    uint16_t         conn_dir;
} NET_TBL_VALUE;

typedef struct table_node {
    NET_TBL_KEY       key;
    NET_TBL_VALUE     value;
} NET_TBL_NODE;

void __ec_net_tracking_print_message(const char *message, NET_TBL_NODE *node);
void __ec_net_tracking_set_key(NET_TBL_KEY    *key,
                      pid_t           pid,
                      CB_SOCK_ADDR   *localAddr,
                      CB_SOCK_ADDR   *remoteAddr,
                      uint16_t        proto,
                      CONN_DIRECTION  conn_dir);
int __ec_print_net_tracking(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context);
bool __ec_net_tracking_check_cache(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir);

//TODO pick appropriate size
#define NET_TBL_SIZE     2048
#define NET_LRU_SIZE     4

static HashTbl __read_mostly s_net_hash_table = {
    .numberOfBuckets = NET_TBL_SIZE,
    .name = "network_tracking_table",
    .datasize = sizeof(NET_TBL_NODE),
    .key_len     = sizeof(NET_TBL_KEY),
    .key_offset  = offsetof(NET_TBL_NODE, key),
    .lruSize = NET_LRU_SIZE,
};


bool ec_net_tracking_initialize(ProcessContext *context)
{
    return ec_hashtbl_init(&s_net_hash_table, context);
}

void ec_net_tracking_shutdown(ProcessContext *context)
{
    ec_hashtbl_destroy(&s_net_hash_table, context);
}

// Track this connection in the local table
//  If it is a new connection, add an entry and send an event (return value of true)
//  If it is a tracked connection, update the time and skip sending an event (return value of false)
bool ec_net_tracking_check_cache(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir)
{
    bool added_entry = __ec_net_tracking_check_cache(context, pid, localAddr, remoteAddr, proto, conn_dir);

    // If this is UDP we need to do a little extra work
    if (added_entry && proto == IPPROTO_UDP)
    {
        // If we added an entry it means that this connection was not already tracked,
        //  which would normally cause an event to be generated.
        //  For UDP we hook the data path, and it is impossible to know the real direction of the connection.
        //  We want to check to make sure we are not tracking the opposite direction for this connection.
        added_entry = __ec_net_tracking_check_cache(
            context,
            pid,
            localAddr,
            remoteAddr,
            proto,
            conn_dir == CONN_IN ? CONN_OUT : CONN_IN);
    }

    return added_entry;
}

bool __ec_net_tracking_check_cache(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir)
{
    bool xcode = false;
    NET_TBL_KEY key;
    NET_TBL_NODE *node;

    // Build the key
    __ec_net_tracking_set_key(&key, pid, localAddr, remoteAddr, proto, conn_dir);

    // Check to see if this item is already tracked
    node = ec_hashtbl_find(&s_net_hash_table, &key, context);

    if (!node)
    {
        xcode = true;
        node = (NET_TBL_NODE *) ec_hashtbl_alloc(&s_net_hash_table, context);
        TRY_MSG(node, DL_ERROR, "Failed to allocate a network tracking node, event will be sent!");

        memcpy(&node->key, &key, sizeof(NET_TBL_KEY));
        node->value.count = 0;
        node->value.conn_dir = conn_dir;

        __ec_net_tracking_print_message("ADD", node);

        TRY_DO_MSG(!ec_hashtbl_add(&s_net_hash_table, node, context),
                   { ec_hashtbl_free(&s_net_hash_table, node, context); },
                   DL_ERROR, "Failed to add a network tracking node, event will be sent!");
    }

    // Update the last seen time and count
    getnstimeofday(&node->value.last_seen);
    ++node->value.count;

CATCH_DEFAULT:

    ec_hashtbl_put(&s_net_hash_table, node, context);
    return xcode;
}

void __ec_net_tracking_print_message(const char *message, NET_TBL_NODE *node)
{
    uint16_t  rport                         = 0;
    uint16_t  lport                         = 0;
    char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
    char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

    ec_ntop(&node->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
    ec_ntop(&node->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
    TRACE(DL_NET_TRACKING, "NET-TRACK <%s> %u %s-%s laddr=%s:%u raddr=%s:%u",
          message,
          node->key.pid,
          PROTOCOL_STR(node->key.proto),
          (node->value.conn_dir == CONN_IN ? "in" : (node->value.conn_dir == CONN_OUT ? "out" : "??")),
          laddr_str, ntohs(lport), raddr_str, ntohs(rport));
}

struct priv_data {
    struct timespec time;
    uint32_t        count;
};

// Completely purge the network tracking table
ssize_t ec_net_track_purge(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ec_hashtbl_clear(&s_net_hash_table, &context);

    return size;
}

int ec_net_track_show(struct seq_file *m, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ec_hashtbl_read_for_each(&s_net_hash_table, __ec_print_net_tracking, m, &context);

    return 0;
}

int __ec_print_net_tracking(HashTbl *hashTblp, void *datap, void *priv, ProcessContext *context)
{
    NET_TBL_NODE *net_data = (NET_TBL_NODE *)datap;
    struct seq_file *m = priv;

    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    if (net_data)
    {
        uint16_t  rport                         = 0;
        uint16_t  lport                         = 0;
        char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
        char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

        ec_ntop(&net_data->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
        ec_ntop(&net_data->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
        seq_printf(m, "NET-TRACK %d %s-%s %s:%u -> %s:%u (%d)\n",
                   net_data->key.pid,
                   PROTOCOL_STR(net_data->key.proto),
                   (net_data->value.conn_dir == CONN_IN ? "in" : (net_data->value.conn_dir == CONN_OUT ? "out" : "??")),
                   laddr_str, ntohs(lport), raddr_str, ntohs(rport),
                   (int)net_data->value.last_seen.tv_sec);
    }

    return ACTION_CONTINUE;

CATCH_DISABLED:
    return ACTION_STOP;
}

void __ec_net_tracking_set_key(NET_TBL_KEY    *key,
                      pid_t           pid,
                      CB_SOCK_ADDR   *localAddr,
                      CB_SOCK_ADDR   *remoteAddr,
                      uint16_t        proto,
                      CONN_DIRECTION  conn_dir)
{
    memset(key, 0, sizeof(NET_TBL_KEY));

    ec_copy_sockaddr(&key->laddr, localAddr);
    ec_copy_sockaddr(&key->raddr, remoteAddr);

    // Network applications tend to randomize the source port, so in order to
    //  reduce the number of reported network connections we ignore the source port.
    //  (Which one that is depends on the direction.)
    if (conn_dir == CONN_IN)
    {
        ec_set_sockaddr_port(&key->raddr, 0);
    } else if (conn_dir == CONN_OUT)
    {
        ec_set_sockaddr_port(&key->laddr, 0);
    } else
    {
        TRACE(DL_WARNING, "Unexpected netconn direction: %d", conn_dir);
    }

    key->pid      = pid;
    key->proto    = proto;
}
