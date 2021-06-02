// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.
/* Copyright 2018 Carbon Black Inc.  All rights reserved. */

#include "logging.h"
#include "usercomm.h"
#include "usercomm_msgs.h"

#include <linux/hashtable.h>
#include <linux/delay.h>
#include <linux/limits.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <asm/atomic.h>
#include <linux/semaphore.h>

#define KMSG_TYPE_CONNECT 0
#define KMSG_TYPE_RESPONSE 1
#define KMSG_TYPE_REQUEST 2

////////////////////////////////////////////////////////////////////////////////
// Stall Table
//
// When a request to usermode is made, the calling context is stalled until
// usermode responsds.  The stalled context of that operation is stored in a
// hashtable that is keyed off the unique request ID.
//
struct um_stall_entry {
    struct hlist_node node;
    int key;
    int result;
    struct semaphore sem;
};

static atomic_t p_stall_request;

static struct kmem_cache *um_stall_kmem_cache;

// Use 2^9 (512) size hashtable for stalls
static DEFINE_HASHTABLE(um_stall_table, 9);
//
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// General usermode comms
//
// Netlink socket for sending/receiving requests/response to/from usermode.
static struct sock* p_nl_sock;

// Track how many responses we get.
static atomic_t p_cb_count;

// The pid of the connected daemon. 0 if the daemon is not connected.
static int p_connected_pid;
//
////////////////////////////////////////////////////////////////////////////////


bool user_connected(void)
{
    return (p_connected_pid != 0);
}

// Add a stall entry to the hashtable in anticipation of making a request.
struct um_stall_entry* prepare_for_response(int req_id)
{
    struct um_stall_entry* entry;
    
    entry = kmem_cache_zalloc(um_stall_kmem_cache, GFP_NOFS);
    
    entry->key = req_id;
    entry->result = OPC_RESULT_ALLOWED;
    sema_init(&entry->sem, 0);
    
    hash_add_rcu(um_stall_table, &entry->node, req_id);
    
    return entry;
}

// Actually stall and wait for the response.  Remove the cache entry either on
// timeout(TBD) or when a response is received from usermode.
int wait_for_response(struct um_stall_entry* entry)
{
    int res = OPC_RESULT_ALLOWED;

    // This will block until sem is signaled
    down(&entry->sem);

    // Capture the response result from usermode.
    res = entry->result;
    
    // Clean up.
    hash_del(&entry->node);
    kmem_cache_free(um_stall_kmem_cache, entry);

    return res;
}

// When a response from usermode is received, the stall entry for the blocking
// context must be signaled and removed. The stall is keyed off the request ID.
// The reponse parameter is the the actual allow/deny result determined in
// usermode.
//
void unstall_op(int req_id, int response)
{
    struct um_stall_entry* entry;
    struct hlist_node* tmp;
    int found = 0;

    // Do a safe (from delete) search on the hash table for the entry.
    // Safe search is used since another context might be freeing a stalled
    // entry.
    hash_for_each_possible_safe(um_stall_table, entry, tmp, node, req_id) {
        if (entry->key == req_id) {
            entry->result = response;
            up(&entry->sem);
            found++;
        }
    }

    // Sanity Checks
    if (found == 0)
    {
        DS_LOG(DS_ERROR, "No stalled op found for request[%d]", req_id);
    }
    
    if (found > 1)
    {
        DS_LOG(DS_ERROR, "Multiple[%d] entries found for stalled op request[%d]", found, req_id);
    }
}

//
// Call to usercomm to determine if the operation captured in ctx is allowed.
// Returns OPC_RESULT_DENIED if operation is specifically blocked, otherwise
//         OPC_RESULT_ALLOWED
//
// TODO: Add alternate return results of could not determine and/or timeout
//
int usercomm_is_op_allowed(const struct opcache_ctx* ctx){
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    struct kmsg_request rqst;
    int msg_size;
    int res;
    struct um_stall_entry* entry;
    char* path;

    // Don't enforce if there is no daemon connected.
    if (p_connected_pid == 0)
    {
        return OPC_RESULT_ALLOWED;
    }
    
    msg_size = sizeof(rqst);

    // Initialize request and give it a unique ID
    rqst.msg_type = KMSG_TYPE_REQUEST;
    rqst.req_id = atomic_inc_return(&p_stall_request);
    rqst.op = ctx->op;
    rqst.pid = ctx->pid;
    rqst.uid = ctx->uid;
    rqst.euid = ctx->euid;
    rqst.ino = ctx->ino;
    rqst.dev = ctx->dev;

    // dentry_path_raw fills the buffer from the back end to the front so
    // we must track the index to the first character.
    memset(rqst.path, 0, sizeof(rqst.path));
    path = dentry_path_raw(ctx->dentry, rqst.path, sizeof(rqst.path));
    if ((u64)(path) == -ENAMETOOLONG) {
        DS_LOG(DS_ERROR, "Error getting dentry path");
        return OPC_RESULT_ALLOWED;
    }
    
    rqst.path_index = (int)(path - rqst.path);
    
    DS_LOG(DS_VERBOSE, "Got path of [%s] [%s] from dentry index[%d] path_at_index[%s].", rqst.path, path, (int)(path - rqst.path), &rqst.path[(int)(path - rqst.path)]);
    
    // Create a cache entry for the stall before sending the message since the
    // response from usermode could beat the creation the stall entry is created
    // after the message is sent.
    entry = prepare_for_response(rqst.req_id);
    if (!entry) {
        DS_LOG(DS_ERROR, "Failed to allocate response entry");
        return OPC_RESULT_ALLOWED;
    }
    
    // Send the msg from kernel to the user
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        DS_LOG(DS_ERROR, "Failed to allocate new skb");
        return OPC_RESULT_ALLOWED;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), &rqst, msg_size);
    
    res = nlmsg_unicast(p_nl_sock, skb_out, p_connected_pid);
    
    if (res) {
        DS_LOG(DS_ERROR, "Error while sending back to usermode pid[%d]", p_connected_pid);
        p_connected_pid = 0;
        // TODO: unstall any contexts waiting on usermode responses.
        return OPC_RESULT_ALLOWED;
    }
    
    DS_LOG(DS_VERBOSE, "Sent request to usermode pid[%d]; waiting on response", p_connected_pid);

    res = wait_for_response(entry);
    
    return res;
}

//
// The netlink callback.  Parse the message and act accordingly.
//
static void nl_callback(struct sk_buff* skb){
    int count = 0;
    struct nlmsghdr *nlh;
    struct kmsg_hdr* hdr = NULL;
    struct kmsg_response* krsp = NULL;

    nlh = (struct nlmsghdr*)skb->data;
    hdr = (struct kmsg_hdr*)(NLMSG_DATA(nlh));

    DS_LOG(DS_VERBOSE, "Got message from pid[%d] from usermode.", nlh->nlmsg_pid);
    
    if (((p_connected_pid != 0) && (nlh->nlmsg_pid != p_connected_pid)) &&
        (hdr->msg_type != KMSG_TYPE_CONNECT ))
    {
        DS_LOG(DS_ERROR, "Ignoring message from unknown process.");
        return;
    }

    switch (hdr->msg_type)
    {
        case KMSG_TYPE_CONNECT:
        {
            p_connected_pid = nlh->nlmsg_pid;
            DS_LOG(DS_INFO, "Connected to pid[%d] from usermode.", p_connected_pid);
            break;
        }
        case KMSG_TYPE_RESPONSE:
        {
            krsp = (struct kmsg_response*)(hdr);
            unstall_op(krsp->req_id, krsp->response);
            break;
        }
        default:
        {
            DS_LOG(DS_ERROR, "Unknown msg type received from usermode");
        }
    }

    atomic_inc(&p_cb_count);
    
    count = atomic_read(&p_cb_count);
    if ((count % 1000) == 0) {
        DS_LOG(DS_INFO, "Received %d callbacks from usermode.", count);
    }
    
}

// Initialize usercomm resources
int usercomm_init(void){

    struct netlink_kernel_cfg cfg = { .input = nl_callback };

    // Initialize counters
    atomic_set(&p_cb_count, 0);
    atomic_set(&p_stall_request, 0);

    // Start in disconnected state
    p_connected_pid = 0;
    
    // Create an allocator for stall entries
    um_stall_kmem_cache = KMEM_CACHE(um_stall_entry, 0);
    if (!um_stall_kmem_cache) {
        return -ENOMEM;
    }
    
    // Creaate the netlink socket.
    p_nl_sock = netlink_kernel_create(
                                 &init_net,
                                 NETLINK_DYNSEC,
                                 &cfg);
    if (p_nl_sock == NULL) {
        DS_LOG(DS_ERROR, "DynSec -- Can't create netlink.");
        return -ENOMEM;
    }
    return 0;
}

// Release usercomm resources
int usercomm_exit(void){
    struct um_stall_entry* entry;
    struct hlist_node* tmp;
    int i;

    // Shutdown comms.
    netlink_kernel_release(p_nl_sock);

    // Signal everything in the stall cache; freed contexts
    // should remove their entries.
    hash_for_each_safe(um_stall_table, i, tmp, entry, node) {
        entry->result = OPC_RESULT_ALLOWED;
        up(&entry->sem);
    }

    kmem_cache_destroy(um_stall_kmem_cache);
    
    return 0;
}

