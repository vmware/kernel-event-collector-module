// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "net-helper.h"
#include "network-tracking.h"
#include "hash-table-generic.h"
#include "process-tracking.h"
#include "event-factory.h"
#include "cb-spinlock.h"
#include <net/ip.h>
#include <net/sock.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <linux/uio.h>
#include <linux/audit.h>
#include <linux/sctp.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/file.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/inet.h>
#endif
#include "cb-isolation.h"
#include "process-tracking.h"
#include "cb-banning.h"

#define UDP_PACKET_TIMEOUT   (30 * HZ)

int64_t recvmsg_cnt;
uint64_t rcv_skb_cnt;
uint64_t relnode_cnt;
#define NETHOOK_RECVMSG_STAT_THROTTLE 100

// The MSG_UDP_HOOK flag is used skip the receive LSM hook so we can call our logic manually.
// This may clash with kernel added flags later!
#define MSG_UDP_HOOK 0x01000000

// Size of IOV buffer that we use to peek at the incoming UDP message
#define IOV_FOR_MSG_PEEK_SIZE 32

typedef enum _conn_direction {
    CONN_IN  = 1,
    CONN_OUT = 2
} CONN_DIRECTION;

typedef struct table_key {
    uint32_t        pid;
    uint16_t        proto;
    uint16_t        conn_dir;
    CB_SOCK_ADDR    laddr;
    CB_SOCK_ADDR    raddr;
} NET_TBL_KEY;

typedef struct table_value {
    struct timespec  last_seen;
    uint64_t         count;
} NET_TBL_VALUE;

typedef struct table_node {
    HashTableNode     link;
    NET_TBL_KEY       key;
    NET_TBL_VALUE     value;
    struct list_head  ageList;
} NET_TBL_NODE;

static void net_tracking_print_message(const char *message, NET_TBL_KEY *key);

HashTbl *g_net_hash_table;

static struct delayed_work net_track_work;
static void network_tracking_task(struct work_struct *work);
static uint32_t g_ntt_delay;

uint64_t g_net_age_lock;
LIST_HEAD(g_net_age_list);

#define NET_TBL_SIZE     262000
#define NET_TBL_PURGE    200000

// checkpatch-ignore: COMPLEX_MACRO,MULTISTATEMENT_MACRO_USE_DO_WHILE,TRAILING_SEMICOLON,LINE_CONTINUATIONS,MACRO_WITH_FLOW_CONTROL
#define TIMED_RECV(recv_func, sock, dlta, our_timeout, return_code) {                                    \
    if (sock && sock->sk)                                                                                \
    {                                                                                                    \
        do {                                                                                             \
            /* Figure out when we expect our timer to exit so we can check for that later */             \
            unsigned long expire = sock->sk->sk_rcvtimeo + jiffies;                                      \
            mm_segment_t oldfs = get_fs();                                                               \
            set_fs(get_ds());                                                                            \
            /* Call the system call to get the packet data */                                            \
            return_code = recv_func;                                                                     \
            set_fs(oldfs);                                                                               \
            /* If there was time left on the timer, it means that we either received some data or        \
             * something is wrong with the socket (some applications cause it to close early).           \
             * In either case we want to exit the loop now.                                              \
             */                                                                                          \
            if (time_before(jiffies, expire))                                                            \
            {                                                                                            \
                break;                                                                                   \
            }                                                                                            \
            /* If the module is exiting we need to return from the function. */                          \
            if (g_exiting)                                                                               \
            {                                                                                            \
                /* If this is a timeout value that we asked for than simulate receiving a zero           \
                 * byte packet.  Otherwise we will return with a possibly collected packet.              \
                 */                                                                                      \
                if (our_timeout && return_code == -EAGAIN)                                               \
                {                                                                                        \
                    return_code = 0;                                                                     \
                }                                                                                        \
                break;                                                                                   \
            }                                                                                            \
            /* The caller has set a timeout value larger than what we use, we want to subtract           \
             * from it after each of our timeouts.  When the last timeout will cause their timeout       \
             * to expire we configure the system to return the EAGAIN.                                   \
             */                                                                                          \
            if (dlta)                                                                                    \
            {                                                                                            \
                dlta -= UDP_PACKET_TIMEOUT;                                                              \
                /* We don't want to set sock->sk->sk_rcvtimeo to 0, it would mean infinite timeout */    \
                if (dlta <= 0)                                                                           \
                {                                                                                        \
                    /* If we're here it means we didn't receive data and xcode has error code now */     \
                    break;                                                                               \
                }                                                                                        \
                else if (dlta < UDP_PACKET_TIMEOUT)                                                      \
                {                                                                                        \
                    sock->sk->sk_rcvtimeo = dlta;                                                        \
                }                                                                                        \
            }                                                                                            \
        } while (our_timeout && return_code == -EAGAIN);                                                 \
    }                                                                                                    \
}

#define PEEK(CONTEXT, recv_func, sock, msg_peek, sk_rcvtimeo_dlta, our_timeout, flags, return_code) {          \
    /* Execute a recv function to peek at the message */                                                       \
    TIMED_RECV(recv_func, sock, sk_rcvtimeo_dlta, our_timeout, return_code);                                   \
                                                                                                               \
    /* TIMED_RECV may return if the module is exiting, in this case just return from this function */          \
    if (g_exiting)                                                                                             \
    {                                                                                                          \
        goto CATCH_DEFAULT;                                                                                    \
    }                                                                                                          \
                                                                                                               \
    TRY(return_code >= 0);                                                                                     \
    TRY(sock && sock->sk);                                                                                     \
                                                                                                               \
    /* Call our local code to process the packet for event generation and isolation */                         \
    TRY_SET(-EPERM != _socket_recvmsg(CONTEXT, sock, &msg_peek, 0, flags), -EPERM);                            \
                                                                                                               \
    /* If we peeked at UDP message sk_rcvtimeo_dlta is what's left from original timeout value.                \
     * Unless a caller set original timeout value to 0 sk_rcvtimeo_dlta should be greater than 0 here          \
     * since we check return code of the recv call above and if it's less than 0 we exit from the function     \
     * as this means that either no data is received and timeout expired or                                    \
     * remote peer terminated connection.                                                                      \
     */                                                                                                        \
    if (our_timeout)                                                                                           \
    {                                                                                                          \
        if (0 == sk_rcvtimeo_dlta || sk_rcvtimeo_dlta > UDP_PACKET_TIMEOUT)                                    \
        {                                                                                                      \
            sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;                                                        \
        }                                                                                                      \
        else                                                                                                   \
        {                                                                                                      \
            sock->sk->sk_rcvtimeo = sk_rcvtimeo_dlta;                                                          \
            our_timeout = false;                                                                               \
        }                                                                                                      \
    }                                                                                                          \
}

#define CHECK_UDP_PEEK(sock, flags, _flags, bUdpPeek)             \
if (CHECK_SOCKET(sock) && IPPROTO_UDP == sock->sk->sk_protocol)   \
{                                                                 \
    _flags = flags;                                               \
    _flags |= MSG_UDP_HOOK;                                       \
    if (!(_flags & MSG_ERRQUEUE))                                 \
    {                                                             \
        _flags |= MSG_PEEK;                                       \
        bUdpPeek = true;                                          \
    }                                                             \
}
// checkpatch-no-ignore: COMPLEX_MACRO,MULTISTATEMENT_MACRO_USE_DO_WHILE,TRAILING_SEMICOLON,LINE_CONTINUATIONS,MACRO_WITH_FLOW_CONTROL

static void udp_init_sockets(void);

bool network_tracking_initialize(ProcessContext *context)
{
    // Initialize the delayed work timeout value.  This will check for timed out network
    //  connections every 15 minutes.
    g_ntt_delay = msecs_to_jiffies(15 * 60 * 1000);
    g_net_hash_table = hashtbl_init_generic(context,
                                             NET_TBL_SIZE,
                                             sizeof(NET_TBL_NODE),
                                             0,
                                             "network_tracking_table",
                                             sizeof(NET_TBL_KEY),
                                             offsetof(NET_TBL_NODE, key),
                                             offsetof(NET_TBL_NODE, link),
                                             HASHTBL_DISABLE_REF_COUNT,
                                             NULL);
    TRY(g_net_hash_table);

    cb_spinlock_init(&g_net_age_lock, context);

    // Configure any already running UDP sockets
    udp_init_sockets();

    // Initialize a workque struct to police the hashtable
    INIT_DELAYED_WORK(&net_track_work, network_tracking_task);
    schedule_delayed_work(&net_track_work, g_ntt_delay);

CATCH_DEFAULT:
    return g_net_hash_table != NULL;
}

void network_tracking_shutdown(ProcessContext *context)
{
   /*
    * Calling the sync flavor gives the guarantee that on the return of the
    * routine, work is not pending and not executing on any CPU.
    *
    * Its supposed to work even if the work schedules itself.
    */

    cancel_delayed_work_sync(&net_track_work);
    hashtbl_shutdown_generic(g_net_hash_table, context);
    cb_spinlock_destroy(&g_net_age_lock, context);
    INIT_LIST_HEAD(&g_net_age_list);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #define UDP_HTABLE_SIZE udp_table.mask
#endif


static void cb_sk_nulls_for_each_rcu(struct hlist_nulls_head *head, bool (*callback)(struct sock *))
{
    struct sock *sk;
    struct hlist_nulls_node *node;

    sk_nulls_for_each_rcu(sk, node, head)
    {
        if (sk)
        {
            callback(sk);
        }
    }
}

static void cb_sk_for_each_rcu(struct hlist_head *head, bool (*callback)(struct sock *))
{
#ifdef sk_for_each_rcu
    // Some older kernels do not have sk_for_each_rcu. (This function will never be called
    //  for those kernels anyway.)
    struct sock *sk;

    sk_for_each_rcu(sk, head)
    {
        if (sk)
        {
            callback(sk);
        }
    }
#endif
}

// In newer kernels the `udp_hslot` structure now uses `hlist_head` instead of `hlist_nulls_head`.
//  This figures out which type the variable is, and calls the correct function.  Note, we
//  have to use a static helper function here because `sk_for_each_rcu` and `cb_sk_nulls_for_each_rcu`
//  are MACRO expansions of a for loop.  (This does not play nicely with the __builtin.)
#define cb_for_each(head, callback)                                           \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(head), struct hlist_nulls_head*),         \
        cb_sk_nulls_for_each_rcu((struct hlist_nulls_head *)head, callback),  \
        cb_sk_for_each_rcu((struct hlist_head *)head, callback))

static void udp_for_each(bool (*callback)(struct sock *))
{
    int slot;
    int size = UDP_HTABLE_SIZE;

    rcu_read_lock();

    for (slot = 0; slot < size; ++slot)
    {
        struct udp_hslot *hslot = &udp_table.hash[slot];

        cb_for_each(&hslot->head, callback);
    }
    rcu_read_unlock();
}

static bool udp_configure_raddr(struct sock *sk)
{
    // TODO: Maybe remove this logic
    //       I found that this logic was no longer getting a valid address.  This
    //       may be because we are collecting the data with peek now.  We need to
    //       do some further testing with this .  (The test app is always using
    //       localhost from a single process, so it is difficult to tell if it is
    //       working correctly.)
    // Configure UDP sockets to extract the destination IP
    // const int      on     = 1;
    // kernel_setsockopt( sk->sk_socket, SOL_IP, IP_PKTINFO, (char*)&on, sizeof(on) );
    // kernel_setsockopt( sk->sk_socket, SOL_IPV6, IPV6_RECVPKTINFO, (char*)&on, sizeof(on) );

    return true;
}

static void udp_init_sockets(void)
{
    udp_for_each(udp_configure_raddr);
}

struct priv_data {
    struct timespec time;
    uint32_t        count;
};

static void net_hash_table_cleanup(ProcessContext *context, struct priv_data *data)
{
    NET_TBL_NODE *datap = NULL;
    NET_TBL_NODE *tmp = NULL;
    uint64_t      purgeCount = 0;

    if (!data)
    {
        TRACE(DL_ERROR, "%s: Bad PARAM", __func__);
        return;
    }

    purgeCount = (data->count >= NET_TBL_SIZE ? NET_TBL_PURGE : 0);

    data->count = 0;

    cb_write_lock(&g_net_age_lock, context);
    list_for_each_entry_safe_reverse(datap, tmp, &g_net_age_list, ageList)
    {
        if (!purgeCount)
        {
            if (data->time.tv_sec < datap->value.last_seen.tv_sec)
            {
                break;
            }
        } else
        {
            --purgeCount;
        }

        net_tracking_print_message("AGE OUT", &datap->key);

        ++data->count;

        list_del(&(datap->ageList));
        hashtbl_del_generic(g_net_hash_table, datap, context);
        hashtbl_free_generic(g_net_hash_table, datap, context);
    }
    cb_write_unlock(&g_net_age_lock, context);
}

static void network_tracking_clean(ProcessContext *context, int sec)
{
    struct priv_data data;
    uint64_t         total = atomic64_read(&(g_net_hash_table->tableInstance));

    data.count = 0;
    getnstimeofday(&data.time);

    data.time.tv_sec -= sec;
    data.count        = total;

    net_hash_table_cleanup(context, &data);

    TRACE(DL_NET_TRACKING, "%s: Removed %d of %llu cached connections\n", __func__, data.count, total);
}

static void network_tracking_task(struct work_struct *work)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    // Set the last seen time that we want to age out
    //  This is set to 3600 to match the default tcp session timeout
    network_tracking_clean(&context, 3600);
    schedule_delayed_work(&net_track_work, g_ntt_delay);
}

// Completely purge the network tracking table
ssize_t cb_net_track_purge_all(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    cb_write_lock(&g_net_age_lock, &context);
    hashtbl_clear_generic(g_net_hash_table, &context);
    INIT_LIST_HEAD(&g_net_age_list);
    cb_write_unlock(&g_net_age_lock, &context);

    return size;
}

// Read in the age to purge from the user
ssize_t cb_net_track_purge_age(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    long seconds = 0;
    int  ret     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    ret = kstrtol(buf, 10, &seconds);
    if (!ret)
    {
        network_tracking_clean(&context, seconds);
    } else
    {
        TRACE(DL_ERROR, "%s: Error reading data: %s (%d)", __func__, buf, -ret);
    }

    return size;
}

// Display the 50 oldest netconns
int cb_net_track_show_old(struct seq_file *m, void *v)
{
    NET_TBL_NODE *datap = 0;
    int           i     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    cb_write_lock(&g_net_age_lock, &context);
    list_for_each_entry_reverse(datap, &g_net_age_list, ageList)
    {
        uint16_t  rport                         = 0;
        uint16_t  lport                         = 0;
        char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
        char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

        cb_ntop(&datap->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
        cb_ntop(&datap->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
        seq_printf(m, "NET-TRACK %d %s-%s %s:%u -> %s:%u (%d)\n",
                        datap->key.pid,
                        PROTOCOL_STR(datap->key.proto),
                        (datap->key.conn_dir == CONN_IN ? "in" : (datap->key.conn_dir == CONN_OUT ? "out" : "??")),
                        laddr_str, ntohs(lport), raddr_str, ntohs(rport),
                        (int)datap->value.last_seen.tv_sec);
        if (++i == 50) break;
    }
    cb_write_unlock(&g_net_age_lock, &context);

    return 0;
}

// Display the 50 newest netconns
int cb_net_track_show_new(struct seq_file *m, void *v)
{
    NET_TBL_NODE *datap = 0;
    int           i     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    cb_write_lock(&g_net_age_lock, &context);
    list_for_each_entry(datap, &g_net_age_list, ageList)
    {
        uint16_t  rport                         = 0;
        uint16_t  lport                         = 0;
        char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
        char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

        cb_ntop(&datap->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
        cb_ntop(&datap->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
        seq_printf(m, "NET-TRACK %d %s-%s %s:%u -> %s:%u (%d)\n",
                        datap->key.pid,
                        PROTOCOL_STR(datap->key.proto),
                        (datap->key.conn_dir == CONN_IN ? "in" : (datap->key.conn_dir == CONN_OUT ? "out" : "??")),
                        laddr_str, ntohs(lport), raddr_str, ntohs(rport),
                        (int)datap->value.last_seen.tv_sec);
        if (++i == 50) break;
    }
    cb_write_unlock(&g_net_age_lock, &context);

    return 0;
}

static void set_net_key(NET_TBL_KEY    *key,
                         pid_t           pid,
                         CB_SOCK_ADDR   *localAddr,
                         CB_SOCK_ADDR   *remoteAddr,
                         uint16_t        proto,
                         CONN_DIRECTION  conn_dir)
{
    memset(key, 0, sizeof(NET_TBL_KEY));

    cb_copy_sockaddr(&key->laddr, localAddr);
    cb_copy_sockaddr(&key->raddr, remoteAddr);

    // Network applications tend to randomize the source port, so in order to
    //  reduce the number of reported network connections we ignore the source port.
    //  (Which one that is depends on the direction.)
    if (conn_dir == CONN_IN)
    {
        cb_set_sockaddr_port(&key->raddr, 0);
    } else if (conn_dir == CONN_OUT)
    {
        cb_set_sockaddr_port(&key->laddr, 0);
    } else
    {
        TRACE(DL_WARNING, "Unexpected netconn direction: %d", conn_dir);
    }

    key->pid      = pid;
    key->proto    = proto;
    key->conn_dir = conn_dir;
}

// Track this connection in the local table
//  If it is a new connection, add an entry and send an event (return value of true)
//  If it is a tracked connection, update the time and skip sending an event (return value of false)
static bool track_connection(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir)
{
    bool          xcode = false;
    NET_TBL_KEY   key;
    NET_TBL_NODE *node;

    // Build the key
    set_net_key(&key, pid, localAddr, remoteAddr, proto, conn_dir);

    // CB-10650
    // We found a rare race condition where we find a node to be updated, and then wait on
    //  the spinlock.  The node is then deleted from the cleanup code.  We attempt to add it
    //  back to the list and crash with a double delete.
    cb_write_lock(&g_net_age_lock, context);

    // Check to see if this item is already tracked
    node = hashtbl_get_generic(g_net_hash_table, &key, context);

    if (!node)
    {
        xcode = true;
        node = (NET_TBL_NODE *)hashtbl_alloc_generic(g_net_hash_table, context);
        TRY_MSG(node, DL_ERROR, "Failed to allocate a network tracking node, event will be sent!");

        memcpy(&node->key, &key, sizeof(NET_TBL_KEY));
        node->value.count = 0;
        // Initialize ageList so it is safe to call delete on it.
        INIT_LIST_HEAD(&(node->ageList));

        net_tracking_print_message("ADD", &key);

        TRY_DO_MSG(!hashtbl_add_generic(g_net_hash_table, node, context),
                    { hashtbl_free_generic(g_net_hash_table, node, context); },
                    DL_ERROR, "Failed to add a network tracking node, event will be sent!");
    }

    // Update the last seen time and count
    getnstimeofday(&node->value.last_seen);
    ++node->value.count;

    // In case this connection is already tracked remove it from it's current location in
    //  the list so we can add it to the end.  This is a safe operation for a new entry
    //  because we initialize ageList above.
    list_del(&(node->ageList));
    list_add(&(node->ageList), &g_net_age_list);

CATCH_DEFAULT:

    cb_write_unlock(&g_net_age_lock, context);

    // If we have an excessive amount of netconns force it to clean up now.
    if (atomic64_read(&(g_net_hash_table->tableInstance)) >= NET_TBL_SIZE)
    {
        // Cancel the currently scheduled work, and and schedule it for immediate execution
        cancel_delayed_work(&net_track_work);
        schedule_work(&net_track_work.work);
    }

    return xcode;
}

static void net_tracking_print_message(const char *message, NET_TBL_KEY *key)
{
    uint16_t  rport                         = 0;
    uint16_t  lport                         = 0;
    char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
    char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

    cb_ntop(&key->raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
    cb_ntop(&key->laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
    TRACE(DL_NET_TRACKING, "NET-TRACK <%s> %u %s-%s laddr=%s:%u raddr=%s:%u",
                            message,
                            key->pid,
                            PROTOCOL_STR(key->proto),
                            (key->conn_dir == CONN_IN ? "in" : (key->conn_dir == CONN_OUT ? "out" : "??")),
                            laddr_str, ntohs(lport), raddr_str, ntohs(rport));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#  define IPV4_SOCKNAME(inet, a) ((inet)->inet_##a)
#  define IPV6_SOCKNAME(sk, a)   ((sk)->sk_v6_##a)
#else
#  define IPV4_SOCKNAME(inet, a) ((inet)->a)
#  define IPV6_SOCKNAME(sk, a)   (inet6_sk(sk)->a)
#endif

static bool cb_getudppeername(struct sock *sk, CB_SOCK_ADDR *remoteAddr, struct msghdr *msg)
{
    int namelen;
    bool rval = false;

    mm_segment_t oldfs = get_fs();

    set_fs(get_ds());

    namelen = msg->msg_namelen;
    if (sk->sk_protocol == IPPROTO_UDP && msg->msg_name && namelen)
    {
        unsigned int nbytes = (sizeof(remoteAddr->ss_addr) >= namelen) ? namelen : sizeof(remoteAddr->ss_addr);

        memcpy(&remoteAddr->ss_addr, msg->msg_name, nbytes);
        rval = true;
    }

    set_fs(oldfs);
    return rval;
}

// I would prefer to use kernel_getpeername here, but it does not work if the socket state is closed.
//  (Which seems to happen under load.)
static void cb_getpeername(struct sock *sk, CB_SOCK_ADDR *remoteAddr, struct msghdr *msg)
{
    CANCEL_VOID(sk);
    CANCEL_VOID(remoteAddr);
    CANCEL_VOID(msg);

    // Use msg->msg_name if we are doing UDP else ...
    if (!cb_getudppeername(sk, remoteAddr, msg))
    {
        struct inet_sock *inet;

        inet = inet_sk(sk);

        remoteAddr->sa_addr.sa_family = sk->sk_family;

        if (sk->sk_family == PF_INET)
        {
            remoteAddr->as_in4.sin_port        = IPV4_SOCKNAME(inet, dport);
            remoteAddr->as_in4.sin_addr.s_addr = IPV4_SOCKNAME(inet, daddr);
        } else {
            remoteAddr->as_in6.sin6_port = IPV4_SOCKNAME(inet, dport);
            memcpy(&remoteAddr->as_in6.sin6_addr, &IPV6_SOCKNAME(sk, daddr), sizeof(struct in6_addr));
        }
    }

}

static void cb_getsockname(struct sock *sk, CB_SOCK_ADDR *localAddr, struct msghdr *msg)
{
    struct inet_sock *inet;

    CANCEL_VOID(sk);
    CANCEL_VOID(localAddr);
    CANCEL_VOID(msg);

    inet = inet_sk(sk);

    localAddr->sa_addr.sa_family = sk->sk_family;

    if (sk->sk_family == PF_INET)
    {
        localAddr->as_in4.sin_port        = IPV4_SOCKNAME(inet, sport);
        localAddr->as_in4.sin_addr.s_addr = IPV4_SOCKNAME(inet, saddr);
    } else {
        void              *sin = NULL;

        localAddr->as_in6.sin6_port = IPV4_SOCKNAME(inet, sport);

        sin = ipv6_addr_any(&IPV6_SOCKNAME(sk, rcv_saddr)) ? &inet6_sk(sk)->saddr : &IPV6_SOCKNAME(sk, rcv_saddr);
        memcpy(&localAddr->as_in6.sin6_addr, sin, sizeof(struct in6_addr));
    }
}

static int checkIsolate(ProcessContext *context, u16 family, int protocol, struct sockaddr *p_sockaddr)
{
    CB_ISOLATION_INTERCEPT_RESULT isolationResult;

    if (family == PF_INET)
    {
        struct sockaddr_in *as_in4 = (struct sockaddr_in *)p_sockaddr;

        TRACE(DL_VERBOSE, "%s: check iso ip=%x port=%d", __func__, ntohl(as_in4->sin_addr.s_addr), ntohs(as_in4->sin_port));
        CbIsolationInterceptByAddrProtoPort(context, ntohl(as_in4->sin_addr.s_addr), true, protocol, as_in4->sin_port, &isolationResult);
        if (isolationResult.isolationAction == IsolationActionBlock)
        {
            //classifyOut->actionType = FWP_ACTION_BLOCK;
            //classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            TRACE(DL_NET, "%s: block ip=%x port=%d", __func__, as_in4->sin_addr.s_addr, as_in4->sin_port);
            g_cbIsolationStats.isolationBlockedInboundIp4Packets++;
            return -EPERM;
        } else if (isolationResult.isolationAction == IsolationActionAllow)
        {
            g_cbIsolationStats.isolationAllowedInboundIp4Packets++;
        }
    } else if (family == PF_INET6)
    {
        struct sockaddr_in6 *as_in6 = (struct sockaddr_in6 *)p_sockaddr;

        CbIsolationInterceptByAddrProtoPort(context, as_in6->sin6_addr.s6_addr32[0], false, protocol, as_in6->sin6_port, &isolationResult);
        if (isolationResult.isolationAction == IsolationActionBlock)
        {
            //classifyOut->actionType = FWP_ACTION_BLOCK;
            //classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            g_cbIsolationStats.isolationBlockedInboundIp6Packets++;
            return -EPERM;
        } else if (isolationResult.isolationAction == IsolationActionAllow)
        {
            g_cbIsolationStats.isolationAllowedInboundIp6Packets++;
        }
    }
    return 0;
}

int socket_post_create(struct socket *sock, int family, int type, int protocol, int kern)
{
    int xcode;

    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_post_create(sock, family, type, protocol, kern);
    TRY(xcode >= 0);
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(!cbIgnoreProcess(&context, getpid(current)));

    //
    // We're only interested in TCP over IPv4 or IPv6
    //
    TRY(CHECK_SOCKET(sock));

    //	pr_err("%s: proc=%16s  pid=%d stype=%d proto=%d\n", __FUNCTION__, current->comm, current->pid, sock->type, sock->sk->sk_protocol);
    //	inode = get_inode_from_file(sock->file);
    //	if (inode)
    //	{
    //		pr_err("%s:  socket inode=%lu\n", __FUNCTION__, inode->i_ino);
    //	}
    if (sock->sk->sk_protocol == IPPROTO_UDP)
    {
        udp_configure_raddr(sock->sk);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

// Not used for now
int socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int xcode;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_bind(sock, address, addrlen);
    TRY(xcode >= 0);
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);
    TRY(!cbIgnoreProcess(&context, getpid(current)));

    //
    // We're only interested in TCP over IPv4 or IPv6
    //
    TRY(address->sa_family == AF_INET || address->sa_family == AF_INET6);

    //pr_err("%s: proc=%16s  pid=%d stype=%d proto=%d\n", __FUNCTION__, current->comm, current->pid, sock->type, sock->sk->sk_protocol);
    //inode = get_inode_from_file(sock->file);
    //if (inode)
    //{
    //pr_err("%s:  socket inode=%lu\n", __FUNCTION__, inode->i_ino);
    //}

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

int socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
    u16               family;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;
    ProcessTracking  *procp         = NULL;
    pid_t             pid           = getpid(current);
    int               xcode         = 0;

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET();

    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_sendmsg(sock, msg, size);
    TRY(xcode >= 0);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(pid != 0);
    TRY(CHECK_SOCKET(sock));

    family = sock->sk->sk_family;
    // Only handle IPv4/6 packets

    // In the send path we have to get the remote address from msg->msg_name.
    //  Unfortunately I have found cases where msg->msg_name has not been initialized correctly.
    //  I am attempting to combat this by making sure that msg->msg_namelen is a sane value.
    //  It is still possible that it could pass this test and still be bad.  I am copying it
    //  into a local variable to limit direct usage of msg->msg_name.
    cb_getpeername(sock->sk, &remoteAddr, msg);

    TRY_SET_DO(-EPERM != checkIsolate(&context, family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        cb_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    procp = get_procinfo_and_create_process_start_if_needed(pid, "SEND", &context);
    TRY(procp);

    pid = process_tracking_exec_pid(procp);

    TRY(!cbIgnoreProcess(&context, pid));

    cb_getsockname(sock->sk, &localAddr, msg);

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(track_connection(&context, pid, &localAddr, &remoteAddr, sock->sk->sk_protocol, CONN_OUT));

    event_send_net(procp,
                   "SEND",
                   CB_EVENT_TYPE_NET_CONNECT_PRE,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   &context);

CATCH_DEFAULT:
    process_tracking_put_process(procp, &context);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

int _socket_recvmsg_hook_counted(ProcessContext *context, struct socket *sock, struct msghdr *msg, int size, int flags)
{
    u16               family;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;
    int               addressLength;
    ProcessTracking  *procp         = NULL;
    uint16_t          proto = 0;
    pid_t             pid   = getpid(current);
    int               xcode = 0;
    struct cmsghdr   *cmsg_kernel = NULL;

    // The MSG_UDP_HOOK flag is used skip the LSM hook so we can call our logic manually.
    TRY(!(flags & MSG_UDP_HOOK));

    TRY(CHECK_SOCKET(sock));
    TRY(pid != 0);
    TRY(msg != NULL);

    family = sock->sk->sk_family;
    proto = sock->sk->sk_protocol;

    // We can not trust msg->msg_name at all because it is possible that the caller has not
    //  initialized it properly.
    cb_getpeername(sock->sk, &remoteAddr, msg);

    // This is the first place in the syscall hook call stack, where in the routine starts accessing
    // dynamically initialized memory resources. As a pre-condition this check can only occur
    // after ensuring that the module is not disabled.

    TRY_SET_DO(-EPERM != checkIsolate(context, family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        cb_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    procp = get_procinfo_and_create_process_start_if_needed(pid, "RECV", context);
    TRY(procp);

    pid = process_tracking_exec_pid(procp);

    TRY(!cbIgnoreProcess(context, pid));

    // For UDP this will probably just get the port
    addressLength = sizeof(CB_SOCK_ADDR);
    kernel_getsockname(sock, &localAddr.sa_addr, &addressLength);

    recvmsg_cnt += 1;
    if ((recvmsg_cnt % NETHOOK_RECVMSG_STAT_THROTTLE) == 0)
    {
        //pr_err("%s: recvmsg_cnt=%llu rcv_skb_cnt=%llu nethash_instance=%llu relnode_cnt=%llu\n", __FUNCTION__, recvmsg_cnt, rcv_skb_cnt, nethash_instance, relnode_cnt);
    }

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(track_connection(context, pid, &localAddr, &remoteAddr, proto, CONN_IN));

    event_send_net(procp,
                   "RECV",
                   CB_EVENT_TYPE_NET_ACCEPT,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   context);

CATCH_DEFAULT:
    process_tracking_put_process(procp, context);
    cb_mem_cache_free_generic(cmsg_kernel);
    cmsg_kernel = NULL;
    return xcode;
}

int _socket_recvmsg(ProcessContext *context, struct socket *sock, struct msghdr *msg, int size, int flags)
{
    int ret = 0;

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

    ret = _socket_recvmsg_hook_counted(context, sock, msg, size, flags);

CATCH_DEFAULT:
    FINISH_MODULE_DISABLE_CHECK(context);
    return ret;
}

int socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags)
{
    int xcode = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    xcode = g_original_ops_ptr->socket_recvmsg(sock, msg, size, flags);
    TRY(xcode >= 0);
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // CB-10087, CB-9235
    // Some versions of netcat used a tricky way of reading UDP data.  (They were able to
    //  use the read function like a TCP connection which I did not know was possible.)
    //  This was able to get around my logic to hook UDP.
    // I fixed it by allowing the LSM hook to be called for UDP as well.  I was never happy
    //  handling all UDP from the LSM hook because I observed cases where the address
    //  information was not always filled in when I needed it. I now set a special flag
    //  in the receive hook that allows LSM to be skipped in those cases.
    TRY(CHECK_SOCKET(sock));

    TRY_SET(-EPERM != _socket_recvmsg_hook_counted(&context, sock, msg, 0, flags), -EPERM);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

//
// Active, outgoing connect (pre)
//
int cb_socket_connect_hook(struct socket *sock, struct sockaddr *addr, int addrlen)
{
    int                  xcode;
    CB_SOCK_ADDR         localAddr;
    CB_SOCK_ADDR         remoteAddr;
    ProcessTracking      *procp        = NULL;
    int                  addressLength = sizeof(CB_SOCK_ADDR);
    pid_t                pid           = getpid(current);

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET();

    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_connect(sock, addr, addrlen);
    TRY(xcode >= 0);
    TRY(sock);

    TRY(CHECK_SOCKET(sock));

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    memcpy(&remoteAddr.ss_addr, addr, addrlen);

    TRY_SET_DO(-EPERM != checkIsolate(&context, remoteAddr.sa_addr.sa_family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        cb_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    procp = get_procinfo_and_create_process_start_if_needed(pid, "CONNECT", &context);
    TRY(procp);

    pid = process_tracking_exec_pid(procp);

    TRY(!cbIgnoreProcess(&context, pid));

    //
    // We're only interested in TCP over IPv4 or IPv6 so we need to make sure that protocol is TCP
    // before reporting the netconn event. UDP is not supposed to be handled in this hook.
    //
    TRY(sock->sk->sk_protocol == IPPROTO_TCP);

    kernel_getsockname(sock, &localAddr.sa_addr, &addressLength);

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(track_connection(&context, pid, &localAddr, &remoteAddr, sock->sk->sk_protocol, CONN_OUT));

    event_send_net(procp,
                   "CONNECT",
                   CB_EVENT_TYPE_NET_CONNECT_PRE,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   &context);

CATCH_DEFAULT:
    process_tracking_put_process(procp, &context);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

//
// Active, outgoing connect (post). Not used for now
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!! IF DECIDE TO USE THIS HOOK, WILL NEED TO UPDATE IT TO SUPPORT MODULE_DISABLE CHECKS
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
void cb_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
    u16 family = sk->sk_family;

    MODULE_GET();

    /* handle mapped IPv4 packets arriving via IPv6 sockets */
    if ((family == PF_INET6 && skb->protocol == htons(ETH_P_IPV6))
        || (family == PF_INET && skb->protocol == htons(ETH_P_IP))
        )
    {
        ;
    }

    g_original_ops_ptr->inet_conn_established(sk, skb);
    MODULE_PUT();
}

//
// Passive, incomming connect (Accept)
//
int cb_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    int                           xcode           = 0;
    u16                           family          = 0;
    pid_t                         pid             = 0;
    uint16_t                      sport           = 0;
    uint32_t                      sip             = 0;
    CB_SOCK_ADDR                  localAddr;
    CB_SOCK_ADDR                  remoteAddr;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->inet_conn_request(sk, skb, req);
    TRY(xcode >= 0);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Without valid structures, we're dead in the water so there is no sense in
    // attempting to continue.
    TRY_MSG(sk && skb && req,
             DL_NET, "%s:%d Got NULL garbage in the request.", __func__, __LINE__);



    family = sk->sk_family;
    pid    = getpid(current);

    // Handle IPv4 over IPv6
    if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
    {
        family = PF_INET;
    }

    // Only handle IPv4/6 TCP packets
    TRY(family == PF_INET6 || family == PF_INET);
    TRY(sk->sk_type == SOCK_STREAM);
    TRY(sk->sk_protocol == IPPROTO_TCP);

    //
    // Populate the event
    //
    if (family == PF_INET)
    {
        struct inet_request_sock *ireq = (struct inet_request_sock *)req;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        sport = ireq->ir_rmt_port;
        sip   = ireq->ir_rmt_addr;
#else
        sport = ireq->rmt_port;
        sip   = ireq->rmt_addr;
#endif

        localAddr.as_in4.sin_family      = PF_INET;
        localAddr.as_in4.sin_port        = sport;
        localAddr.as_in4.sin_addr.s_addr = sip;
    }
    memset(&remoteAddr, 0, sizeof(CB_SOCK_ADDR));

    TRY_SET_DO(-EPERM != checkIsolate(&context, family, sk->sk_protocol, &localAddr.sa_addr), -EPERM, {
        cb_print_address("Isolate Connection", sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });
    cb_print_address("ACCEPT <SILENT>", sk, &localAddr.sa_addr, &remoteAddr.sa_addr);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

// This hook only looks for DNS response packets.  If one is found, a message is sent to
//  user space for processing.  NOTE: Process ID and such will be added to the event but
//  it is not used by the daemon.  This is only used for internal caching.
//  We have to do this here because the UDP header is not easily available in later hooks.
int on_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    int            xcode;
    struct udphdr  udphdr;
    struct udphdr *udp;
    char *data = NULL;

    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Only handle IPv4 UDP packets
    TRY(CHECK_SK_FAMILY_INET(sk) && CHECK_SK_PROTO_UDP(sk));

    // Copy the packet for inspection
    TRY_MSG(!skb_copy_bits(skb, 0, &udphdr, sizeof(udphdr)),
             DL_WARNING, "Error copying UDP packet bits");

    udp = &udphdr;

    if (ntohs(udp->source) == 53)
    {
        //
        // This is a DNS response, log it
        //
        int32_t       len   = ntohs(udp->len) - sizeof(struct udphdr);

        TRY_MSG(len > 0, DL_WARNING, "invalid length:%d for UDP response", len);

        data = cb_mem_cache_alloc_generic(len, &context);
        if (data)
        {
            TRY_MSG(!skb_copy_bits(skb, sizeof(udphdr), data, len),
                DL_WARNING, "Error copying UDP DNS response data");
            event_send_dns(
                CB_EVENT_TYPE_DNS_RESPONSE,
                data,
                len,
                &context);
        }

        rcv_skb_cnt += 1;
    }

CATCH_DEFAULT:
    cb_mem_cache_free_generic(data);
    xcode = g_original_ops_ptr->socket_sock_rcv_skb(sk, skb);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

// These will hold a copy of the old syscall so that it can be called from below and restored
//  when the module is unloaded.
long (*cb_orig_sys_recvfrom)(int fd, void __user *ubuf, size_t size, unsigned int flags,
                             struct sockaddr __user *addr, int __user *addr_len);
long (*cb_orig_sys_recvmsg)(int fd, struct msghdr __user *msg, unsigned int flags);
long (*cb_orig_sys_recvmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned int flags, struct timespec __user *timeout);

// The functions below replace the linux syscalls.  In most cases we will also call the original
//  syscall.
//
// !!!!! IMPORTANT NOTE AROUND SUPPORT FOR DISABLING MODULE !!!!!!!!!
// The checks to test if module is disabled are done in the inner function _socket_recvmsg
// This works today because the outer routines don't access any of the memory resources, thus even
// in a disabled module its OK to run the body of the outer routine. If this rule is violated (as
// in the  outer calls do start accessing the memory resources) will have to refactor the checks
// for the disabled checks to work correctly.
//

asmlinkage long cb_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags)
{
    int            xcode;
    struct socket *sock;
    unsigned int _flags           = flags;
    bool           weSetTimeout     = false;
    long           sk_rcvtimeo      = MAX_SCHEDULE_TIMEOUT;
    long           sk_rcvtimeo_dlta = 0;
    bool           bUdpPeek = false;

    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    if (!((flags & MSG_DONTWAIT) || (sock->file->f_flags & O_NONBLOCK)) &&
           (sk_rcvtimeo == 0 || sk_rcvtimeo > UDP_PACKET_TIMEOUT))
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        }
    }

    // CB-13480
    // In case of UDP IP address/port data that is needed to check for isolation is not always available
    // in the LSM hook, it becomes available only when UDP packet is read.
    // In case of TCP all data that is needed to check for isolation should be available in the LSM hook.
    // In general, we don't want to copy received data to the buffer provided by a caller before we check
    // for isolation because the caller may 'steal' the data from the buffer before
    // we zero it out prior to returning from this call which would allow a caller to bypass isolation.
    //
    // 1. TCP: call original syscall and check for isolation in the LSM hook.
    // 2. UDP, MSG_ERRQUEUE flag is not set by a caller:
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Set MSG_PEEK flag to peek at the data without consuming it
    //    - Allocate small buffer in kernel space and read data into it using original syscall
    //    - Get IP address/port info and check for isolation
    //    - If isolation check fails exit with EPERM error code
    //    - If isolation check is passed call original syscall with (original flags | MSG_UDP_HOOK)
    //      and user buffer
    //    - If a caller specified a timeout value calculate remaining time after exit from syscall
    //      with MSG_PEEK and pass it to the original syscall
    // 3. UDP, MSG_ERRQUEUE flag is set by a caller:
    //    - Assumption is that data from sk->sk_error_queue can be passed to a caller and no
    //      check for isolation is needed, and no need to report this connection either
    //    - MSG_PEEK flag doesn't work in this case, data from error queue is always consumed
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Call original syscall with original flags and user buffer

    CHECK_UDP_PEEK(sock, flags, _flags, bUdpPeek);

    if (bUdpPeek)
    {
        mm_segment_t oldfs;
        struct sockaddr_storage sock_addr_peek = {0};
        struct msghdr msg_peek = {0};
        struct iovec iovec_peek = {0};
        char iovec_peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};
        char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};

        msg_peek.msg_iovlen = 1;
        msg_peek.msg_iov = &iovec_peek;
        msg_peek.msg_iov->iov_len = IOV_FOR_MSG_PEEK_SIZE;
        msg_peek.msg_iov->iov_base = iovec_peek_buf;
        msg_peek.msg_name = &sock_addr_peek;
        msg_peek.msg_namelen = sizeof(sock_addr_peek);
        msg_peek.msg_control = cbuf;
        msg_peek.msg_controllen = sizeof(cbuf);

        // We're going to work with msg_peek struct which is allocated in kernel space
        oldfs = get_fs();
        set_fs(get_ds());
        // Peek at the message to determine remote IP address and port
        PEEK(&context, cb_orig_sys_recvmsg(fd, &msg_peek, _flags), sock, msg_peek, sk_rcvtimeo_dlta, weSetTimeout, flags, xcode);
        set_fs(oldfs);
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    if (_flags & MSG_UDP_HOOK)
    {
        flags |= MSG_UDP_HOOK;
    }

    // Get the actual data which will be copied to the buffer provided by caller
    TIMED_RECV(cb_orig_sys_recvmsg(fd, msg, flags), sock, sk_rcvtimeo_dlta, weSetTimeout, xcode);

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT();
    return xcode;
}

asmlinkage long cb_sys_recvmmsg(int fd, struct mmsghdr __user *msg,
                                unsigned int vlen, unsigned int flags,
                                struct timespec __user *timeout)
{
    int             xcode;
    struct socket   *sock;
    struct timespec _timeout = {0, 0};
    unsigned int _flags = flags;
    bool            weSetTimeout     = false;
    long            sk_rcvtimeo      = MAX_SCHEDULE_TIMEOUT;
    long            sk_rcvtimeo_arg  = MAX_SCHEDULE_TIMEOUT;
    long            sk_rcvtimeo_dlta = 0;
    bool            bUdpPeek = false;

    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    // struct timespec __user *timeout is a user space pointer.
    // NULL pointer means an infinite timeout, otherwise we need to copy
    // the timespec structure from user space to kernel space
    if (timeout)
    {
        TRY_SET(!copy_from_user(&_timeout, timeout, sizeof(_timeout)), -EINVAL);
    }

    // If the caller specified a timeout value I will take that one into account as well,
    //  but I will let one configured from setsocketopt take precedence.
    // Kernel's __sys_recvmmsg() calls __sys_recvmsg() in a loop to collect messages.
    // The socket timeout is used for __sys_recvmsg() calls only. The timeout structure that the caller
    // passes to recvmmsg() is used to determine when to exit the loop. If __sys_recvmsg() times out
    // the loop is terminated and __sys_recvmmsg() returns no matter what timeout value the caller specified
    // in the timespec structure. Given all that we don't need to modify timespec structure here, adjusting
    // socket timeout value so it doesn't block forever is enough.
    if (sk_rcvtimeo == MAX_SCHEDULE_TIMEOUT && timeout)
    {
        if (_timeout.tv_sec != 0 || _timeout.tv_nsec != 0)
        {
            __kernel_suseconds_t tv_usec = _timeout.tv_nsec / NSEC_PER_USEC;

            sk_rcvtimeo_arg = _timeout.tv_sec*HZ + (tv_usec+(1000000/HZ-1))/(1000000/HZ);
        }
    }

    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    if (!((flags & MSG_DONTWAIT) || (sock->file->f_flags & O_NONBLOCK)) && (sk_rcvtimeo == 0 || (sk_rcvtimeo > UDP_PACKET_TIMEOUT && sk_rcvtimeo_arg > UDP_PACKET_TIMEOUT)))
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        } else if (sk_rcvtimeo_arg != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo_arg > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo_arg;
        }
    }

    CHECK_UDP_PEEK(sock, flags, _flags, bUdpPeek);

    if (bUdpPeek)
    {
        struct sockaddr_storage sock_addr_peek = {0};
        struct mmsghdr mmsg_peek = {{0}, 0};
        struct iovec iovec_peek = {0};
        char iovec_peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};
        char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
        long sk_rcvtimeo_dlta_peek = 0;
        struct timespec *p_timeout = NULL;

        mmsg_peek.msg_hdr.msg_iovlen = 1;
        mmsg_peek.msg_hdr.msg_iov = &iovec_peek;
        mmsg_peek.msg_hdr.msg_iov->iov_len = IOV_FOR_MSG_PEEK_SIZE;
        mmsg_peek.msg_hdr.msg_iov->iov_base = iovec_peek_buf;
        mmsg_peek.msg_hdr.msg_name = &sock_addr_peek;
        mmsg_peek.msg_hdr.msg_namelen = sizeof(sock_addr_peek);
        mmsg_peek.msg_hdr.msg_control = cbuf;
        mmsg_peek.msg_hdr.msg_controllen = sizeof(cbuf);
        mmsg_peek.msg_len = 0;

        // Initial value of sk_rcvtimeo_dlta should be restored after peeking because socket timeout is used in recvmsg()
        // which is called by recvmmsg() internally in a loop and it should be the same value for all recvmsg() calls.
        // PEEK() calls TIMED_RECV() which adjusts sk_rcvtimeo_dlta, that's why we use sk_rcvtimeo_dlta_peek here to
        // preserved.nitial value of sk_rcvtimeo_dlta that will be passed to the non-peeking system call below.
        sk_rcvtimeo_dlta_peek = sk_rcvtimeo_dlta;

        // If the caller provided timeout value we need to use our kernel space copy of it for peeking because
        // we call set_fs(get_ds()) below before recvmmsg() syscall so kernel will accept pointers to kernel address space
        // which can be exploited if the caller provides such a pointer because recvmmsg() reads and writes timespec structure
        if (timeout)
        {
            p_timeout = &_timeout;
        }

        // Peek at the message to determine remote IP address and port.
        // timeout value will be updated with remaining time if recvmmsg() receives a datagram
        // We only need one message at this time as we're checking/reporting only the first received packet for now
        // TODO: CB-11228 - we need to check/report every packet we received, not only the first one
        PEEK(&context, cb_orig_sys_recvmmsg(fd, &mmsg_peek, 1, _flags, p_timeout), sock, mmsg_peek.msg_hdr, sk_rcvtimeo_dlta_peek, weSetTimeout, flags, xcode);

        // If the caller provided timeout our kernel space timespec structure was updated by the recvmmsg() syscall
        // Now we need to copy it back to the caller's structure
        if (timeout && p_timeout)
        {
            TRY_SET(!copy_to_user(timeout, p_timeout, sizeof(struct timespec)), -EINVAL);
        }
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    if (_flags & MSG_UDP_HOOK)
    {
        flags |= MSG_UDP_HOOK;
    }

    // This call can block here for a long time if the caller passes a big timeout value or doesn't specify the timeout at all.
    // In this case recvmmsg() will call recvmsg() in a loop until either of the following conditions are met:
    // 1. Caller's timeout expires (if it's set)
    // 2. Socket timeout expires
    // 3. There are no more msghdr structures available to store incoming packets
    // We can't unload our kernel module until we exit from this call, so this behavior may cause delays when unloading the module.
    TIMED_RECV(cb_orig_sys_recvmmsg(fd, msg, vlen, flags, timeout), sock, sk_rcvtimeo_dlta, weSetTimeout, xcode);

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT();
    return xcode;
}

asmlinkage long cb_sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
                             struct sockaddr __user *addr, int __user *addr_len)
{
    struct socket *sock;
    int           xcode;
    bool          weSetTimeout = false;
    long          sk_rcvtimeo  = MAX_SCHEDULE_TIMEOUT;
    long          sk_rcvtimeo_dlta = 0;
    unsigned int _flags = 0;
    bool          bUdpPeek = false;

    DECLARE_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    if (sock->file->f_flags & O_NONBLOCK)
    {
        flags |= MSG_DONTWAIT;
    }
    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    else if (sk_rcvtimeo == 0 || sk_rcvtimeo > UDP_PACKET_TIMEOUT)
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        }
    }

    // CB-13703
    // In case of UDP IP address/port data that is needed to check for isolation is not always available
    // in the LSM hook, it becomes available only when UDP packet is read.
    // In case of TCP all data that is needed to check for isolation should be available in the LSM hook.
    // In general, we don't want to copy received data to the buffer provided by a caller before we check
    // for isolation.
    //
    // 1. TCP: call original syscall and check for isolation in the LSM hook.
    // 2. UDP, MSG_ERRQUEUE flag is not set by a caller:
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Set MSG_PEEK flag to peek at the data without consuming it
    //    - Allocate small buffer in kernel space and read data into it using kernel_recvmsg()
    //    - Get IP address/port info and check for isolation
    //    - If isolation check fails exit with EPERM error code
    //    - If isolation check is passed call original syscall with (original flags | MSG_UDP_HOOK)
    //      and user buffer
    //    - If a caller specified a timeout value calculate remaining time after exit from syscall
    //      with MSG_PEEK and pass it to the original syscall
    // 3. UDP, MSG_ERRQUEUE flag is set by a caller:
    //    - Assumption is that data from sk->sk_error_queue can be passed to a caller and no
    //      check for isolation is needed, and no need to report this connection either
    //    - MSG_PEEK flag doesn't work in this case, data from error queue is always consumed
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Call original syscall with original flags and user buffer
    // 4. Only handle the type of sockets we are interested in recvmsg. So pass the rest to
    //    the standard syscall. I need to do this because kernel_recvmsg logic below messes up some
    //    non-ip sockets (Specifically I noticed a problem with PF_NETLINK.)

    CHECK_UDP_PEEK(sock, flags, _flags, bUdpPeek);

    if (bUdpPeek)
    {
        // Unlike in the recvmsg and recvmmsg calls, we can not call the real syscall to get the packet
        //  because we need a struct msghdr object for our logic.  The code below has been adapted from
        //  the recvfrom call in the kernel source.
        struct iovec             iov;
        struct msghdr            msg;
        struct sockaddr_storage  address;
        char                     cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
        char                     peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};

        msg.msg_flags      = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);
        msg.msg_control    = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        msg.msg_name       = (struct sockaddr *)&address;
        msg.msg_namelen    = sizeof(address);
        iov.iov_len        = IOV_FOR_MSG_PEEK_SIZE;
        iov.iov_base       = peek_buf;

        // Get information needed for isolation check
        PEEK(&context, kernel_recvmsg(sock, &msg, (struct kvec *)&iov, 1, IOV_FOR_MSG_PEEK_SIZE, _flags),
             sock, msg, sk_rcvtimeo_dlta, weSetTimeout, flags, xcode);
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    if (_flags & MSG_UDP_HOOK)
    {
        flags |= MSG_UDP_HOOK;
    }

    // Call original syscall which should populate all the buffers and variables that a caller passed in
    TIMED_RECV(cb_orig_sys_recvfrom(fd, ubuf, size, flags, addr, addr_len),
               sock, sk_rcvtimeo_dlta, weSetTimeout, xcode);

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT();
    return xcode;
}

#ifdef __NR_recv
#warning "The sys_recv call is used, and we have not provided a hook for it."
#endif
