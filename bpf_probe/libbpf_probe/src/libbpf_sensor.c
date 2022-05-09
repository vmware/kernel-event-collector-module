#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sensor.skel.h"

#include <sys/utsname.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define MAX_FNAME 255L
#define DNS_SEGMENT_LEN 40

enum event_type {
    EVENT_PROCESS_EXEC_ARG,
    EVENT_PROCESS_EXEC_PATH,
    EVENT_PROCESS_EXEC_RESULT,
    EVENT_PROCESS_EXIT,
    EVENT_PROCESS_CLONE,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CREATE,
    EVENT_FILE_PATH,
    EVENT_FILE_MMAP,
    EVENT_FILE_TEST,
    EVENT_NET_CONNECT_PRE,
    EVENT_NET_CONNECT_ACCEPT,
    EVENT_NET_CONNECT_DNS_RESPONSE,
    EVENT_NET_CONNECT_WEB_PROXY,
    EVENT_FILE_DELETE,
    EVENT_FILE_CLOSE,
    EVENT_FILE_RENAME,
    EVENT_CONTAINER_CREATE
};

struct data_header {
    u64 event_time; // Time the event collection started.  (Same across message parts.)
    u8 type;
    u8 state;

    u32 tid;
    u32 pid;
    u32 uid;
    u32 ppid;
    u32 mnt_ns;
};

struct data {
    struct data_header header;
};

struct exec_data {
    struct data_header header;

    int retval;
};

struct file_data {
    struct data_header header;

    u64 inode;
    u32 device;
    u64 flags; // MMAP only
    u64 prot;  // MMAP only
    u64 fs_magic;
};

struct path_data {
    struct data_header header;

    u8 size;
    char fname[MAX_FNAME];
};

struct net_data {
    struct data_header header;

    u16 ipver;
    u16 protocol;
    union {
        u32 local_addr;
        u32 local_addr6[4];
    };
    u16 local_port;
    union {
        u32 remote_addr;
        u32 remote_addr6[4];
    };
    u16 remote_port;
};

struct dns_data {
    struct data_header header;

    char dns[DNS_SEGMENT_LEN];
    u32 name_len;
};

struct rename_data {
    struct data_header header;

    u64 old_inode, new_inode;
    u32 device;
    u64 fs_magic;
};

struct kprobe {
    char *program_name;
    char *kprobe_name;
    bool is_kretprobe;
};

// TODO: add __x64_ prefix to sys_* hook names only for kernels >= 4.17
struct kprobe kprobes[] = {
        {
                .program_name = "syscall__on_sys_execve",
                .kprobe_name = "__x64_sys_execve",
                .is_kretprobe = false
        },
        {
                .program_name = "syscall__on_sys_execveat",
                .kprobe_name = "__x64_sys_execveat",
                .is_kretprobe = false
        },
        {
                .program_name = "after_sys_execve",
                .kprobe_name = "__x64_sys_execve",
                .is_kretprobe = true
        },
        {
                .program_name = "after_sys_execve",
                .kprobe_name = "__x64_sys_execveat",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_connect_v4_entry",
                .kprobe_name = "tcp_v4_connect",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_connect_v6_entry",
                .kprobe_name = "tcp_v6_connect",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_connect_v4_return",
                .kprobe_name = "tcp_v4_connect",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_connect_v6_return",
                .kprobe_name = "tcp_v6_connect",
                .is_kretprobe = true
        },
        {
                .program_name = "on_security_file_free",
                .kprobe_name = "security_file_free",
                .is_kretprobe = false
        },
        {
                .program_name = "on_security_mmap_file",
                .kprobe_name = "security_mmap_file",
                .is_kretprobe = false
        },
        {
                .program_name = "on_security_file_open",
                .kprobe_name = "security_file_open",
                .is_kretprobe = false
        },
        {
                .program_name = "on_security_inode_unlink",
                .kprobe_name = "security_inode_unlink",
                .is_kretprobe = false
        },
        {
                .program_name = "on_security_inode_rename",
                .kprobe_name = "security_inode_rename",
                .is_kretprobe = false
        },
        {
                .program_name = "on_wake_up_new_task",
                .kprobe_name = "wake_up_new_task",
                .is_kretprobe = false
        },
        {
                .program_name = "on_do_exit",
                .kprobe_name = "do_exit",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_skb_recv_udp",
                .kprobe_name = "__skb_recv_udp",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_accept_return",
                .kprobe_name = "inet_csk_accept",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_udp_recvmsg",
                .kprobe_name = "udp_recvmsg",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_udp_recvmsg_return",
                .kprobe_name = "udp_recvmsg",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_udp_recvmsg",
                .kprobe_name = "udpv6_recvmsg",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_udp_recvmsg_return",
                .kprobe_name = "udpv6_recvmsg",
                .is_kretprobe = true
        },

        {
                .program_name = "trace_udp_sendmsg",
                .kprobe_name = "udp_sendmsg",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_udp_sendmsg_return",
                .kprobe_name = "udp_sendmsg",
                .is_kretprobe = true
        },
        {
                .program_name = "trace_udp_sendmsg",
                .kprobe_name = "udpv6_sendmsg",
                .is_kretprobe = false
        },
        {
                .program_name = "trace_udp_sendmsg_return",
                .kprobe_name = "udpv6_sendmsg",
                .is_kretprobe = true
        },
};

static int bpfverbose = 0;
static volatile bool exiting;

bool btf_supported() {
    return access("/sys/kernel/btf/vmlinux", F_OK) == 0;
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static int print_event(void* data_event)
{
    struct data *generic_event = (struct data*)data_event;
    switch (generic_event->header.type) {
        case EVENT_PROCESS_EXEC_ARG: {
            struct path_data *e = (struct path_data *)data_event;
            fprintf(stdout, "exec arg--> %llu %u %u %u %u %u %u %u %d %s\n", e->header.event_time, e->header.tid, e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns, e->size, e->fname);
            break;
        }
        case EVENT_PROCESS_EXEC_PATH: {
            struct path_data *e = (struct path_data *)data_event;
            fprintf(stdout, "exec path--> %llu %u %u %u %u %u %u %u %d %s\n", e->header.event_time, e->header.tid, e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns, e->size, e->fname);
            break;
        }
        case EVENT_PROCESS_EXEC_RESULT: {
            struct exec_data *e = (struct exec_data *) data_event;
            fprintf(stdout, "exec res--> %llu %u %u %u %u %u %u %u %d\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->retval);
            break;
        }
        case EVENT_PROCESS_EXIT: {
            struct data *e = (struct data *) data_event;
            fprintf(stdout, "exit--> %llu %u %u %u %u %u %u %u\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns);
            break;
        }
        case EVENT_PROCESS_CLONE: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "clone--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_FILE_READ: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "file read--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_FILE_WRITE: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "file write--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_FILE_MMAP: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "file mmap--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_NET_CONNECT_PRE: {
            struct net_data *e = (struct net_data *) data_event;
            fprintf(stdout, "net pre--> %llu %u %u %u %u %u %u %u %u %u %u %u %u %u\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->ipver, e->protocol, e->local_addr, e->local_port, e->remote_addr, e->remote_port);
            break;
        }
        case EVENT_NET_CONNECT_ACCEPT: {
            struct net_data *e = (struct net_data *) data_event;
            fprintf(stdout, "net accept--> %llu %u %u %u %u %u %u %u %u %u %u %u %u %u\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->ipver, e->protocol, e->local_addr, e->local_port, e->remote_addr, e->remote_port);
            break;
        }
        case EVENT_NET_CONNECT_DNS_RESPONSE: {
            struct dns_data *e = (struct dns_data *) data_event;
            fprintf(stdout, "dns resp--> %llu %u %u %u %u %u %u %u %s %u\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->dns, e->name_len);
            break;
        }
        case EVENT_FILE_DELETE: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "file delete--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_FILE_CLOSE: {
            struct file_data *e = (struct file_data *) data_event;
            fprintf(stdout, "file close--> %llu %u %u %u %u %u %u %u %llu %u %llu %llu %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->inode, e->device, e->flags, e->prot, e->fs_magic);
            break;
        }
        case EVENT_FILE_RENAME: {
            struct rename_data *e = (struct rename_data *) data_event;
            fprintf(stdout, "file rename--> %llu %u %u %u %u %u %u %u, %llu %llu %u %llu\n", e->header.event_time, e->header.tid,
                    e->header.pid, e->header.uid, e->header.ppid, e->header.type, e->header.state, e->header.mnt_ns,
                    e->old_inode, e->new_inode, e->device, e->fs_magic);
            break;
        }
        default: {
            fprintf(stdout, "Unidentified type %u\n", generic_event->header.type);
        }

    }
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}


void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{

    print_event(data);
	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void initiate_exit()
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	int opt, err = 0;
	struct sensor_bpf *sensor;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;


	signal(SIGINT, initiate_exit);
	signal(SIGTERM, initiate_exit);

    struct utsname buffer;
    if (uname(&buffer) == 0) {
        fprintf(stdout, "kernel release     = %s\n", buffer.release);
    }

    if (!btf_supported()){
        fprintf(stderr, "BTF unsupported - fallback to BCC");
        exit(1);
    }

	libbpf_set_print(libbpf_print_fn);

    // must be done for libbpf - done automatically in BCC
    // we might consider setting a limit here
	if ((err = bump_memlock_rlimit())) {
        fprintf(stderr, "failed to increase rlimit: %d", err);
        exit(1);
    }


	// create BPF module using BPF object file
	if (!(sensor = sensor_bpf__open())) {
        fprintf(stderr, "failed to open BPF object\n");
        exit(1);
    }

	// load BPF object from BPF module
	if ((err = sensor_bpf__load(sensor))) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        exit(1);
    }

    int num_of_kprobes = sizeof(kprobes) / sizeof(kprobes[0]);

    for (int i = 0; i < num_of_kprobes; i++) {
        struct bpf_program *func = bpf_object__find_program_by_name(sensor->obj, kprobes[i].program_name);
        if ((err = libbpf_get_error(bpf_program__attach_kprobe(func, kprobes[i].is_kretprobe, kprobes[i].kprobe_name)))) {
            fprintf(stderr, "failed to attach\n");
            exit(1);
        }
    }

	pb_opts.sz = sizeof(struct perf_buffer_opts);

	// start perf event polling (call handle_event & handle_lost_events on fd activity)
	pb = perf_buffer__new(bpf_map__fd(sensor->maps.events), 16, handle_event, handle_lost_events,0, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
        sensor_bpf__destroy(sensor);
        exit(err);
	}

    while (1) {
        if ((err = perf_buffer__poll(pb, 100)) < 0) {
            fprintf(stderr, "polling error: %d\n", err);
            break;
        }

        if (exiting) {
            break;
        }
    }

	perf_buffer__free(pb);
    sensor_bpf__destroy(sensor);
}
