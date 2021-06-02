//
//  main.cpp
//  PerfTestExec
//
//  Created by Berni McCoy on 4/18/19.
//  Copyright © 2019 Berni McCoy. All rights reserved.
//

#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <atomic>

#ifndef NETLINK_DYNSEC
#define NETLINK_DYNSEC 27
#endif

#define MAX_NL_BUFF 1024

#define KMSG_TYPE_CONNECT 0
#define KMSG_TYPE_RESPONSE 1
#define KMSG_TYPE_REQUEST 2

#define UM_RESULT_ALLOWED 0
#define UM_RESULT_DENIED 1

struct kmsg_hdr {
    int msg_type;
};

struct kmsg_response {
    int msg_type;
    int response;
    int req_id;
};

struct kmsg_request {
    int msg_type;
    int req_id;
    int op;
    int pid;
    int uid;
    int euid;
    uint64_t ino;
    uint32_t dev;
    int path_index;
    char path[512];
};

struct sockaddr_nl src_addr, dest_addr;
int sock_fd;
std::atomic<int> request_counter;

void send_kernel_msg(const struct kmsg_hdr* kmsg,
                     size_t kmsg_size)
{
    struct msghdr msg;
    struct nlmsghdr* nlh = NULL;
    struct iovec iov;

    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_NL_BUFF));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_NL_BUFF);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), kmsg, kmsg_size);
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    ssize_t res = sendmsg(sock_fd, &msg, 0);
    if (res == -1)
    {
        printf("Error calling sendmsg error[%d]\n", errno);
    }
    
    free(nlh);

}

int is_op_allowed(const struct kmsg_request* krqst)
{
    if ((request_counter % 1000) == 0)
    {
        printf("Handled %d requests from kernel\n", (int)request_counter);
    }
    
    request_counter++;
    
    if (strstr(&krqst->path[krqst->path_index], "foo.sh") != NULL)
    {
        printf("Blocking execution to file[%s] from pid[%d] as user[%d] inode[%lu] device[%u]\n", &krqst->path[krqst->path_index], krqst->pid, krqst->uid, krqst->ino, krqst->dev);

        return UM_RESULT_DENIED;
    }
    
    return UM_RESULT_ALLOWED;
}

void* kernel_comm_loop(void *arg)
{
    unsigned long i = 0;
    pthread_t id = pthread_self();
    
    struct msghdr msg;
    struct nlmsghdr* nlh = NULL;
    struct iovec iov;
    
    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_NL_BUFF));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_NL_BUFF);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    while (true)
    {
        recvmsg(sock_fd, &msg, 0);
        struct kmsg_hdr* hdr = (struct kmsg_hdr*)(NLMSG_DATA(nlh));
        switch (hdr->msg_type)
        {
        case KMSG_TYPE_REQUEST:
            {
                struct kmsg_request* rqst = (struct kmsg_request*)(void*)(hdr);
                int res = is_op_allowed(rqst);
                struct kmsg_response resp = {.msg_type = KMSG_TYPE_RESPONSE, .response = res, .req_id = rqst->req_id };
//                printf("Sending response to kernel for request id[%d]\n", rqst->req_id);
                
                send_kernel_msg((struct kmsg_hdr*)(void*)(&resp), sizeof(resp));
                break;
            }
        default:
            {
                printf("unknown message received\n");
                break;
            }
        }
        
        sched_yield();
        
    }
    return NULL;
}


int main(int argc, const char * argv[]) {

    request_counter = 0;
    
    // Initialize socket and src/dest address... these
    // won't change with each message.
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_DYNSEC);
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    
    pthread_t kernel_comms_thread;
    
    pthread_create(&kernel_comms_thread, NULL, kernel_comm_loop, NULL);

    struct kmsg_hdr connect_msg = { .msg_type = KMSG_TYPE_CONNECT };
    
    printf("Sending connect message to kernel from pid[%d]\n", getpid());
    
    send_kernel_msg(&connect_msg, sizeof(connect_msg));
    
    while (true)
    {
        sleep(1);
    }
}

