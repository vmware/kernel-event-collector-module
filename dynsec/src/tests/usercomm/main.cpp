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
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <stdlib.h>

#ifndef NETLINK_DYNSEC
#define NETLINK_DYNSEC 27
#endif

#define MAX_NL_BUFF 1024

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr* nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main(int argc, const char * argv[]) {

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
    
    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_NL_BUFF));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_NL_BUFF);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy((char*)NLMSG_DATA(nlh), "Response To Kernel");
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    
    for (int i=0; i<10000; i++)
    {
        sendmsg(sock_fd, &msg, 0);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("batch msg send took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
}
