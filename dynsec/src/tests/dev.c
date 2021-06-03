


#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <poll.h>
#include "dynsec.h"

static int create_chrdev(unsigned int major_num, unsigned int minor,
                         const char *dev_path)
{
    dev_t dev = 0;
    int ret;

    if (!dev_path)
    {
        return -EINVAL;
    }

    dev = makedev(major_num, 0);

    ret = mknod(dev_path, S_IFCHR|S_IRUSR|S_IWUSR, dev);
    if (!ret || (ret < 0 && errno == EEXIST))
    {
        ret = open(dev_path, O_RDWR | O_CLOEXEC);
        if (ret < 0)
        {
            fprintf(stderr, "Unable to open(%s,O_RDWR| O_CLOEXEC) = %m\n",
                    dev_path);
            unlink(dev_path);
        }
    }

    return ret;
}

int respond_to_access_request(int fd, uint64_t req_id,
                              uint32_t event_type, int response_type)
{
    ssize_t ret;
    struct dynsec_response response = {
        .req_id = req_id,
        .event_type = event_type,
        .response = response_type,
        .cache_flags = 0xFFFFFFFF,
    };

    if (fd < 0) {
        return -EBADF;
    }
    switch (event_type)
    {
    case DYNSEC_LSM_bprm_set_creds:
        break;

    default:
        return -EINVAL;
    }
    switch (response_type) {
    case DYNSEC_RESPONSE_ALLOW:
    case DYNSEC_RESPONSE_EPERM:
        break;

    default:
        return -EINVAL;
    }

    ret = write(fd, &response, sizeof(response));
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

void read_events(int fd, const char *banned_path)
{
    char buf[8192];
    struct dynsec_exec_umsg *exec_msg;

    memset(&buf, 0, sizeof(buf));

    while (1)
    {
        struct dynsec_msg_hdr *hdr = (struct dynsec_msg_hdr *)buf;
        ssize_t bytes_read = 0;
        struct pollfd pollfd = {
             .fd = fd,
             .events = POLLIN | POLLOUT,
             .revents = 0,
        };
        int ret = poll(&pollfd, 1, -1);
        int response = DYNSEC_RESPONSE_ALLOW;

        if (ret <= 0) {
            continue;
        }

        bytes_read = read(fd, buf, sizeof(buf));
        if (bytes_read > 0) {

            if (hdr->type == DYNSEC_LSM_bprm_set_creds) {
                char *path = NULL;
                struct dynsec_exec_umsg *exec_msg = (struct dynsec_exec_umsg *)hdr;

                if (hdr->payload != exec_msg->hdr.payload ||
                    hdr->req_id != exec_msg->hdr.req_id || 
                    hdr->type != exec_msg->hdr.type) {
                    printf("hdr->payload:%u hdr->req_id:%llu hdr->type:%#x\n",
                           hdr->payload, hdr->req_id, hdr->type);
                    printf("payload:%u req_id:%llu type:%#x\n", exec_msg->hdr.payload,
                           exec_msg->hdr.req_id, exec_msg->hdr.type);
                } else {
                    if (exec_msg->msg.path_offset) {
                        path = buf + exec_msg->msg.path_offset;
                        // if (path) {
                        //     printf("offset:%u size:%u strlen:%lu path:%s\n",
                        //            exec_msg->msg.path_offset, exec_msg->msg.path_size,
                        //            strlen(path), path);
                        // }
                    }
                    if (path && *path) {
                        printf("Exec: tid:%u ino:%llu dev:%#x magic:%#lx uid:%u '%s'\n",
                               exec_msg->msg.pid, exec_msg->msg.ino, exec_msg->msg.dev,
                               exec_msg->msg.sb_magic, exec_msg->msg.uid, path
                        );
                        // Ban some matching substring
                        if (banned_path && *banned_path && strstr(path, banned_path)) {
                            response = DYNSEC_RESPONSE_EPERM;
                        }
                    } else {
                        printf("Exec: tid:%u ino:%llu dev:%#x magic:%#lx uid:%u\n",
                               exec_msg->msg.pid, exec_msg->msg.ino, exec_msg->msg.dev,
                               exec_msg->msg.sb_magic, exec_msg->msg.uid
                        );
                    }
                }
            }

            ret = respond_to_access_request(fd, hdr->req_id, hdr->type, response);
            if (ret < 0) {
                fprintf(stderr, "Unable to response to:%llu %#x resp:%d err:%d\n",
                        hdr->req_id, hdr->type, response, ret);
            }

            // Observe bytes committed to
            memset(buf, 'A', sizeof(buf));
        } else {
            if (ret != -EAGAIN) {
                break;
            }
        }
    }
}


int main(int argc, const char *argv[])
{
    int fd;
    const char *devpath;
    unsigned long major;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <desired dev filename> <major dev num>\n", argv[0]);
        return 1;
    }

    devpath = argv[1];
    major = strtoul(argv[2], NULL, 0);

    fd = create_chrdev(major, 0, devpath);
    if (fd < 0) {
        return 255;
    }
    read_events(fd, "/foo.sh");
    close(fd);

    return 1;
}
