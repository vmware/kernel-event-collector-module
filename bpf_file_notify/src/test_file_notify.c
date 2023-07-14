

#include <stdio.h>
#include <unistd.h>

#include "file_notify.h"
#include "file_notify.skel.h"


int init_basic(int argc, const char *argv[])
{
    int ret = 0;
    struct file_notify_bpf *skel = NULL;

    skel = file_notify_bpf__open_and_load();
    if (!skel) {
        printf("Unabled to open and load bpf\n");
        return 1;
    }

    ret = file_notify_bpf__attach(skel);
    if (ret) {
        printf("Unable to attach bpf: %d\n", ret);
    }

    for (int i = 1; i < argc; i++)
    {
        if (argv[i] && argv[i]) {
            int ret = file_notify__ban_filepath(skel, argv[i]);

            if (ret) {
                fprintf(stderr, "Unable to ban file:%s :%d\n", argv[i], ret);
            } else {
                printf("Banning file:%s\n", argv[i]);
            }
        } else {
            break;
        }
    }

    // Where we'd poll for events from perf or ring buffer
    while (true) {
        sleep(1000);
    }

    if (skel) {
        file_notify_bpf__destroy(skel);
    }
    return ret;
}

bool has_bpf_lsm_loaded(void)
{
    return file_notify__bpf_lsm_enabled() == 0;
}


int main(int argc, const char *argv[])
{
    if (!has_bpf_lsm_loaded()) {
        fprintf(stderr, "Unable to run tests: bpf lsm not loaded\n");
        fprintf(stderr, "  Kernels with BPF LSM can be configured to load this on boot.\n");
        return 0;
    }

    init_basic(argc, argv);

    return 0;
}
