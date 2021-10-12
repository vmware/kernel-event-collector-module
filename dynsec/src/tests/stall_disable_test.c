// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <stdio.h>
#include "client.h"
#include "print.h"

int main(int argc, const char *argv[])
{
    int ret;
    struct dynsec_client client;
    struct dynsec_config config;
    struct dynsec_config new_config;

    dynsec_client_register(&client, 0, NULL, NULL);
    ret = dynsec_client_connect(&client, 1, 1, false);
    if (ret < 0) {
        fprintf(stderr, "Unabled to connect to kmod: %d\n", ret);
        return 1;
    }

    ret = dynsec_client_get_config(&client, &config);
    if (ret < 0) {
        fprintf(stderr, "Unable to get dynsec_config:%d\n", ret);
        dynsec_client_reset(&client);
        return 1;
    }
    if (config.stall_mode == 0) {
        fprintf(stderr, "Stall Mode Already Disabled\n");
        dynsec_client_reset(&client);
        return -1;
    }

    ret = dynsec_client_disable_stalling(&client);
    if (ret < 0) {
        fprintf(stderr, "Error disabling stall mode:%d\n", ret);
        dynsec_client_reset(&client);
        return 1;
    }
    ret = dynsec_client_get_config(&client, &new_config);
    if (ret < 0) {
        fprintf(stderr, "Unable to verify disable of stall mode:%d\n", ret);
        dynsec_client_reset(&client);
        return 1;
    }

    if (new_config.stall_mode) {
        printf("FAIL: Disabling stalling did not work\n");
        dynsec_client_reset(&client);
        return 1;
    }

    printf("PASS: Disabled Stalling\n");
    print_dynsec_config(&new_config);

    ret = dynsec_client_enable_stalling(&client);
    if (ret < 0) {
        fprintf(stderr, "ERROR: Unable to restore stalling of client\n");
    }
    ret = dynsec_client_get_config(&client, &new_config);
    if (!ret) {
        printf("Restored back to:\n");
        print_dynsec_config(&new_config);
    }
    dynsec_client_reset(&client);

    return 0;
}
