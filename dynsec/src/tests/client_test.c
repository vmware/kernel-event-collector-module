// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include "client.h"

// Just does default of everything

int main(int argc, const char *argv[])
{
    struct dynsec_client client;

    dynsec_client_register(&client, 0, NULL, NULL);
    dynsec_client_connect(&client, 1, 1, false);
    dynsec_client_read_events(&client);
    dynsec_client_reset(&client);

    return 0;
}
