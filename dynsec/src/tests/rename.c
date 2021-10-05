// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include "rename.h"
#include "exp.h"
#include "client.h"

#include "test_utils.h"

#define RENAME_OLDNAME ".rename.oldpath"
#define RENAME_NEWNAME ".rename.newpath"


// Private data within `struct test_case`
// 
struct rename_test_data {
    char olddir[PATH_MAX];
    char newdir[PATH_MAX];

    char oldpath[PATH_MAX];
    char newpath[PATH_MAX];

    struct dynsec_file exp_old;
    struct dynsec_file exp_new;

    // List of events to match on to save off
    struct matches matches;
};


static struct match_obj rename_matchers[] = {
    {
        .hdr = {
            .exp_mask = (EXP_HDR_EVENT_TYPE | EXP_HDR_REPORT_INTENT),
            .hdr = {
                .event_type = DYNSEC_EVENT_TYPE_RENAME,
            }
        },
    },
    {
        .hdr = {
            .exp_mask = (EXP_HDR_EVENT_TYPE | EXP_HDR_REPORT_STALL),
            .hdr = {
                .event_type = DYNSEC_EVENT_TYPE_RENAME,
            }
        },
    },
    {
        .hdr = {
            .exp_mask = EXP_HDR_EVENT_TYPE,
            .hdr = {
                .event_type = DYNSEC_EVENT_TYPE_EXIT,
            }
        },
    },
};



// Use to find the matching events.
// Will be called in dynsec_client_read_events from the
// regular event_cb.
enum DYNSEC_EAT rename_match_cb(struct dynsec_client *client,
                                const struct dynsec_msg_hdr *hdr)
{
    struct test_case *test_case = client->private_data;
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return DYNSEC_EAT_DEFAULT;
    }

    data = test_case->private_data;
    if (!data) {
        return DYNSEC_EAT_DEFAULT;
    }

    (void)find_match(&data->matches, hdr);
    // fprintf(stderr, "%s: total_found:%lu\n",
    //         __func__, data->matches.total_found);

    return DYNSEC_EAT_DEFAULT;
}

// Call to primarly only release/free objects
// not ideal for performing operations DynSec may observe.
void release_rename(struct test_case *test_case)
{
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return;
    }

    data = test_case->private_data;

    if (!data) {
        return;
    }

    if (data->matches.match) {
        release_matches(&data->matches);
        free(data->matches.match);
        data->matches.match = NULL;
    }
    free(data);
    test_case->private_data = NULL;
}

// For now deep copies the list of match objects
static int setup_rename_matcher(struct test_case *test_case)
{
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return -EINVAL;
    }
    data = test_case->private_data;

    if (!data) {
        return 0;
    }

    data->matches.count = ARRAY_SIZE(rename_matchers);
    if (data->matches.count > 0) {
        data->matches.match = malloc(sizeof(rename_matchers));
        if (!data->matches.match) {
            return -ENOMEM;
        }
        memcpy(data->matches.match, rename_matchers, sizeof(rename_matchers));
    }
    return 0;
}

int setup_rename_matcher0(struct test_case *test_case)
{
    return setup_rename_matcher(test_case);
}

int setup_rename0(struct test_case *test_case)
{
    int fd;
    struct rename_test_data *data;

    if (!test_case) {
        return -EINVAL;
    }

    test_case->private_data = NULL;

    if (!test_case->base.dir || !*(test_case->base.dir) ||
        test_case->base.dirfd < 0) {
        return -EINVAL;
    }

    data = malloc(sizeof(*data));
    if (!data) {
        return -ENOMEM;
    }

    test_case->private_data = data;
    memset(data, 0, sizeof(*data));
    memset(data->oldpath, 'a', sizeof(data->oldpath));
    memset(data->newpath, 'a', sizeof(data->newpath));

    snprintf(data->oldpath, sizeof(data->oldpath), "%s/%s",
              test_case->base.dir, RENAME_OLDNAME);
    snprintf(data->newpath, sizeof(data->newpath), "%s/%s",
              test_case->base.dir, RENAME_NEWNAME);

    // Create Source/Old Path
    unlinkat(test_case->base.dirfd, data->oldpath, 0);
    fd = open(data->oldpath, O_CREAT|O_RDONLY, CREATE_MODE);
    if (fd < 0) {
        return -errno;
    }
    fill_in_exp_dynsec_file(test_case->base.dirfd, fd, &data->exp_old);
    close(fd);

    return 0;
}



int test_case_rename0(struct test_case *test_case)
{
    int local_errno = 0;
    int result = -EINVAL;
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return -EINVAL;
    }
    data = test_case->private_data;
    if (!data) {
        return -EINVAL;
    }

    result = rename(data->oldpath, data->newpath);
    if (result < 0) {
        local_errno = -errno;
        fprintf(stderr, "%s,%s :%d\n", data->oldpath, data->newpath, local_errno);
    }

    write_test_result(test_case, result, local_errno, "");
    return local_errno;
}

int verify_rename0(struct test_case *test_case)
{
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return -EINVAL;
    }
    data = test_case->private_data;
    if (!data) {
        return -EINVAL;
    }

    if (data->matches.total_found == data->matches.count) {
        return 0;
    }
    return 1;
}

int teardown_rename0(struct test_case *test_case)
{
    struct rename_test_data *data = NULL;

    if (!test_case) {
        return 0;
    }

    data = test_case->private_data;
    if (data) {
        if (test_case->base.dirfd >= 0) {
            unlinkat(test_case->base.dirfd, RENAME_OLDNAME, 0);
            unlinkat(test_case->base.dirfd, RENAME_NEWNAME, 0);
        } else {
            unlink(data->oldpath);
            unlink(data->newpath);
        }
    }

    return 0;
}


static struct test_case rename_tests[] = {
    {
        .name = "rename",
        .desc = "rename reg file in basedir",

        .event_hook = rename_match_cb,

        .setup = setup_rename0,
        .setup_matcher = setup_rename_matcher0,
        .func = test_case_rename0,
        .verify = verify_rename0,
        .teardown = teardown_rename0,
        .release = release_rename,
    },
};


struct test_suite rename_fork_test_suite = {
    .test_case = rename_tests,
    .size = ARRAY_SIZE(rename_tests),
};

