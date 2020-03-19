/* Copyright 2019 Carbon Black Inc.  All rights reserved. */

#ifndef __PATCH_SCHED__
#define __PATCH_SCHED__

#include "priv.h"
#include <linux/sched.h>

bool patch_sched(ProcessContext *context);
void restore_sched(ProcessContext *context);
bool sched_changed(ProcessContext *context);

#endif
