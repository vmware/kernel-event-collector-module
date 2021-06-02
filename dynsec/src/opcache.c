/* Copyright 2018 Carbon Black Inc.  All rights reserved. */

#include "opcache.h"
#include "usercomm.h"

#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/limits.h>

// Presently, this is pass-through for exec ops... when file mod ops are
// added, we will implement a simple cache here.
int opcache_is_op_allowed(const struct opcache_ctx* ctx)
{
    if (ctx == NULL)
    {
        return OPC_RESULT_ALLOWED;
    }
    
    return usercomm_is_op_allowed(ctx);
}

int opcache_init(void)
{
    return 0;
}

int opcache_exit(void)
{
    return 0;
}

