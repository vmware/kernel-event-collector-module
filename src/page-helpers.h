/* Copyright 2019 Carbon Black Inc.  All rights reserved. */

#ifndef __PAGE_HELPERS__
#define __PAGE_HELPERS__

#include "priv.h"
#include <linux/unistd.h>

pte_t *lookup_pte(p_sys_call_table address);
bool set_page_state_rw(p_sys_call_table address, unsigned long *old_page_rw);
void restore_page_state(p_sys_call_table address, unsigned long page_rw);

#endif
