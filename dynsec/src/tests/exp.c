// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "dynsec.h"
#include "exp.h"

uint32_t cmp_dynsec_file(uint32_t exp_mask,
                             uint32_t *err_mask,
                             const struct dynsec_file *exp,
                             const struct dynsec_file *act)
{
    uint32_t local_mask = 0;
    uint32_t local_err_mask = 0;

    if (err_mask) {
        *err_mask = local_err_mask;
    }

    return local_mask;
}

uint32_t cmp_dynsec_msg_hdr(uint32_t exp_mask,
                                uint32_t *err_mask,
                                const struct dynsec_msg_hdr *exp,
                                const struct dynsec_msg_hdr *act)
{
    uint32_t local_mask = 0;
    uint32_t local_err_mask = 0;

    if (err_mask) {
        *err_mask = local_err_mask;
    }

    return local_mask;
}

uint32_t cmp_task_ctx(uint32_t exp_mask,
                          uint32_t *err_mask,
                          const struct dynsec_msg_hdr *exp,
                          const struct dynsec_msg_hdr *act)
{
    uint32_t local_mask = 0;
    uint32_t local_err_mask = 0;

    if (err_mask) {
        *err_mask = local_err_mask;
    }

    return local_mask;
}

void release_matches(struct matches *matches)
{
    int i;
    struct match_obj *match = NULL;

    if (!matches || !matches->match) {
        return;
    }

    match = matches->match;


    for (i = 0; i < matches->count; i++, match++) {
        if (match->act_hdr) {
            free(match->act_hdr);
            match->act_hdr = NULL;
        }
    }

    matches->count = 0;
    matches->total_found = 0;
}

bool find_match(struct matches *matches,
                const struct dynsec_msg_hdr *act_hdr)
{
    int i;
    bool found = false;
    struct match_obj *match = NULL;

    if (!matches || !matches->match || !act_hdr) {
        return false;
    }

    // For now have this only act like MATCH_BY_FIRST_ANY
    // aka find the first matching occurence and stop.
    match = matches->match;

    if (matches->match_type == MATCH_BY_FIRST_ANY) {
        for (i = 0; i < matches->count; i++, match++) {
            if (match_event(match, act_hdr)) {
                found = true;
                matches->total_found += 1;
                break;
            }
        }
    }
    // Find the first entry in the list that matches
    // skipping already seen matched
    else if (matches->match_type == MATCH_BY_SEQ) {
        for (i = 0; i < matches->count; i++, match++) {
            // skip if entry already matched
            if (match->total_matched) {
                continue;
            }
            if (match_event(match, act_hdr)) {
                found = true;
                matches->total_found += 1;
                break;
            }
        }
    }

    return found;
}

// Currently just super primitive matching
// Eventually return some computed mask
bool match_event(struct match_obj *obj,
                 const struct dynsec_msg_hdr *act_hdr)
{
    if (!obj || !act_hdr) {
        return false;
    }

    if (obj->hdr.exp_mask & EXP_HDR_EVENT_TYPE)
    {
        if (act_hdr->event_type != obj->hdr.hdr.event_type)
        {
            return false;
        }
    }

    if (obj->hdr.exp_mask & EXP_HDR_REPORT_INTENT)
    {
        if (!(act_hdr->report_flags & DYNSEC_REPORT_INTENT))
        {
            return false;
        }
    }

    if (obj->hdr.exp_mask & EXP_HDR_REPORT_STALL)
    {
        if (!(act_hdr->report_flags & DYNSEC_REPORT_STALL))
        {
            return false;
        }
    }

    if (obj->hdr.exp_mask & EXP_HDR_REPORT_SELF)
    {
        if (!(act_hdr->report_flags & DYNSEC_REPORT_SELF))
        {
            return false;
        }
    }

    // Something else may have already matched!
    if (!obj->act_hdr) {
        // Duplicate Entry...
        obj->act_hdr = malloc(act_hdr->payload);
        if (obj->act_hdr) {
            memcpy(obj->act_hdr, act_hdr, act_hdr->payload);
        }
    }

    obj->total_matched += 1;

    return true;
}

