// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "task-helper.h"

static void _show_process_tracking_table(void *data, void *priv, ProcessContext *context);

int cb_proc_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    seq_printf(m, "%20s | %6s | %12s | %6s | %6s | %6s | %10s | %10s | %5s |\n",
                "Name", "RPID", "RPPID", "PID", "PPID", "TID", "Inode", "Exec Count", "Alive");

    sorted_tracking_table_for_each(_show_process_tracking_table, m, &context);

    return 0;
}

const char *process_tracking_get_proc_name(const char *path)
{
    const char *proc_name = "<unknown>";

    if (path)
    {
        proc_name = strrchr(path, '/');
        if (proc_name)
        {
            proc_name++;
        } else
        {
            proc_name = path;
        }
    }
    return proc_name;
}

static void _show_process_tracking_table(void *data, void *priv, ProcessContext *context)
{
    struct seq_file    *seq_file     = (struct seq_file *)priv;
    ProcessTracking    *procp        = sorted_tracking_table_get_process(data, context);
    const char         *proc_name    = NULL;
    struct task_struct *task         = NULL;
    uint64_t            shared_count = 0;

    TRY(procp && seq_file);

    task = cb_find_task(procp->posix_details.pid);

    proc_name = process_tracking_get_proc_name(procp->shared_data->path);

    shared_count = atomic64_read(&procp->shared_data->reference_count);

    seq_printf(seq_file, "%20s | %6llu | %12llu | %6llu | %6llu | %6llu | %10llu | %10llu | %5s |\n",
                  proc_name,
                  (uint64_t)procp->shared_data->exec_details.pid,
                  (uint64_t)procp->shared_data->exec_parent_details.pid,
                  (uint64_t)procp->posix_details.pid,
                  (uint64_t)procp->posix_parent_details.pid,
                  (uint64_t)procp->tid,
                  procp->posix_details.inode,
                  shared_count,
                  (is_task_alive(task) ? "yes" : "no"));

CATCH_DEFAULT:
    process_tracking_put_process(procp, context);
    return;
}

int cb_proc_track_show_stats(struct seq_file *m, void *v)
{
    seq_printf(m, "%22s | %6llu |\n", "Total Changes",   g_process_tracking_data.op_cnt);
    seq_printf(m, "%22s | %6llu |\n", "Process Creates", g_process_tracking_data.create);
    seq_printf(m, "%22s | %6llu |\n", "Process Forks",   g_process_tracking_data.create_by_fork);
    seq_printf(m, "%22s | %6llu |\n", "Process Execs",   g_process_tracking_data.create_by_exec);
    seq_printf(m, "%22s | %6llu |\n", "Process Exits",   g_process_tracking_data.exit);

    return 0;
}
