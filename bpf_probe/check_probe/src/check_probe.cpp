// Copyright 2021 VMware Inc.  All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"
#include "BpfProgram.h"

#include "sensor.skel.h"

#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>

using namespace cb_endpoint::bpf_probe;

static void PrintUsage();
static void ParseArgs(int argc, char** argv);
static void ReadProbeSource(const std::string &probe_source);
static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program);
static void ProbeEventCallback(Data data);
static void DroppedCallback(uint64_t drop_count);
static std::string EventToBlobStrings(const data *event);
static std::string EventToExtraData(const data *event);
static void PrintNetEvent(std::stringstream &ss, const data *event);
static void CompatFilePathData(std::stringstream &output,
                               const data *event);

static std::string s_bpf_program;
static bool read_events = false;
static bool try_bcc_first = false;
static unsigned int verbosity = 0;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    switch (verbosity)
    {
    case 0:
        if (level == LIBBPF_DEBUG)
            return 0;
        return vfprintf(stdout, format, args);

    case 1:
        if (level == LIBBPF_DEBUG)
            return vfprintf(stderr, format, args);
        return vfprintf(stdout, format, args);

    default:
        return vfprintf(stdout, format, args);
    }
}

int main(int argc, char *argv[])
{
    ParseArgs(argc, argv);

    printf("Attempting to load probe...\n");
    std::unique_ptr<BpfApi> bpf_api = std::unique_ptr<BpfApi>(new BpfApi());
    if (!bpf_api)
    {
        printf("Create probe failed\n");
        return 1;
    }

    bpf_api->SetLibBpfLogCallback(libbpf_print_fn);

    if (!LoadProbe(*bpf_api, (!s_bpf_program.empty() ? s_bpf_program : BpfProgram::DEFAULT_PROGRAM)))
    {
        printf("Load probe failed\n");
        return 1;
    }

    printf("Probe loaded!\n");

    if (read_events)
    {
        auto didRegister = bpf_api->RegisterEventCallback(ProbeEventCallback,
                                                          DroppedCallback);
        if (!didRegister)
        {
            printf("Failed to register callback\n");
            return 1;
        }

        while(true)
        {
            auto result = bpf_api->PollEvents();
            if (result < 0)
            {
                printf("Poll data Error: returned %d\n", result);
                return 1;
            }
        }
    }

    return 0;
}

static void PrintUsage()
{
    printf("Usage: -- [options]\nOptions:\n");
    printf(" -h - this message\n");
    printf(" -p - probe source file to test\n");
    printf(" -r - read events after loading probe\n");
    printf(" -L - try loading libbpf first\n");
    printf(" -B - try loading BCC first\n");
    printf(" -v - Add verbosity\n");
}

static void ParseArgs(int argc, char** argv)
{
    int                 option_index    = 0;
    struct option const long_options[]  = {
        {"help",                no_argument,       nullptr, 'h'},
        {"probe-source",        required_argument, nullptr, 'p'},
        {"read-events",         no_argument,       nullptr, 'r'},
        {"try-bcc-first",       no_argument,       nullptr, 'B'},
        {"try-libbpf-first",    no_argument,       nullptr, 'L'},
        {"verbose",             no_argument,       nullptr, 'v'},
        {nullptr, 0,       nullptr, 0}};

    while(true)
    {
        int opt = getopt_long(argc, argv, "hp:rLBv", long_options, &option_index);
        if(-1 == opt) break;

        switch(opt)
        {
            case 'v':
                verbosity += 1;
                break;
            case 'L':
                try_bcc_first = false;
                break;
            case 'B':
                try_bcc_first = true;
                break;
            case 'p':
                ReadProbeSource(optarg);
                break;
            case 'r':
                read_events = true;
                break;
            case 'h':
            default:
                PrintUsage();
                exit(1);
                break;
        }
    }
}

static void ReadProbeSource(const std::string &probe_source)
{
    if (!probe_source.empty())
    {
        auto fileHandle = open(probe_source.c_str(), O_RDONLY);
        if (fileHandle < 0)
        {
            return;
        }

        struct stat data;
        int result = fstat(fileHandle, &data);

        if (result == 0)
        {
            std::unique_ptr<unsigned char []> buffer(new unsigned char[data.st_size + 1]);

            ssize_t ret = read(fileHandle, buffer.get(), data.st_size);
            if ((ret > 0) && (ret == data.st_size))
            {
                char* pTmp = (char *)buffer.get();
                pTmp[data.st_size] = 0;
                s_bpf_program = pTmp;
            }
        }

        close(fileHandle);
    }
}

static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program)
{
    if (bpf_program.empty())
    {
        printf("Invalid argument to 'LoadProbe'\n");
        return false;
    }
    const char *preferred_instance = "Unknown";
    if (try_bcc_first)
    {
        preferred_instance = "Bcc";
    }
    else
    {
        preferred_instance = "Libbpf";
    }

    bool init = bpf_api.Init(bpf_program, try_bcc_first);
    if (!init)
    {
        printf("Failed to init BPF program: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    BpfApi::ProgInstanceType instance_type = bpf_api.GetProgInstanceType();
    printf("PreferredInstance: %s InstanceType: %s\n", preferred_instance,
           BpfApi::InstanceTypeToString(instance_type));

    if (!BpfProgram::InstallHooks(bpf_api, BpfProgram::DEFAULT_HOOK_LIST))
    {
        printf("Failed to attach a probe hook: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    return true;
}

static void DroppedCallback(uint64_t drop_count)
{
    std::cout << "DROPPED EVENTS:" << drop_count << std::endl;
}

void ProbeEventCallback(Data data)
{
    if (data.data)
    {
        std::stringstream output;

        bool isStartingMessage = (data.data->header.state == PP_ENTRY_POINT) || (data.data->header.state == PP_NO_EXTRA_DATA);
        bool isEndingMessage = (data.data->header.state == PP_FINALIZED) ||
                (data.data->header.state == PP_NO_EXTRA_DATA);
        bool hasPathData = (data.data->header.state == PP_PATH_COMPONENT) ||
                (data.data->header.state == PP_ENTRY_POINT && data.data->header.type == EVENT_PROCESS_EXEC_ARG) ||
                (data.data->header.state == PP_APPEND && data.data->header.type != EVENT_NET_CONNECT_DNS_RESPONSE);

        if (isStartingMessage) {
            output << "\n+++++++++++++++++++++ " << BpfApi::TypeToString(data.data->header.type) << " ++++++++++++++++++++++\n";
        }

        output << data.data->header.event_time << " "
               << BpfApi::TypeToString(data.data->header.type) << "::"
               << BpfApi::StateToString(data.data->header.state) << " "
               << "tid:" << data.data->header.tid << " "
               << "pid:" << data.data->header.pid << " "
               << "pid_ns_vnr:" << data.data->header.pid_ns_vnr << " "
               << "ppid:" << data.data->header.ppid << " "
               << "pid_ns:" << data.data->header.pid_ns << " "
               << "mnt_ns:" << data.data->header.mnt_ns;

        output << " report_flags:0x" << std::hex
               << data.data->header.report_flags << std::dec;

        if (data.data->header.report_flags & REPORT_FLAGS_DYNAMIC)
        {
            output << " payload:" << data.data->header.payload;
            output << " [" << EventToBlobStrings(data.data) << "]";
        }
        else if (hasPathData)
        {
            auto pdata = reinterpret_cast<const path_data*>(data.data);
            output << " [" << pdata->fname << "]";
        }
        else if (data.data->header.report_flags & REPORT_FLAGS_TASK_DATA)
        {
            output << " [" << EventToExtraData(data.data) << "]";
        }

        // Print extra compat primitive data here
        if (!(data.data->header.report_flags & REPORT_FLAGS_DYNAMIC))
        {
            CompatFilePathData(output, data.data);
        }

        if (data.data->header.type == EVENT_PROCESS_EXEC_RESULT)
        {
            auto exec_result = reinterpret_cast<const exec_data *>(data.data);
            output << " ret:" << exec_result->retval;
        }

        if (isEndingMessage) {
            output << "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
        }

        std::cout << output.str() << std::endl;

        delete [] data.data;
    }
}

static std::string BlobToArgs(const data *event,
                              const struct blob_ctx &blob_entry)
{
    std::string raw_args;

    if (event && blob_entry.size && blob_entry.offset)
    {
        auto blob = reinterpret_cast<const char *>(event) + blob_entry.offset;

        for (size_t i = 0; i < blob_entry.size; i++)
        {
            std::string exec_arg;

            while (blob[i] && i < blob_entry.size)
            {
                exec_arg.append(1, blob[i]);
                i++;
            }

            if (!exec_arg.empty())
            {
                if (!raw_args.empty())
                {
                    raw_args.append(1, ' ');
                }
                raw_args += exec_arg;
            }
        }
    }

    return raw_args;
}

static std::string BlobToPath(const data *event,
                              const blob_ctx &blob_entry)
{
    std::stringstream ss;

    ss << " size:" << blob_entry.size;
    ss << " offset:" << blob_entry.offset;

    if (event && blob_entry.size && blob_entry.offset)
    {
        std::list<std::string> comps;
        auto blob = reinterpret_cast<const char *>(event) + blob_entry.offset;

        ss << " ";

        for (size_t i = 0; i < blob_entry.size; i++)
        {
            std::string path_component;

            while (blob[i] && i < blob_entry.size)
            {
                path_component.append(1, blob[i]);
                i++;
            }

            if (!path_component.empty())
            {
                comps.emplace_front(path_component);
            }
        }

        for (const auto &comp : comps)
        {
            ss << "/" << comp;
        }
    }

    return ss.str();
}

static std::string EventToBlobStrings(const data *event)
{
    if (!(event->header.report_flags & REPORT_FLAGS_DYNAMIC))
    {
        return "";
    }

    std::stringstream ss;

    switch (event->header.type)
    {
    case EVENT_PROCESS_EXEC_ARG: {
        auto exec_arg = reinterpret_cast<const exec_arg_data *>(event);

        ss << " ExecArgBlob: ";
        ss << BlobToArgs(event, exec_arg->exec_arg_blob);
        ss << " CgroupBlob:";
        ss << BlobToPath(event, exec_arg->cgroup_blob);
        return ss.str();
    }

    case EVENT_PROCESS_EXIT: {
        auto data = reinterpret_cast<const struct data_x *>(event);

        return BlobToPath(event, data->cgroup_blob);
    }

    case EVENT_PROCESS_CLONE:
    case EVENT_PROCESS_EXEC_PATH:
    case EVENT_FILE_READ:
    case EVENT_FILE_WRITE:
    case EVENT_FILE_CREATE:
    case EVENT_FILE_PATH:
    case EVENT_FILE_DELETE:
    case EVENT_FILE_CLOSE:
    case EVENT_FILE_MMAP: {
        auto data_x = reinterpret_cast<const file_path_data_x *>(event);

        ss << " FilePathBlob:" << BlobToPath(event, data_x->file_blob);
        ss << " CgroupBlob:" << BlobToPath(event, data_x->cgroup_blob);
        ss << std::hex << " fsmagic:0x" << data_x->fs_magic << std::dec;

        return ss.str();
    }

    //struct net_data_x
    case EVENT_NET_CONNECT_PRE:
    case EVENT_NET_CONNECT_ACCEPT: {
        auto data_x = reinterpret_cast<const net_data_x *>(event);

        PrintNetEvent(ss, event);
        ss << BlobToPath(event, data_x->cgroup_blob);
        return ss.str();
    }

    case EVENT_NET_CONNECT_DNS_RESPONSE: {
        auto data_x = reinterpret_cast<const dns_data_x *>(event);

        return BlobToPath(event, data_x->cgroup_blob);
    }

    case EVENT_FILE_RENAME: {
        auto data_x = reinterpret_cast<const rename_data_x *>(event);

        ss << " OldFileBlob:" << BlobToPath(event, data_x->old_blob);
        ss << " NewFileBlob:" << BlobToPath(event, data_x->new_blob);
        ss << " CgroupBlob:" << BlobToPath(event, data_x->cgroup_blob);
        return ss.str();
    }

    // Does not return blob data
    case EVENT_PROCESS_EXEC_RESULT: {
        return "Not sure how to access blob data";
    }

    // Unused for the most part
    case EVENT_NET_CONNECT_WEB_PROXY:
    case EVENT_FILE_TEST:
    default:
        break;
    }

    return "Blob data unused here";
}

static void EventToExtraData(std::stringstream &ss,
                             const struct extra_task_data &extra_data)
{
    if (extra_data.cgroup_size) {
        ss << " CgroupName[size:" << (uint32_t)extra_data.cgroup_size;
        ss << " '" << extra_data.cgroup_name << "']";
    }
}

static std::string EventToExtraData(const data *event)
{
    std::stringstream ss;

    switch (event->header.type)
    {
    // single message events - aka struct specific handling for extra data
    case EVENT_PROCESS_CLONE: {
        auto data = reinterpret_cast<const file_data *>(event);

        EventToExtraData(ss, data->extra);
        break;
    }
    case EVENT_PROCESS_EXEC_RESULT: {
        auto data = reinterpret_cast<const exec_data *>(event);

        EventToExtraData(ss, data->extra);
        break;
    }
    case EVENT_PROCESS_EXIT: {
        EventToExtraData(ss, event->extra);
        break;
    }
    case EVENT_NET_CONNECT_PRE:
    case EVENT_NET_CONNECT_ACCEPT: {
        auto net_data = reinterpret_cast<const net_data_compat *>(event);

        PrintNetEvent(ss, event);
        EventToExtraData(ss, net_data->extra);
        break;
    }

    // multi message events - aka struct data with PP_FINALIZED
    default:
        if (event->header.state == PP_FINALIZED) {
            EventToExtraData(ss, event->extra);
        } else {
            ss << "{Not Finalized But Has Cgroup Name???}";
        }
        break;
    }

    return ss.str();
}

static void PrintNetEvent(std::stringstream &ss, const data *event)
{
    char local[64] = {};
    char remote[64] = {};
    const net_data *net_data = nullptr;

    if (event->header.report_flags & REPORT_FLAGS_DYNAMIC)
    {
        net_data = &reinterpret_cast<const net_data_x *>(event)->net_data;
    }
    else
    {
        net_data = &reinterpret_cast<const net_data_compat *>(event)->net_data;
    }

    inet_ntop(net_data->ipver, &net_data->local_addr, local, sizeof(local));
    inet_ntop(net_data->ipver, &net_data->remote_addr, remote, sizeof(remote));

    if (net_data->protocol == IPPROTO_UDP)
    {
        ss << "udp ";
    }
    else
    {
        ss << "tcp ";
    }

    if (net_data->ipver == AF_INET)
    {
        ss << "ipv4 ";
    }
    else
    {
        ss << "ipv6 ";
    }

    ss << local << ":" << ntohs(net_data->local_port);
    ss << " -> ";
    ss << remote << ":" << ntohs(net_data->remote_port);
    ss << " ";
}

static void CompatFilePathData(std::stringstream &output,
                               const data *event)
{
    if (event->header.state != PP_ENTRY_POINT ||
        (event->header.report_flags & REPORT_FLAGS_DYNAMIC))
    {
        return;
    }

    switch (event->header.type)
    {
    case EVENT_PROCESS_CLONE:
    case EVENT_PROCESS_EXEC_PATH:
    case EVENT_FILE_READ:
    case EVENT_FILE_WRITE:
    case EVENT_FILE_CREATE:
    case EVENT_FILE_PATH:
    case EVENT_FILE_DELETE:
    case EVENT_FILE_CLOSE:
    case EVENT_FILE_MMAP: {

        auto compat_file_data = reinterpret_cast<const file_data *>(event);

        output << " ino:" << compat_file_data->inode;
        output << std::hex;
        output << " dev:0x"  << compat_file_data->device;
        output << " fsmagic:0x" << compat_file_data->fs_magic;
        output << std::dec;

        break;
    }

    default:
        break;
    }
}
