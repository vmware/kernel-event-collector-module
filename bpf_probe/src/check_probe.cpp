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

using namespace cb_endpoint::bpf_probe;

static void PrintUsage();
static void ParseArgs(int argc, char** argv);
static void ReadProbeSource(const std::string &probe_source);
static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program);
static void ProbeEventCallback(Data data);

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
        auto didRegister = bpf_api->RegisterEventCallback(ProbeEventCallback);
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

void ProbeEventCallback(Data data)
{
    if (data.data)
    {
        std::stringstream output;

        if (data.data->header.state == PP_ENTRY_POINT || data.data->header.state == PP_NO_EXTRA_DATA) {
            output << "\n+++++++++++++++++++++ " << BpfApi::TypeToString(data.data->header.type) << " ++++++++++++++++++++++\n";
        }
        output << data.data->header.event_time << " "
               << BpfApi::TypeToString(data.data->header.type) << "::"
               << BpfApi::StateToString(data.data->header.state) << " "
               << "tid:" << data.data->header.tid << " "
               << "ppid:" << data.data->header.ppid;

        if (data.data->header.report_flags & REPORT_FLAGS_DYNAMIC)
        {
            output << " report_flags:0x" << std::hex
                   << data.data->header.report_flags << std::dec;
            output << " payload:" << data.data->header.payload;
        }

        if (data.data->header.state == PP_PATH_COMPONENT || data.data->header.state == PP_ENTRY_POINT || data.data->header.state == PP_APPEND)
        {
            auto pdata = reinterpret_cast<const path_data*>(data.data);
            output << " [" << pdata->fname << "]";
        }

        if (data.data->header.state == PP_CGROUP)
        {
            auto pdata = reinterpret_cast<const path_data*>(data.data);
            output << " >>>>> [" << pdata->fname << "]";
        }

        if (data.data->header.state == PP_FINALIZED || data.data->header.state == PP_NO_EXTRA_DATA) {
            output << "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
        }

        std::cout << output.str() << std::endl;

        delete [] data.data;
    }
}
