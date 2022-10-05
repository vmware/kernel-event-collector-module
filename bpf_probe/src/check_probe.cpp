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

using namespace cb_endpoint::bpf_probe;

static void PrintUsage();
static void ParseArgs(int argc, char** argv);
static void ReadProbeSource(const std::string &probe_source);
static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program);

static std::string s_bpf_program;
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

    return 0;
}

static void PrintUsage()
{
    printf("Usage: -- [options]\nOptions:\n");
    printf(" -h - this message\n");
    printf(" -p - probe source file to test\n");
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
        {"try-bcc-first",       no_argument,       nullptr, 'B'},
        {"try-libbpf-first",    no_argument,       nullptr, 'L'},
        {"verbose",             no_argument,       nullptr, 'v'},
        {nullptr, 0,       nullptr, 0}};

    while(true)
    {
        int opt = getopt_long(argc, argv, "hp:LBv", long_options, &option_index);
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
