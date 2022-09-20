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
static bool check_udp_maps = false;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
    ParseArgs(argc, argv);
    libbpf_set_print(libbpf_print_fn);

    printf("Attempting to load probe...\n");
    std::unique_ptr<BpfApi> bpf_api = std::unique_ptr<BpfApi>(new BpfApi());
    if (!bpf_api)
    {
        printf("Create probe failed\n");
        return 1;
    }

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
}

static void ParseArgs(int argc, char** argv)
{
    int                 option_index    = 0;
    struct option const long_options[]  = {
        {"help",           no_argument,       nullptr, 'h'},
        {"probe-source",   required_argument, nullptr, 'p'},
        {nullptr, 0,       nullptr, 0}};

    while(true)
    {
        int opt = getopt_long(argc, argv, "hp:u", long_options, &option_index);
        if(-1 == opt) break;

        switch(opt)
        {
            case 'u':
                check_udp_maps = true;
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

    bool init = bpf_api.Init(bpf_program);
    int prog_type = bpf_api.m_ProgType;

    const char *prog_type_name = "UNINIT";
    if (prog_type == PROG_TYPE_BCC) prog_type_name = "BCC";
    if (prog_type == PROG_TYPE_LIBBPF) prog_type_name = "LIBBPF";
    fprintf(stderr, "prog_type: %s\n", prog_type_name);

    if (!init)
    {
        printf("Failed to init BPF program: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    if (!BpfProgram::InstallHooks(bpf_api, BpfProgram::DEFAULT_HOOK_LIST))
    {
        printf("Failed to attach a probe hook: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    return true;
}
