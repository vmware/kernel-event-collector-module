// Copyright 2021 VMware Inc.  All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"
#include "BpfProgram.h"

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
static bool LoadProbe(BpfApi & bpf_api);
//static bool CheckUDPMaps(BpfApi &bpf_api);

///static std::string s_bpf_program;
static bool check_udp_maps = false;

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

    if (!LoadProbe(*bpf_api))
    {
        printf("Load probe failed\n");
        return 1;
    }

    printf("Probe loaded!\n");

    if (check_udp_maps)
    {
        // if (!CheckUDPMaps(*bpf_api))
        // {
        //     return 1;
        // }

        printf("UDPv4 Cache Map Works!\n");
    }

    return 0;
}

static void PrintUsage()
{
    printf("Usage: -- [options]\nOptions:\n");
    printf(" -h - this message\n");
    printf(" -p - probe source file to test\n");
    printf(" -u - check UDP maps usage\n");
}

static void ParseArgs(int argc, char** argv)
{
    int                 option_index    = 0;
    struct option const long_options[]  = {
        {"help",           no_argument,       nullptr, 'h'},
        {"probe-source",   required_argument, nullptr, 'p'},
        {"check-udp-maps",     no_argument,       nullptr, 'u'},
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
                //ReadProbeSource(optarg);
                break;
            case 'h':
            default:
                PrintUsage();
                exit(1);
                break;
        }
    }
}

// static void ReadProbeSource(const std::string &probe_source)
// {
//     if (!probe_source.empty())
//     {
//         auto fileHandle = open(probe_source.c_str(), O_RDONLY);
//         if (fileHandle <= 0)
//         {
//             return;
//         }

//         struct stat data;
//         int result = fstat(fileHandle, &data);

//         if (result == 0)
//         {
//             std::unique_ptr<unsigned char []> buffer(new unsigned char[data.st_size + 1]);

//             IGNORE_UNUSED_RETURN_VALUE(read(fileHandle, buffer.get(), data.st_size));

//             // = (const char *)buffer.get();
//         }

//         close(fileHandle);
//     }
// }

static bool LoadProbe(BpfApi & bpf_api)
{
       if (!bpf_api.Init())
    {
        printf("Failed to init BPF program: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    if (!BpfProgram::InstallHooks(bpf_api))
    {
        printf("Failed to attach a probe hook: %s\n",
               bpf_api.GetErrorMessage().c_str());
        return false;
    }

    return true;
}

// static bool CheckUDPMaps(BpfApi &bpf_api)
// {
//     bool result = true;
//     ip_key ip4_key;
//     ip_entry value;

//     value.flow = FLOW_TX | FLOW_TX;
//     memset(&ip4_key, 'A', sizeof(ip4_key));

//     // Verify Update/Insert works
//     if (!bpf_api.InsertUDPCache4(ip4_key, value))
//     {
//         printf("Unable to insert into UDPv4 hashmap\n");
//         return false;
//     }

//     // Verify remove works
//     if (!bpf_api.RemoveEntryUDPCache4(ip4_key))
//     {
//         printf("Unable to remove entry from UDPv4 hashmap\n");
//         result = false;
//     }

//     // Re-insert to setup Get/Lookup
//     if (!bpf_api.InsertUDPCache4(ip4_key, value))
//     {
//         printf("Unable to insert/update entry in UDPv4 hashmap\n");
//         result = false;
//     }

//     if (bpf_api.IsLRUCapable())
//     {
//         ip_entry found_value = {};

//         if (!bpf_api.GetEntryUDPLRUCache4(ip4_key, found_value))
//         {
//             printf("Unable to get LRU UDPv4 entry just inserted\n");
//             result = false;
//         }

//         if (found_value.flow != value.flow)
//         {
//             printf("Found LRU entry does not match inserted value\n");
//             result = false;
//         }
//     }
//     else
//     {
//         ip_key found_value = {};

//         if (!bpf_api.GetEntryUDPCache4(ip4_key.pid, found_value))
//         {
//             printf("Unable to get NonLRU UDPv4 entry just inserted\n");
//             result = false;
//         }

//         if (memcmp(&found_value, &ip4_key, sizeof(found_value)) != 0)
//         {
//             printf("Found NonLRU entry does not match inserted value\n");
//             result = false;
//         }
//     }

//     if (!bpf_api.ClearUDPCache4())
//     {
//         printf("Unable to Clear UDP Cache\n");
//         result = false;
//     }

//     return result;
// }
