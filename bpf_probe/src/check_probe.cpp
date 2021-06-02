// Copyright 2021 VMware Inc.  All rights reserved.

#include "BpfApi.h"
#include "BpfProgram.h"

using namespace cb_endpoint::cb_ebpf;

static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program);

int main(int argc, char *argv[])
{
    printf("Attempting to load probe...\n");
    auto bpf_api = std::make_unique<BpfApi>();
    if (!bpf_api)
    {
        printf("Create probe failed\n");
        return 1;
    }
    
    if (!LoadProbe(*bpf_api, BpfProgram::DEFAULT_PROGRAM))
    {
        printf("Load probe failed\n");
        return 1;
    }

    printf("Probe loaded!\n");
    
    return 0;
}

static bool LoadProbe(BpfApi & bpf_api, const std::string &bpf_program)
{
    if (bpf_program.empty())
    {
        printf("Invalid argument to 'LoadProbe'\n");
        return false;
    }

    if (!bpf_api.Init(bpf_program))
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