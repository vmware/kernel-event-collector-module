# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

from conans import python_requires, CMake, tools, AutoToolsBuildEnvironment
import os
from datetime import datetime

base = python_requires("CONAN_UTIL_VERSION")

class KernelEventCollectorModule(base.CbConanFile):
    name     = "KernelEventCollectorModule"
    version  = "PROJECT_VERSION"
    settings = "os", "arch"
    generators = "cmake"
    build_requires = "CPPUTEST_VERSION"
    options = {
        'module_name': ['event_collector', 'cbsensor']
    }
    default_options = "module_name=event_collector"

    kernelDeps = [
        "KERNEL_RHEL_6_6_VERSION", "KERNEL_RHEL_6_7_VERSION",
        "KERNEL_RHEL_6_8_VERSION", "KERNEL_RHEL_6_9_VERSION",
        "KERNEL_RHEL_6_10_VERSION",
        "KERNEL_RHEL_7_0_VERSION", "KERNEL_RHEL_7_1_VERSION",
        "KERNEL_RHEL_7_2_VERSION", "KERNEL_RHEL_7_3_VERSION",
        "KERNEL_RHEL_7_4_VERSION", "KERNEL_RHEL_7_5_VERSION",
        "KERNEL_RHEL_7_6_VERSION", "KERNEL_RHEL_7_7_VERSION",
        "KERNEL_RHEL_7_8_VERSION", "KERNEL_RHEL_7_9_VERSION"
    ]
    override_list = "KERNEL_OVERRIDE_LIST"

    def configure(self):
        self.KernelHelper.AddKernelRequires(self,
                                            requires=self.kernelDeps,
                                            override_list=self.override_list)

    #############################################################################################
    # Gets the module version suffix, from the PACKAGE_VERSION.
    # This version suffix becomes a part of the ".ko" filename, also is compiled into code and
    # becomes a part of the device name created by the module.
    # Doing this should allow for more than one kernel-modules to be installed on the system
    # (since each will have its own unique device-node.)
    # example:
    # PACKAGE_VERSION would be 1.6.12349
    # module_version_suffix would be 1_6_12349
    #
    # Converting dots to underscore just because insmod does not like dots.
    #############################################################################################
    def getModuleVersionSuffix(self):

        # Extracting the package_version from
        module_version_suffix = "PACKAGE_VERSION"
        module_version_suffix = module_version_suffix.replace('.', '_')

        return module_version_suffix

    def build(self):
        self.checKernelSource()
        self.buildRedhatKernels("redhat6")
        self.buildRedhatKernels("redhat7")
        self.buildRedhatKernels("redhat8")

    def checKernelSource(self):
        self.log("## Check Kernel Source")
        cmake     = CMake(self)
        env_build = AutoToolsBuildEnvironment(self)

        with tools.environment_append(env_build.vars):
            if os.getenv("FAST_BUILD") != "1":
                cmake.configure(source_dir=self.source_folder)
            cmake.build()

    def buildRedhatKernels(self, distro):
        source_dir = self.source_folder + "/src"
        build_dir  = self.build_folder + os.path.sep + distro
        message    = "## Build {} Kernels".format(distro)

        module_version_suffix = self.getModuleVersionSuffix()

        opts = self.KernelHelper.GetKernelOpts(self,
                                               "",
                                               module_version_suffix,
                                               distro=distro)

        if self.options.module_name == 'event_collector':
            opts["PROC_DIR"]     = 'event_collector'
            opts["DEBUG_PREFIX"] = "EventCollector"
            opts["MEM_CACHE_PREFIX"] = "ec_"
        else:
            opts["PROC_DIR"]     = 'cb'
            opts["DEBUG_PREFIX"] = "CbSensor"
            opts["MEM_CACHE_PREFIX"] = "cbr_"

        opts["MODULE_VERSION_SUFFIX"] = module_version_suffix
        opts["MODULE_NAME"]    = self.options.module_name
        opts["VERSION_STRING"] = "PACKAGE_VERSION"
        opts["BUILD_DATE"]     = datetime.now().strftime('%b %d, %Y - %H:%M:%S %p')
        opts["API_VERSION"]    = "KERNEL_API_VERSION"

        self.KernelHelper.BuildKernels(self,
                                       opts,
                                       source_dir,
                                       build_dir,
                                       distro,
                                       message)


    def package(self):
        self.copy("*.h", dst="include" + os.path.sep + "k_events_module", src="include", keep_path=True)
        self.copy("*.ko.*", excludes="*.debug", dst="modules", src="kernel-builds", keep_path=True)
        self.copy("*.symvers.*", dst="symvers", src="kernel-builds", keep_path=True)
        self.copy("*.debug", dst="debug", src="kernel-builds", keep_path=True)

    def package_info(self):
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.bindirs     = ["modules"]
        self.cpp_info.resdirs     = ["symvers"]


        self.user_info.module_version_suffix = self.getModuleVersionSuffix()
        self.user_info.module_name = self.options.module_name + "_" + self.getModuleVersionSuffix()
