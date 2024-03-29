# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

from conans import python_requires, CMake, tools, AutoToolsBuildEnvironment
import os
from datetime import datetime

from conan_util.CbConanFile import CbConanFile

class SHORT_NAME(CbConanFile):
    name     = "SHORT_NAME"
    version  = "PACKAGE_VERSION"
    settings = "os", "compiler", "build_type", "arch"
    generators = "cmake"
    requires = (
        "LLVM_VERSION",
        "ELFUTILS_VERSION",
        "BCC_VERSION",
        "BOOST_VERSION",
        "BPFTOOL_VERSION",
        "LIBBPF_VERSION",
    )

    build_requires = "CPPUTEST_VERSION"
    default_options = (
        "elfutils:shared=False",
        "llvm:shared=False",
        "bcc:shared=False",
        "bpftool:shared=False",
        "libbpf:shared=False",
    )

    def build(self):
        cmake = CMake(self)
        env_build = AutoToolsBuildEnvironment(self)

        cmake.verbose = True
        with tools.environment_append(env_build.vars):
            if os.getenv("FAST_BUILD") != "1":
                cmake.configure(source_dir=self.source_folder + os.path.sep + "src")
                with open("%s/env" % (self.build_folder), 'w') as fh:
                    for key in os.environ:
                        fh.write(key + "=" + os.environ[key] + "\n")

            cmake.build()

    # Would be better as a cmake.install call
    def package(self):
        self.copy("*.h", dst="include/bpf_probe", src="include", keep_path=True)
        self.copy("*.a", dst="lib", keep_path=False)
        self.copy("check_probe", dst="bin", src="bin")
        self.copy("sensor.bpf.o*", dst="lib")
        self.copy("sensor.skel.h", dst="include")

    def package_info(self):
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs     = ['lib']
        self.cpp_info.libs        = ['bpf-probe']