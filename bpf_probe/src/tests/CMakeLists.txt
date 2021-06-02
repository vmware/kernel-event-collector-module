

cb_run_tests(NAME          RunAllTests
             TARGETS       RunAllTests.cpp
                           BpfApi_tests.cpp
             LIBRARIES     CONAN_PKG::CppUTest
                           bpf-probe
             DEPENDENCIES  check_probe
             UNIT)
