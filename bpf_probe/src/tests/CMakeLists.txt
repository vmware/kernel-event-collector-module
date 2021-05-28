cb_configure_flags()

cb_run_tests(NAME        RunAllTests
             TARGETS     RunAllTests.cpp
                         BpfApi_Mock.cpp
             LIBRARIES   CONAN_PKG::CppUTest
                         CONAN_PKG::Logger
             DEPENDENCIES event_collector
             UNIT)
