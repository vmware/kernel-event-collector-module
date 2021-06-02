# Dynamic Security Linux Kernel Module Tests

## Purpose
The purpose of these tests is to exercise the functionality of the Dynamic Security Module.  These tests assume that you have built and loaded the dyn_sec_generic security module.


## MockDaemon
To build the mock daemon issue the command:
gcc -std=c++11 main.cpp -o mockdaemon

To run the mock daemon, simply execute the mockdaemon from the command line.  It will connect to and listen to requests from the dyn_sec_generic kernel module.  

When the MockDaemon isn't running the dyn_sec_generic kernel module operates in 'bypass' mode which is basically returning 0 from the  bprm_set_cred LSM hook.

## Performance - Exec
To build the performance/exec project, issue the command
gcc main.cpp -o testexec

The tests issues 10,000 execs of echo.  This test is used to determine average overhead per exec transaction of the dyn_sec_generic kernel module.  When the module is loaded and the MockDaemon is listening, this test exercises the hook-to-usermode-with-response transaction of the dyn_sec_generic kernel module.  To get useful output, use the following command:

./testexec | grep batch

You will see output as follows:

batch execs took about 4.69405 seconds

This means that the average exec took about .469 ms.  

You can run this test without the kernel module present to get a baseline and then use the difference to compute a per-transactional overhead.  For example, if without the kernel module the result 2as 4.1930 seconds, then the result would be about 0.5 sec overhead for 10,000 transactions or about 50 microseconds per transaction.


