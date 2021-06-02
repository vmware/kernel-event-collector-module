# Dynamic Security Linux Kernel Module

## Purpose
The Dynamic Security Linux Kernel Module (dyn-sec) implements a dynamically loadable module that can hook LSM security callbacks and provide decision points to a connected user-space process.  This is similar to seccomps user-space decision points.  The main advantage to using dyn-sec over seccomps is that it backports the ability to make security decision in user space and does not require modifying the attributes of a target process.  Thus advanced dynamic policy decisions can be made against any operation of any process.


## Branding
Because it is possible for multiple dyn-sec modules to be loaded, it can be branded with a name (the brand).  This allows for multiple dyn-sec modules to co-exist and allows multiple user-space processes to be talking to their own dyn-sec module.  As a result, the brand affects the following:
1. The module name: dyn_sec_<brand>
2. The device node name: /dev/dynsec_<brand>
3. Kernel output to syslog

If no brand is specified, the build will default to "generic" as the brand name.

## Building
Building requires that you have at least the default kernel development packages installed for your platform.  You can install others and build for those specific versions of the kernel.  To build, from the source directory simply issue 'make' on the command line.  To build for a specific version of the kernel, set the KVERSION environment variable before calling make.  You must have the kernel development modules for that version of the kernel installed.
