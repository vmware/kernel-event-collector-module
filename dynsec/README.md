# Dynamic Security Linux Kernel Module

## Purpose
The Dynamic Security Linux Kernel Module (dynsec) implements a dynamically loadable module that can hook LSM security callbacks and provide decision points to a connected user-space process.  This is similar to seccomps user-space decision points.  The main advantage to using dynsec over seccomps is that it backports the ability to make security decision in user space and does not require modifying the attributes of a target process.  Thus advanced dynamic policy decisions can be made against any operation of any process.

