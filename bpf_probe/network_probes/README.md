# VMWare Carbon Black network eBPF Probe code
This directory includes the eBPF probe C files used in the VMWare Carbon Black network monitor solution.
It is currently used as bare C files - compiled at load time and loaded to the kernel using the [iovisor/gobpf](https://github.com/iovisor/gobpf) library.
Later this would be compiled with the rest of the source code into the Linux Sensor.
This module is intended and tested for kernel versions >= 4.8

