#!/bin/sh

mount -t debugfs none /sys/kernel/debug
/check_probe -L -vvv -r
