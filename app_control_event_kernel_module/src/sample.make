# SPDX-License-Identifier: GPL-2.0
# Copyright 2022 VMware, Inc. All rights reserved.
#
# Sample Vanilla kmod Makefile for the appc kmod
#
# Steps:
#  - Copy app_control_event_kernel_module project tree to builddir
#  - Copy sample.make ontop of Makefile
#  - Run It:
#    make -C <builddir>/app_control_event_kernel_module/src
#

ifeq ($(KDIR),)
BASEPATH ?=/lib/modules
KVERREL ?=$(shell uname -r)
KDIR :=$(PATHPREFIX)/$(BASEPATH)/$(KVERREL)/build
endif

ifeq ($(MODULE_NAME),)
BASENAME ?= cb_appc_events
MAJOR ?= 3
MINOR ?= 0
PATCH ?= 17000

MODULE_NAME := $(BASENAME)_$(MAJOR)_$(MINOR)_$(PATCH)
VERSION_STRING := $(MAJOR).$(MINOR).$(PATCH)
endif

# Simulate the version.h generated file
ifeq ($(VERSION_H),)
EXTRA_INCLUDES = -D'CB_APP_MODULE_NAME="$(MODULE_NAME)"'
EXTRA_INCLUDES += -D'MODULE_NAME=$(MODULE_NAME)'
EXTRA_INCLUDES += -D'CB_APP_MODULE_DEVICE="/dev/$(MODULE_NAME)"'
EXTRA_INCLUDES += -D'CB_APP_VERSION_STRING="/dev/$(VERSION_STRING)"'
else
EXTRA_INCLUDES = -include $(VERSION_H)
endif


ifeq ($(MOD_PATH),)
MOD_PATH:=$(shell pwd)
endif

obj-m := $(MODULE_NAME).o
ccflags-y := -Wall -Wformat -Werror -g -I$(src)/../include $(EXTRA_INCLUDES)

$(MODULE_NAME)-objs := \
	dynsec.o \
	preaction_hooks.o \
	hooks.o \
	tracepoints.o \
	inode_cache.o \
	task_cache.o \
	lsm.o \
	symbols.o \
	factory.o \
	stall_reqs.o \
	stall_tbl.o \
	protect.o \
	path_utils.o \
	task_utils.o \
	wait.o \


.PHONY: clean

all:
	make -C $(KDIR) M=$(MOD_PATH) -j

clean:
	make -C $(KDIR) M=$(MOD_PATH) clean

