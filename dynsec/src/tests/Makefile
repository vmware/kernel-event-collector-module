# Copyright 2021 VMware, Inc.
# SPDX-License-Identifier: GPL-2.0

INCLUDES += -I. -I../../include
CFLAGS += -g -O2 -fpic -Wall

DYNSEC_H := ../../include/dynsec.h

.PHONY : all clean test

# Try to find python3 somewhere
ifeq ($(PYTHON),)
PYTHON := $(shell which python3.6)
endif
ifeq ($(PYTHON),)
PYTHON := $(shell which python3)
endif

# Objects
client.o: client.c client.h $(DYNSEC_H)
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
print.o: print.c print.h $(DYNSEC_H)
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
exp.o: exp.c exp.h $(DYNSEC_H)
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
test_utils.o: test_utils.c test_utils.h $(DYNSEC_H) client.h
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
rename.o: rename.c rename.h $(DYNSEC_H) test_utils.h
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<


# Shared Libraries
libdynsecclient.so: client.o print.o
	$(CC) -shared $(CFLAGS) $(INCLUDES) -o $@ $^


# Executables
sizeof: sizeof.c $(DYNSEC_H)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

client_test: client_test.c client.o print.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

self_tests: tests.c test_utils.o rename.o exp.o print.o client.o
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

# Might as well output some sizes of objects
dynsec.pahole: client_test $(DYNSEC_H)
ifneq ($(shell which pahole),)
	@echo "*** Outputting struct sizes via pahole ***"
	@pahole --prefix_filter=dynsec client_test > $@
else
	@>$@
endif

# Cheaply compare sizes of structs
sizeof.c.log: $(DYNSEC_H) sizeof
	./sizeof > $@

ifeq ($(PYTHON),)
sizeof.py.log: $(DYNSEC_H) sizeof.py dynsec.py
	@>$@
sizeof.diff: sizeof.c.log
	@>$@
else
sizeof.py.log: $(DYNSEC_H) sizeof.py dynsec.py
	$(PYTHON) $(CURDIR)/sizeof.py > $@

sizeof.diff: sizeof.py.log sizeof.c.log
	diff sizeof.c.log sizeof.py.log | tee $@
endif

test: sizeof.diff dynsec.pahole

clean:
	rm -f dynsec.pahole sizeof.diff sizeof.*.log \
		sizeof client_test self_tests \
		libdynsecclient.so \
		test_utils.o rename.o exp.o print.o client.o \


# Real Targets
all: dynsec.pahole sizeof.diff \
	sizeof client_test self_tests \
	libdynsecclient.so \

