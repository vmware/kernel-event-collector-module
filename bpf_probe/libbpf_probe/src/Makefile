OUTPUT = ./output

BTFFILE = /sys/kernel/btf/vmlinux
BPFTOOL = $(shell which bpftool || /bin/false)
GIT = $(shell which git || /bin/false)
VMLINUXH = $(OUTPUT)/vmlinux.h

LIBBPF_SRC = $(abspath ./libbpf/src)
LIBBPF_OBJ = $(abspath ./$(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR = $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR = $(abspath ./$(OUTPUT))

CC = gcc
CLANG = clang

CFLAGS = -g -O2 -Wall -fpie -D__TARGET_ARCH_x86
LDFLAGS =

.PHONY: sensor.bpf.c

all: libbpf_sensor

# vmlinux header file

.PHONY: vmlinuxh
vmlinuxh: $(VMLINUXH)

$(VMLINUXH): $(OUTPUT)
	@if [ ! -f $(BTFFILE) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
	fi
	@if [ ! -f $(VMLINUXH) ]; then \
		if [ ! $(BPFTOOL) ]; then \
			echo "ERROR: could not find bpftool"; \
			exit 1; \
		fi; \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	fi

# static libbpf generation

.PHONY: libbpf-static
libbpf-static: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	CC="$(CC)" CFLAGS="$(CFLAGS)" LD_FLAGS="$(LDFLAGS)" \
	   $(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

$(LIBBPF_SRC):
ifeq ($(wildcard $@), )
	echo "INFO: cloning 'libbpf'"
	$(GIT) clone https://github.com/libbpf/libbpf.git
endif

## bpf dependency

sensor.bpf.o: sensor.bpf.c | vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -I$(OUTPUT) -c $< -o $@


.PHONY: libbpf_sensor.c

sensor.skel.h: sensor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

.PHONY: libbpf_sensor

# static here means libbpf statically compiled not full static binaries

libbpf_sensor: libbpf-static | sensor.skel.h
	$(CLANG) -lelf -lz -I$(OUTPUT) libbpf_sensor.c -o $@ $(LIBBPF_OBJ)

# output

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/libbpf:
	mkdir -p $(OUTPUT)/libbpf

clean:
	rm -f *.o *-static libbpf_sensor
