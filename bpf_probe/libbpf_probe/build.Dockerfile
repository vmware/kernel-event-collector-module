FROM ubuntu:21.10

ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get -y install golang

RUN apt-get update && apt-get -y install arping netperf iperf python3.9 curl python \
    bison build-essential cmake flex git libedit-dev pkg-config librdkafka-dev \
    libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev tar

RUN apt-get update && apt-get install -y libbpf-dev
RUN apt-get update && apt-get install -y libbpf0

RUN apt-get update && apt-get install -y build-essential linux-tools-common clang

# BPFTool
RUN git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
WORKDIR linux/tools/bpf/bpftool
RUN make install

# ELFUtils - static
WORKDIR /
RUN apt-get update && apt-get install -y autoconf autopoint gawk
RUN git clone git://sourceware.org/git/elfutils.git
WORKDIR /elfutils
RUN autoreconf -i -f
RUN ./configure --enable-maintainer-mode --disable-libdebuginfod --disable-debuginfod --enable-static
RUN make

# libz - static
WORKDIR /
RUN git clone https://github.com/madler/zlib.git
WORKDIR zlib
RUN ./configure --prefix=/usr
RUN make

RUN mkdir /libbpf_sensor

RUN cp /elfutils/libelf/libelf.a /libbpf_sensor
RUN cp /zlib/libz.a /libbpf_sensor
COPY src /libbpf_sensor

WORKDIR /libbpf_sensor

CMD ["sh", "-c", "make ; sleep infinity"]
