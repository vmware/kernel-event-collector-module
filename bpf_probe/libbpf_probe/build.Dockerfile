FROM ubuntu:20.04

#ARG UNAME_R='$(uname -r)'
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#RUN apt-get update && apt-get -y install golang

RUN apt-get update && apt-get -y install arping netperf iperf python3.9 curl  \
    bison build-essential cmake flex git libedit-dev pkg-config librdkafka-dev \
    libllvm12 llvm-12-dev libclang-12-dev  zlib1g-dev libelf-dev libfl-dev tar

#RUN apt-get update && apt-get install -y libbpf-dev
#RUN apt-get update && apt-get install -y libbpf0

RUN apt-get update && apt-get install -y build-essential linux-tools-common clang

# BPFTool
RUN apt-get install -y linux-tools-$(uname -r)

# ELFUtils - static
WORKDIR /
RUN apt-get update && apt-get install -y autoconf autopoint gawk
RUN git clone git://sourceware.org/git/elfutils.git
WORKDIR /elfutils
RUN autoreconf -i -f
RUN ./configure --enable-maintainer-mode --disable-libdebuginfod --disable-debuginfod --enable-static
RUN make
#RUN apt-get install -y elfutils zlib1g-dev

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
# COPY libbpf_sensor /project/bin
# COPY sensor.skel.h /project/bin
# COPY sensor.bpf.o /project/bin

CMD ["sh", "-c", "make; cp libbpf_sensor /project/bin; cp sensor.bpf.o /project/bin/"]
