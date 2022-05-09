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

RUN git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
WORKDIR linux/tools/bpf/bpftool
RUN make install

RUN mkdir /libbpf_sensor
ADD src/sensor.bpf.c /libbpf_sensor
ADD src/libbpf_sensor.c /libbpf_sensor
ADD src/Makefile /libbpf_sensor
ADD src/build.sh /libbpf_sensor

WORKDIR /libbpf_sensor

CMD ["./build.sh"]
