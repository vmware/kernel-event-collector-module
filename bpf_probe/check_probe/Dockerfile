FROM ubuntu:20.04

ADD ./workspace/bpf_probe/build/gcc73-relwithdebinfo.0/bin/check_probe /
ADD ./bpf_probe/check_probe/run_check_probe.sh /
CMD ["/run_check_probe.sh"]