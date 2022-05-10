FROM ubuntu:21.10

# on a non-mac setting - we can do this as a second stage in the build container
COPY bin/libbpf_sensor /
CMD ["/libbpf_sensor"]