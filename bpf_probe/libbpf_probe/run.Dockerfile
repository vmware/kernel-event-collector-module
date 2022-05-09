FROM ubuntu:21.10

RUN apt-get update && apt-get -y install libelf1

ADD bin/libbpf_sensor /
RUN chmod +x /libbpf_sensor

CMD ["/libbpf_sensor"]
