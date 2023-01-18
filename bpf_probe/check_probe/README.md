# Check Probe
check_probe is a program that helps testing the BPF program of the event collector

# Build
In order to build the BPF program and check probe run:
```
./build-util/build.py build bpf_probe/
```
The executable will be located at:
* x86
```
workspace/bpf_probe/build/gcc73-relwithdebinfo.0/bin/check_probe
```
* ARM
```
workspace/bpf_probe/build/gcc-arm-8_2-relwithdebinfo.1/bin/check_probe
```

# Run
* Use libbpf
```
sudo ./check_probe -L -vvv -r
```
* Use BCC
```
sudo ./check_probe -B -vvv -r
```

# Docker
* x86
```
docker build -f bpf_probe/check_probe/Dockerfile -t octarinesec/cndr:check-probe-$USER . --platform linux/amd64 &&  docker push octarinesec/cndr:check-probe-$USER
```
* ARM
```
docker build -f bpf_probe/check_probe/Dockerfile.arm -t octarinesec/cndr:check-probe-$USER . --platform linux/aarch64 && docker push octarinesec/cndr:check-probe-$USER
```
