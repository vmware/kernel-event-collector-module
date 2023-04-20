# Check Probe
`check_probe` is a program that helps testing the BPF program of the event collector

## Build
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

## Run
* Use libbpf
```
sudo ./check_probe -L -vvv -r 2>&1
```
* Use BCC
```
sudo ./check_probe -B -r 2>&1
```

# Docker
## Build & Push
* x86
```
docker build -f bpf_probe/check_probe/Dockerfile -t octarinesec/cndr:check-probe-$USER . --platform linux/amd64 && docker push octarinesec/cndr:check-probe-$USER
```
* ARM
```
docker build -f bpf_probe/check_probe/Dockerfile.arm -t octarinesec/cndr:check-probe-arm-$USER . --platform linux/aarch64 && docker push octarinesec/cndr:check-probe-arm-$USER
```
## Run
* x86
```
docker run -it --privileged -v /boot:/boot octarinesec/cndr:check-probe-$USER
```
* ARM
```
docker run -it --privileged -v /boot:/boot octarinesec/cndr:check-probe-arm-$USER
```

# Kubernetes
## Run DaemonSet
A daemonset is a method of kubernetes deployment that would deploy a single pod on each node.
Thus deploying the following daemonset would deploy a single instance of `check_probe` on each node.
```
# Add you username to the image tag, if your'e following this convention:
sed -i "s/\:check-probe/\:check_probe-$USER/" bpf_probe/check_probe/daemonset.yaml
# Apply the daemonset to the cluster:
kubectl apply -f bpf_probe/check_probe/daemonset.yaml
```
