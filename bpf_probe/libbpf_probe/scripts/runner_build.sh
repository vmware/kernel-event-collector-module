#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'please provide a docker repo as an argument'
    exit 1
fi
echo 'Using repo' $1
REP=$1
BUILD_IMAGE=$REP/libbpf_builder
RUN_IMAGE=$REP/libbpf_test
TAG=sensor

# this will only work on hosts with BPF enabled kernel (not mac docker host VM)
echo "--- running remote build container ---"
kubectl -n default run libbpf-build --image-pull-policy Always --image $BUILD_IMAGE:$TAG
while true
do
   kubectl -n default exec libbpf-build -- test -f /libbpf_sensor/libbpf_sensor
   if [[ $? -eq 0 ]]; then
     break
   fi
   echo "--- waiting for remote build to finish ---"
   sleep 5
done

echo "--- remote build finished ---"

echo "--- copying exec file ---"
while true
do
	kubectl cp default/libbpf-build:/libbpf_sensor/libbpf_sensor ./bin/libbpf_sensor
	if [[ $? -eq 0 ]]; then
	  break
	fi
	echo "--- remote copy FAILED ---"
	sleep 5
	echo "--- retry ---"
done

chmod +x ./bin/libbpf_sensor

echo "--- building run container ---"
docker build . -f run.Dockerfile -t $RUN_IMAGE:$TAG
echo "--- pushing run container ---"
docker push $RUN_IMAGE:$TAG
echo "--- removing remote build container ---"
kubectl -n default delete pod libbpf-build &
sleep 1
echo "--- compleated ---"


