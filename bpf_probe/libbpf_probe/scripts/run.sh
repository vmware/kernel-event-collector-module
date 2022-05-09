#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'please provide a docker repo as an argument'
    exit 1
fi
echo 'Using repo' $1
REP=$1
RUN_IMAGE=$REP/libbpf_test
TAG=sensor

kubectl -n default run libbpf-run-sensor --image-pull-policy Always --privileged --image $RUN_IMAGE:$TAG
