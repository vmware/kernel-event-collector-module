#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'please provide a docker repo as an argument'
    exit 1
fi
echo 'Using repo' $1
REP=$1
BUILD_IMAGE=$REP/libbpf_builder
TAG=sensor

docker build . -f build.Dockerfile -t $BUILD_IMAGE:$TAG
docker push $BUILD_IMAGE:$TAG
