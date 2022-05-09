#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'please provide a docker repo as an argument'
    exit 1
fi
REP=$1
kubectl -n default delete pod libbpf-run-sensor &
./scripts/builder_build.sh $REP
./scripts/runner_build.sh $REP
./scripts/run.sh $REP
