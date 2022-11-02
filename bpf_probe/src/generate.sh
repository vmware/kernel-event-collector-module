#!/bin/bash
# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0

SOURCE_PROG=$1
OUT_FILE=$2
SHARED_SOURCE_PROG=$3
SHARED_SOURCE_RAW_HDR=$4

if [[ x"${SOURCE_PROG}" == x ]]
then
	exit 1
fi

if [[ ! -f "${SOURCE_PROG}" ]]
then
	echo "No source program: ${SOURCE_PROG}" 1>&2
	exit 1
fi

bcc_prog=$(cat ${SOURCE_PROG})
printf '#include "BpfProgram.h"\n' "${bcc_prog}" > "${OUT_FILE}"
printf 'const std::string cb_endpoint::bpf_probe::BpfProgram::DEFAULT_PROGRAM = R"(\n%s\n)";\n' "${bcc_prog}" >> "${OUT_FILE}"

# Generate a C++ header that just contains the R("...") string
# of the sensor source.
# This is to allow the string be defined much more arbitrarily.
if [[ x"${SHARED_SOURCE_PROG}" != x ]]
then
	if [[ x"${SHARED_SOURCE_RAW_HDR}" == x ]]
	then
		SHARED_SOURCE_RAW_HDR=sensor.bpf.h
	fi

	{
		printf 'R"(\n'
		cat ${SHARED_SOURCE_PROG}
		printf '\n)"'
	} > ${SHARED_SOURCE_RAW_HDR}
fi
