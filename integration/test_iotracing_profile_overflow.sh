#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# The test-only BPF object limits admission to the fixture PID. The real
# filesystem probes and the same aggregate and overflow code count its writes.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_profiler.sh"
source "${ROOT_DIR}/integration/lib_iotracing.sh"

readonly IO_OVERFLOW_CAPACITY=4096
readonly IO_OVERFLOW_KEYS=4200
require_commands python3 jq clang findmnt timeout
bpf_tool_setup iotracing iotracing iotracing-overflow
trap 'cleanup_running_jobs; cleanup_iotracing_profile_data' EXIT
prepare_iotracing_profile_data

start_piped_process "${TOOL_WORK_DIR}/workload" python3 -u \
	"${ROOT_DIR}/integration/testdata/test_io_profile.py" "${iotracing_profile_data}/overflow.data"
workload_pid=${PROCESS_PID}
input_fd=${PROCESS_INPUT_FD}
output_fd=${PROCESS_OUTPUT_FD}
printf '%s\n' "${workload_pid}" > "${TOOL_WORK_DIR}/target.pid"
assert_process_message "${output_fd}" "${TOOL_WORK_DIR}/workload.log" io-workload-ready

object="${TOOL_WORK_DIR}/iotracing-overflow.o"
compile_bpf_fixture "${ROOT_DIR}/integration/testdata/test_iotracing_profile_overflow.bpf.c" \
	"${object}" "-DIO_FIXTURE_TGID=${workload_pid}"
timeout --kill-after=2 15 "${TOOL_BIN}" --bpf-path "${object}" --duration 2 --output json \
	> "${TOOL_OUT}" 2> "${TOOL_ERR}" &
profiler_pid=$!
wait_until 10 0.1 grep -Fq 'iotracing: capture ready' "${TOOL_ERR}" \
	|| fatal "IO overflow capture did not become ready: $(< "${TOOL_ERR}")"

printf 'overflow %s\n' "${IO_OVERFLOW_KEYS}" 1>&"${input_fd}"
IFS= read -r -t 10 -u "${output_fd}" workload || fatal "IO overflow workload did not finish"
printf '%s\n' "${workload}" > "${TOOL_WORK_DIR}/workload.json"
wait "${profiler_pid}" || fatal "IO overflow capture failed: $(< "${TOOL_ERR}")"
jq -e '.io_profile' "${TOOL_OUT}" > "${TOOL_WORK_DIR}/profile.json" \
	|| fatal "IO overflow capture did not produce a profile: $(< "${TOOL_ERR}")"
assert_iotracing_profile_overflow "${TOOL_WORK_DIR}" "${IO_OVERFLOW_CAPACITY}" true

printf 'stop\n' 1>&"${input_fd}"
exec {input_fd}>&-
wait "${workload_pid}" || fatal "IO overflow workload failed"
exec {output_fd}<&-
