#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# Exercise the existing disk trigger and verify one report includes the
# original diagnostics and the IO flamegraph.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"
source "${ROOT_DIR}/integration/lib_iotracing.sh"
require_commands python3 jq ss
require_readable /sys/kernel/btf/vmlinux
readonly IO_TRIGGER_FIXTURE="${HUATUO_BAMAI_TEST_TMPDIR}/disk-fixture"
readonly IO_TRIGGER_EVENT="${HUATUO_BAMAI_TEST_TMPDIR}/events/iotracing"
io_trigger_device=()
io_trigger_writer=""
io_workload_pid=""

cleanup_io_trigger() {
	local status=$?
	huatuo_bamai_stop "${HUATUO_BAMAI_TEST_TMPDIR}" || status=1
	stop_iotracing_profile_fixture "${io_trigger_writer}" || status=1
	stop_iotracing_profile_fixture "${io_workload_pid}" || status=1
	cleanup_iotracing_profile_data || status=1
	exit "${status}"
}
trap cleanup_io_trigger EXIT

prepare_iotracing_profile_trigger "${IO_TRIGGER_FIXTURE}"
prepare_iotracing_profile_data
readonly IO_TRIGGER_WORKLOAD="${iotracing_profile_data}/trigger-write"
python3 -u "${ROOT_DIR}/integration/testdata/test_io_profile.py" "${IO_TRIGGER_WORKLOAD}" stream &
io_workload_pid=$!
wait_until 5 0.1 test -s "${IO_TRIGGER_WORKLOAD}" || fatal "fixture process did not write to its test file"

integration_huatuo_bamai_start write_config_bamai_iotracing_profile \
	--region integration --procfs-prefix "${IO_TRIGGER_FIXTURE}" --disable-kubelet --log-debug
start_iotracing_profile_trigger "${IO_TRIGGER_FIXTURE}"
wait_until 50 1 assert_iotracing_profile_svg "${IO_TRIGGER_EVENT}" host "${io_workload_pid}" \
	|| fatal "IO event lacks the original report or fixture write stack: ${IO_TRIGGER_EVENT}"
assert_log_has_no_failure "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "IO trigger"
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp "${IO_TRIGGER_EVENT}" "${HUATUO_IO_ARTIFACT_DIR}/triggered-io-profile.json"
fi
