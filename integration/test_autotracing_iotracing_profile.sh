#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# Exercise the existing disk trigger, both real tools, Toolstream handoff and one
# local event containing the unchanged original report and the additional SVG.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"
require_commands python3 jq ss
require_readable /sys/kernel/btf/vmlinux
readonly IO_TRIGGER_FIXTURE="${HUATUO_BAMAI_TEST_TMPDIR}/disk-fixture"
readonly IO_TRIGGER_EVENT="${HUATUO_BAMAI_TEST_TMPDIR}/events/iotracing"
io_trigger_writer=""
io_trigger_major=""
io_trigger_minor=""
io_trigger_device=""
while read -r major minor device rest; do
	case ${device} in loop* | ram* | zram* | fd* | md*) continue ;; esac
	[[ -e /sys/dev/block/${major}:${minor} && ! -e /sys/dev/block/${major}:${minor}/partition ]] || continue
	io_trigger_major=${major}
	io_trigger_minor=${minor}
	io_trigger_device=${device}
	break
done < /proc/diskstats
[[ -n ${io_trigger_device} ]] || skip "no whole block device for the diskstats trigger fixture"
cleanup_io_trigger() {
	huatuo_bamai_stop "${HUATUO_BAMAI_TEST_TMPDIR}" || true
	stop_and_wait_by_pid "${io_trigger_writer}" 5 || true
}
trap cleanup_io_trigger EXIT
mkdir -p "${IO_TRIGGER_FIXTURE}/proc" "${IO_TRIGGER_FIXTURE}/sys"
ln -s /sys/dev "${IO_TRIGGER_FIXTURE}/sys/dev"
python3 "${ROOT_DIR}/integration/testdata/test_iotracing_diskstats.py" "${IO_TRIGGER_FIXTURE}/proc/diskstats" \
	"${io_trigger_major}" "${io_trigger_minor}" "${io_trigger_device}" &
io_trigger_writer=$!
wait_until 5 0.1 test -s "${IO_TRIGGER_FIXTURE}/proc/diskstats" || fatal "diskstats producer did not start"

io_profile_event_ready() {
	[[ -s ${IO_TRIGGER_EVENT} ]] || return 1
	jq -e '.tracer_name == "iotracing" and .tracer_type == "autotracing"
		and (.tracer_data | has("process_file_io_stats") and has("io_schedule_timeout_stacks"))
		and .tracer_data.reason_snapshot.device != null
		and .tracer_data.io_profile_error == null
		and .tracer_data.io_profile.duration_ns == 2000000000
		and (.tracer_data.io_profile.groups | length > 0)
		and (.tracer_data.io_profile.flamegraph_svg | contains("<svg") and contains("WRITE / host"))' \
		"${IO_TRIGGER_EVENT}" > /dev/null
}

integration_huatuo_bamai_start write_config_bamai_iotracing_profile \
	--region integration --procfs-prefix "${IO_TRIGGER_FIXTURE}" --disable-kubelet --log-debug
wait_until 50 1 io_profile_event_ready || fatal "original IO report or supplemental graph missing: ${IO_TRIGGER_EVENT}"
assert_log_has_no_failure "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "IO trigger"
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp "${IO_TRIGGER_EVENT}" "${HUATUO_IO_ARTIFACT_DIR}/triggered-io-profile.json"
fi
