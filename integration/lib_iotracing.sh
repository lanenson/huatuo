#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
#
# Authors:
# Tonghao Zhang <tonghao@bamaicloud.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify the iotracing CLI end-to-end: a normal run emits well-formed
# JSON with the expected top-level schema and the dd workload we drive
# shows up under per-file attribution. A private filesystem keeps unrelated
# host IO out of the bounded capture.
# Path-validation rules are covered by internal/bpf TestValidateName.

readonly IOTRACING_STACK_MAP_WARNING='^IO profile stack map rejected [1-9][0-9]* samples due to hash collisions or unavailable entries, leaving affected IO under unknown user stacks$'

iotracing_profile_data=""
iotracing_profile_uses_test_disk=false

# The runner directory can be tmpfs even when the built tools reside on disk.
prepare_iotracing_profile_data() {
	local base filesystem
	require_commands findmnt
	for base in "${HUATUO_BAMAI_TEST_TMPDIR}" "${ROOT_DIR}/_output"; do
		filesystem=$(findmnt -n -o FSTYPE --target "${base}")
		case ${filesystem} in
		ext4 | xfs)
			iotracing_profile_data=$(mktemp -d "${base}/iotracing-data.XXXXXX")
			log_info "IO profile workload filesystem: ${filesystem} (${iotracing_profile_data})"
			return
			;;
		esac
	done
	source "${ROOT_DIR}/integration/lib_io.sh"
	iotracing_profile_uses_test_disk=true
	io_test_prepare_storage ext4
	iotracing_profile_data=$(mktemp -d "${io_test_storage_dir}/iotracing-data.XXXXXX")
}

cleanup_iotracing_profile_data() {
	local status=0
	if [[ -n ${iotracing_profile_data:-} ]]; then
		rm -rf -- "${iotracing_profile_data}" || status=1
	fi
	if [[ ${iotracing_profile_uses_test_disk} == true ]]; then
		io_test_cleanup_disks || status=1
	fi
	return "${status}"
}

assert_iotracing_profile_overflow() {
	local directory=$1 capacity=$2 exact=$3
	# The host-wide capture has a lower bound. The PID-scoped BPF fixture
	# admits only the known writer, so its normal and overflow rows must add up.
	jq -e --arg pid "$(< "${directory}/target.pid")" --argjson capacity "${capacity}" \
		--argjson exact "${exact}" --slurpfile workload "${directory}/workload.json" '
	(.profile as $p |
		[$p.sample[]? | . as $sample |
			([$sample.label[]? | {key:$p.string_table[.key],value:$p.string_table[.str]}] | from_entries) as $labels |
			{labels:$labels, bytes:.value[0], count:.value[1], duration:.value[2], stack:.location_id}]) as $rows |
	($rows | map(select(.labels | has("pid")))) as $normal |
	[$normal[] | select(.labels.pid == $pid)] as $target |
	[$rows[] | select((.labels | has("pid") | not)
		and .labels.direction == "write" and .labels.result == "success")] as $overflow |
	[$overflow[] | select(.bytes > 0)] as $positive |
	[$overflow[] | select(.bytes == 0)] as $zero |
	($target | map(.count) | add) as $count |
	($target | map(.bytes) | add) as $bytes |
	((.dropped_samples // {}) | length == 0)
	and ($normal | length == $capacity)
	and ($target | length > 0 and all(.[]; .count == 1 and .duration > 0))
	and all($overflow[]; .labels.attribution == "other" and (.stack | length == 0))
	and ($positive | length == 1)
	and ($positive[0].count >= $workload[0].count - $count and $positive[0].duration > 0)
	and $positive[0].bytes >= $workload[0].bytes - $bytes
	and ($workload[0].zero_bytes == 0)
	and ($zero | length == 1 and .[0].count >= 1 and .[0].duration > 0)
	and (if $exact then
		all($rows[]; .labels.direction == "write" and .labels.result == "success")
		and ($workload[0].bytes == 19 * $workload[0].count)
		and ($target | length == $capacity and all(.[]; .bytes == 19))
		and ($overflow | length == 2)
		and ($positive[0].count == $workload[0].count - $count)
		and ($positive[0].bytes == $workload[0].bytes - $bytes)
		and ($zero[0].count == 1)
	else true end)
	' "${directory}/profile.json" > /dev/null || fatal "overflow lost measurements or gained an incorrect stack: ${directory}"
}

stop_iotracing_profile_fixture() {
	local pid=$1 status=0
	stop_and_wait_by_pid "${pid}" 5 || status=$?
	if ((status != 0 && status != 143)); then
		log_error "IO fixture PID ${pid} stopped with status ${status}"
		return 1
	fi
}

prepare_iotracing_profile_trigger() {
	local root=$1 major minor device rest
	while read -r major minor device rest; do
		case ${device} in loop* | ram* | zram* | fd* | md*) continue ;; esac
		[[ -e /sys/dev/block/${major}:${minor} && ! -e /sys/dev/block/${major}:${minor}/partition ]] || continue
		io_trigger_device=("${major}" "${minor}" "${device}")
		break
	done < /proc/diskstats
	(("${#io_trigger_device[@]}")) || skip "no whole block device for the diskstats trigger fixture"

	mkdir -p "${root}/proc" "${root}/sys"
	ln -s /sys/dev "${root}/sys/dev"
	printf '%s %s %s 0 0 0 0 0 0 0 0 0 0 0\n' "${io_trigger_device[@]}" > "${root}/proc/diskstats"
}

start_iotracing_profile_trigger() {
	local root=$1
	python3 "${ROOT_DIR}/integration/testdata/test_iotracing_diskstats.py" "${root}/proc/diskstats" \
		"${io_trigger_device[@]}" &
	io_trigger_writer=$!
}

# Each expected pair is a scope (host or container ID) and the writer's host PID.
assert_iotracing_profile_svg() {
	local event=$1
	shift
	[[ -s ${event} ]] || return 1
	jq -ser --arg stack_warning "${IOTRACING_STACK_MAP_WARNING}" '
	last | select(.tracer_name == "iotracing" and .tracer_type == "autotracing"
		and (.tracer_data | has("process_file_io_stats") and has("io_schedule_timeout_stacks"))
		and .tracer_data.reason_snapshot.device != null
		and (.tracer_data.io_profile_error |
			if type == "string" then test($stack_warning) else . == null end)
		and .tracer_data.io_profile.duration_ns == 1000000000
		and (.tracer_data.io_profile.groups | length > 0)) | .tracer_data.io_profile.flamegraph_svg
	' "${event}" | python3 -c '
import sys
import xml.etree.ElementTree as ET

host_panel = "WRITE / host"
expected = {}
for scope, pid in zip(sys.argv[1::2], sys.argv[2::2]):
    panel = host_panel if scope == "host" else "WRITE / container / " + scope
    expected[panel] = "pid=\"{}\"".format(pid)
container_writers = {pid for panel, pid in expected.items() if panel != host_panel}
found = set()
namespace = "{http://www.w3.org/2000/svg}"
panel = None
target_y = None
try:
    svg = ET.parse(sys.stdin).getroot()
except ET.ParseError:
    sys.exit(1)
for element in svg:
    if element.tag == namespace + "text":
        text = element.text or ""
        if text.startswith(("READ / ", "WRITE / ")):
            panel = text
            target_y = None
    if panel not in expected or element.tag != namespace + "g":
        continue
    rectangle = element.find(namespace + "rect")
    if rectangle is None:
        continue
    frame = element.findtext(namespace + "title", "").split("; ", 1)[0]
    labels = set(frame.split())
    own_write = expected[panel] in labels and float(rectangle.attrib["width"]) > 0
    if panel != host_panel:
        if labels & (container_writers - {expected[panel]}):
            sys.exit(1)
        if own_write:
            found.add(panel)
        continue

    # Rectangles are drawn in tree order, with descendants above their parent.
    y = int(rectangle.attrib["y"])
    if target_y is not None and y >= target_y:
        target_y = None
    if own_write:
        target_y = y
    elif target_y is not None and frame and frame != "[unknown user stack]" and not frame.endswith(" [kernel]"):
        found.add(panel)
sys.exit(found != set(expected))
' "$@"
}

assert_iotracing_profile_logs() {
	local log_file=$1 component=$2 warning filtered
	warning=${IOTRACING_STACK_MAP_WARNING#^}
	warning=${warning%$}
	filtered="${HUATUO_BAMAI_TEST_TMPDIR}/iotracing-log-without-stack-map-warning"
	# Only the exact optional stack-map warning is allowed after a valid result.
	awk -v warning="${warning}" '
		!($0 ~ /(^| )msg="iotracing IO profile is incomplete"( |$)/ &&
			$0 ~ "(^| )reason=\"" warning "\"( |$)")
	' "${log_file}" > "${filtered}" || fatal "cannot read iotracing logs: ${log_file}"
	assert_log_has_no_failure "${filtered}" "${component}"
}

iotracing_filesystem_test() {
	source "${ROOT_DIR}/integration/lib.sh"
	source "${ROOT_DIR}/integration/lib_io.sh"

	require_commands grep timeout setsid python3 jq
	filesystem=$1
	case ${filesystem} in
	ext4 | xfs) ;;
	*) fatal "unsupported test filesystem: ${filesystem}; expected ext4 or xfs" ;;
	esac
	command -v "mkfs.${filesystem}" > /dev/null 2>&1 \
		|| skip "${filesystem} qualification requires mkfs.${filesystem}"
	if ! grep -qw "${filesystem}" /proc/filesystems; then
		if ! command -v modprobe > /dev/null 2>&1 || ! modprobe -n -q "${filesystem}"; then
			skip "${filesystem} is unavailable in the running kernel"
		fi
	fi
	bpf_tool_setup iotracing
	readonly DURATION=8
	IO_PID=""
	WORKLOAD_PID=""

	worker_pids=()
	iotracing_worker_names=(first second)
	iotracing_batch_id=0
	iotracing_last_capture=""
	xfs_module_added=0
	signal_status=0
	resources="${TOOL_WORK_DIR}/resources.txt"

	defer_interrupts() {
		trap 'signal_status=130' INT
		trap 'signal_status=143' TERM
	}

	record_resources() {
		printf 'mount=%s\ndisk=%s\ntracer=%s\nworkload=%s\nworkers=%s\n' \
			"${io_test_storage_dir}" "${TEST_IO_DISK}" "${IO_PID}" "${WORKLOAD_PID}" \
			"${worker_pids[*]}" > "${resources}"
		trap 'signal_status=130; exit 130' INT
		trap 'signal_status=143; exit 143' TERM
		((signal_status == 0)) || exit "${signal_status}"
	}

	process_stopped() {
		! kill -0 -- "-$1" 2> /dev/null
	}

	cleanup() {
		local status=$? pid processes_stopped=1
		((signal_status == 0)) || status=${signal_status}
		trap - EXIT
		trap '' INT TERM
		set +e
		if ((status != 0)) && [[ -n ${iotracing_last_capture} ]]; then
			iotracing_report_capture_inputs "${iotracing_last_capture}"
		fi
		for pid in "${IO_PID}" "${WORKLOAD_PID}" "${worker_pids[@]}"; do
			[[ -n ${pid} ]] || continue
			kill -TERM -- "-${pid}" 2> /dev/null || true
			stop_by_pid "${pid}" 5
			kill -KILL -- "-${pid}" 2> /dev/null || true
			if ! wait_until 2 0.1 process_stopped "${pid}"; then
				log_error "iotracing process remains: pid=${pid}; inspect ${resources} before reusing the fixture"
				status=1
				processes_stopped=0
			else
				wait "${pid}" 2> /dev/null
			fi
		done
		if ((processes_stopped)); then
			io_test_cleanup_disks || status=1
		else
			log_error "retaining filesystem ${io_test_storage_dir} until its owned processes exit"
		fi
		if ((processes_stopped && xfs_module_added)); then
			if ! wait_until 10 0.1 timeout --kill-after=1s 2s bash -c \
				'[[ ! -d /sys/module/xfs ]] || rmmod xfs' > "${TOOL_WORK_DIR}/xfs-module-cleanup.log" 2>&1; then
				log_error "cannot restore initially absent XFS module; inspect xfs-module-cleanup.log and remaining mounts"
				status=1
			fi
		fi
		printf 'cleanup_status=%s\n' "${status}" >> "${resources}"
		exit "${status}"
	}
	trap cleanup EXIT
	record_resources

	assert_iotracing_cli_schema() {
		[[ -s ${TOOL_OUT} ]] || fatal "iotracing produced empty output"

		# Envelope: parses as JSON, both top-level keys exist as arrays.
		jq -e '
			(.process_file_io_stats | type == "array") and
			(.io_schedule_timeout_stacks | type == "array") and
			(has("reason_snapshot") | not) and
			(has("failure_reason") | not)
		' "${TOOL_OUT}" > /dev/null \
			|| fatal "iotracing JSON schema invalid"
	}

	assert_iotracing_cli_writes() {
		MATCHED_IO=$(jq -ce '
			[
				.process_file_io_stats[]
				| select(.comm | test("^dd( |$)")) as $process
				| $process.total_files[]?
				| (.fs_write_bps + .disk_write_bps) as $write_bps
				| select(.path == "/io")
				| select($write_bps > 0)
				| {
					pid: $process.pid,
					comm: $process.comm,
					path: .path,
					fs_write_bps: .fs_write_bps,
					disk_write_bps: .disk_write_bps,
					total_write_bps: $write_bps
				}
			]
			| select(length > 0)
		' "${TOOL_OUT}") \
			|| fatal "no dd-attributed write to ${io_test_dir} found"
	}

	assert_iotracing_cli_device() {
		jq -e --argjson major "${major}" --argjson minor "${minor}" '
			all(.process_file_io_stats[].total_files[]?;
				.major == $major and .minor == $minor)
		' "${TOOL_OUT}" > /dev/null || fatal "iotracing output device does not match --device ${device}"
	}

	assert_iotracing_cli_block_reads() {
		jq -e --argjson reader "${block_reader_pid}" \
			--arg disk "${io_test_disk_name}" \
			--argjson major "${major}" --argjson minor "${minor}" '
			[.process_file_io_stats[] | select(.pid == $reader)] as $readers |
			($readers | length == 1) and
			all($readers[];
				(.total_disk_read_bps | type == "number" and . > 0) and
				any(.total_files[]?;
					.major == $major and .minor == $minor and .dev_name == $disk and
					(.disk_read_bps | type == "number" and . > 0))) and
			all(.process_file_io_stats[].total_files[]?;
				.major == $major and .minor == $minor)
		' "${TOOL_WORK_DIR}/block-read.out" > /dev/null \
			|| fatal "buffered block-device read lacks the workload PID, target device or positive read statistics; inspect block-read.out"
	}

	assert_iotracing_cli_empty() {
		jq -e '
			has("process_file_io_stats") and
			(.process_file_io_stats == [] or .process_file_io_stats == null) and
			(has("reason_snapshot") | not) and (has("failure_reason") | not)
		' "${TOOL_WORK_DIR}/empty.json" > /dev/null \
			|| fatal "nonexistent device did not produce a successful empty snapshot"
	}

	assert_iotracing_cli_output_conflict() {
		assert_invalid_args output-conflict --output json \
			--output-storage "${TOOL_WORK_DIR}/unused.sock" --task-id cli-invalid
		grep -Fq -- '--output and --output-storage are mutually exclusive' \
			"${TOOL_WORK_DIR}/invalid-output-conflict.err" \
			|| fatal "output-conflict: missing the mutually exclusive parameter error"
	}

	assert_iotracing_cli_workload_exit() {
		local name=$1 status=$2
		# timeout implementations report TERM as either 15 or shell status 143.
		[[ ${status} == 15 || ${status} == 143 ]] \
			|| fatal "${name} workload exit=${status}, expected TERM cancellation (15 or 143)"
	}

	assert_iotracing_cli_completed() {
		local name=$1 status=0
		wait "${IO_PID}" || status=$?
		((status == 0)) || fatal "iotracing ${name} capture exit=${status}, expected 0; inspect its stderr"
	}

	assert_iotracing_cli_writers() {
		jq -e --argjson first "${worker_pids[0]}" --argjson second "${worker_pids[1]}" '
			[.process_file_io_stats[] | select(.pid == $first or .pid == $second)] as $workers |
			($workers | map(.pid) | sort) == ([$first, $second] | sort) and
			all($workers[];
				(if .pid == $first then "first" else "second" end) as $prefix |
				([.total_files[] | select(.path | test("^/(first|second)-[012]$")) |
					select(.fs_read_bps > 0 and .fs_write_bps > 0 and
						.disk_write_bps > 0 and .is_direct == false) | .path] | sort) ==
				[range(0; 3) | "/" + $prefix + "-" + tostring] and
				any(.total_files[]; .path == "/" + $prefix + "-direct" and
					.fs_write_bps > 0 and .is_direct == true) and
				any(.total_files[]; .path == "/" + $prefix + "-shared" and
					.fs_write_bps > 0 and .is_direct == false))
		' "${TOOL_WORK_DIR}/top-full.out" > /dev/null \
			|| fatal "top-N fixture lacks attributed synchronous or shared mmap IO, Direct IO files or their expected is_direct flags"
	}

	assert_iotracing_cli_order() {
		# Rates are rounded individually; sums may differ by one at a tie.
		jq -e --argjson major "${major}" --argjson minor "${minor}" '
			def descending: . as $a | all(range(1; length); $a[. - 1] + 1 >= $a[.]);
			([.process_file_io_stats[] | .total_disk_read_bps + .total_disk_write_bps] | descending) and
			all(.process_file_io_stats[];
				([.total_files[]? | .disk_read_bps + .disk_write_bps] | descending)) and
			all(.process_file_io_stats[].total_files[]?;
				.major == $major and .minor == $minor)
		' "${TOOL_WORK_DIR}/top-full.out" > /dev/null \
			|| fatal "iotracing process/file order or device filtering is incorrect"
	}

	assert_iotracing_cli_file_limit() {
		jq -e --argjson first "${worker_pids[0]}" --argjson second "${worker_pids[1]}" '
			[.process_file_io_stats[] | select(.pid == $first or .pid == $second)] as $workers |
			($workers | map(.pid) | sort) == ([$first, $second] | sort) and
			all(.process_file_io_stats[]; .total_files | length <= 1) and
			all($workers[];
				(if .pid == $first then "first" else "second" end) as $prefix |
				.total_file_count >= 3 and (.total_files | length == 1) and
				(.total_files[0].path | test("^/" + $prefix + "-[012]$")) and
				.total_files[0].disk_write_bps > 0 and
				.total_disk_write_bps > .total_files[0].disk_write_bps)
		' "${TOOL_WORK_DIR}/top-files.out" > /dev/null \
			|| fatal "iotracing file limit lost known writers, their totals or nonempty file trimming"
	}

	assert_iotracing_cli_process_limit() {
		jq -e '
			(.process_file_io_stats | length == 1) and
			all(.process_file_io_stats[];
				(.total_disk_read_bps + .total_disk_write_bps > 0) and
				(.total_files | length > 0))
		' "${TOOL_WORK_DIR}/top-process.out" > /dev/null \
			|| fatal "iotracing process limit did not retain one nonempty IO process"
	}

	assert_iotracing_cli_text() {
		grep -Eq '/(first|second)-[012]' "${TOOL_WORK_DIR}/text.out" \
			|| fatal "text output does not identify a known workload file"
		grep -Eq "(^|[^0-9])(${worker_pids[0]}|${worker_pids[1]})([^0-9]|$)" \
			"${TOOL_WORK_DIR}/text.out" || fatal "text output does not identify a known workload PID"
		if jq -e . "${TOOL_WORK_DIR}/text.out" > /dev/null 2>&1; then
			fatal "--output text returned JSON"
		fi
	}

	iotracing_capture_is_ready() {
		local error_file=${1:-${TOOL_ERR}}
		kill -0 "${IO_PID}" 2> /dev/null \
			|| fatal "iotracing exited before readiness was observed; see ${error_file}"
		grep -Fxq 'iotracing: capture ready' "${error_file}"
	}

	iotracing_monotonic_ns() {
		python3 -c 'import time; print(int(time.monotonic() * 1000000000))'
	}

	iotracing_batch_is_complete() {
		local batch=$1 requested=$2 index pending=0
		for index in "${!worker_pids[@]}"; do
			kill -0 "${worker_pids[index]}" 2> /dev/null \
				|| fatal "writer ${worker_pids[index]} exited during batch ${batch}; inspect its workload log"
			if ! jq -e --argjson pid "${worker_pids[index]}" --argjson batch "${batch}" --argjson requested "${requested}" '
				.pid == $pid and .batch == $batch and .phase == "completed"
				and .started_ns >= $requested and .finished_ns > .started_ns
				and .read_bytes == 24576 and .sync_write_bytes == 24576
				and .direct_write_bytes == 4096 and .shared_write_bytes == 1
			' "${TOOL_WORK_DIR}/${iotracing_worker_names[index]}.ready" > /dev/null; then
				pending=1
			fi
		done
		((pending)) || return 0
		kill -0 "${IO_PID}" 2> /dev/null \
			|| fatal "iotracing ended before both writers completed batch ${batch}; inspect capture inputs and receipts"
		return 1
	}

	iotracing_report_capture_inputs() {
		local capture=$1 index pid output
		log_error "iotracing input diagnostics: capture=${capture}, batch=${iotracing_batch_id}"
		printf 'failure_observed_ns=%s\n' "$(iotracing_monotonic_ns)" >> "${TOOL_WORK_DIR}/${capture}.inputs"
		cat "${TOOL_WORK_DIR}/${capture}.inputs" >&2
		for index in "${!worker_pids[@]}"; do
			pid=${worker_pids[index]}
			output="${TOOL_WORK_DIR}/${capture}-${iotracing_worker_names[index]}.state"
			{
				printf 'pid=%s\n' "${pid}"
				cat "${TOOL_WORK_DIR}/${iotracing_worker_names[index]}.ready"
				grep -E '^(Name|State|Pid|PPid|Threads):' "/proc/${pid}/status"
				cat "/proc/${pid}/io" "/proc/${pid}/wchan"
			} > "${output}" 2>&1
			cat "${output}" >&2
		done
	}

	run_filesystem_tests() {
		local filesystem=$1 device
		local io_test_dir="${io_test_storage_dir}"
		read -r device < "/sys/class/block/${io_test_disk_name}/dev"
		record_resources

		# The CLI attaches XFS probes whenever the host advertises XFS,
		# including captures whose workload filesystem is ext4.
		if grep -qw xfs /proc/filesystems; then
			local probe_status=0
			io_test_xfs_available "${TOOL_BIN}" "${TOOL_BPF}" "${device}" "${TOOL_WORK_DIR}/xfs-qualification" \
				|| probe_status=$?
			if ((probe_status == 77)); then
				skip "XFS name-based attachment is unavailable; inspect xfs-qualification"
			fi
			((probe_status == 0)) || fatal "XFS CLI startup failed; inspect xfs-qualification/xfs-cli.err"
		fi

		log_info "iotracing: filesystem=${filesystem}, duration=${DURATION}s, device=${device}, io_test_dir=${io_test_dir}"
		defer_interrupts
		setsid timeout --kill-after=5s "$((io_test_iotracing_ready_timeout + DURATION))s" "${TOOL_BIN}" --bpf-path "${TOOL_BPF}" \
			--duration "${DURATION}" \
			--device "${device}" \
			--output json \
			> "${TOOL_OUT}" 2> "${TOOL_ERR}" &
		IO_PID=$!
		record_resources

		# The CLI confirms both event-channel creation and complete probe attachment.
		wait_until "${io_test_iotracing_ready_timeout}" 1 iotracing_capture_is_ready \
			|| fatal "iotracing capture was not ready within ${io_test_iotracing_ready_timeout} seconds; see ${TOOL_ERR}"

		# Keep writes active until capture ends without growing the private filesystem.
		defer_interrupts
		setsid timeout --preserve-status --kill-after=1s 30s bash -c '
			while :; do
				dd if=/dev/zero of="$1" bs=1M count=16 oflag=dsync conv=notrunc status=none || exit
			done
		' _ "${io_test_dir}/io" > "${TOOL_WORK_DIR}/dd.log" 2>&1 &
		WORKLOAD_PID=$!
		record_resources

		assert_iotracing_cli_completed baseline
		IO_PID=""
		kill -0 "${WORKLOAD_PID}" 2> /dev/null || fatal "dd workload ended before capture completed"
		kill -TERM -- "-${WORKLOAD_PID}" 2> /dev/null || true
		workload_status=0
		wait "${WORKLOAD_PID}" || workload_status=$?
		wait_until 3 0.1 process_stopped "${WORKLOAD_PID}" \
			|| fatal "dd process group remains after cancellation; inspect resources.txt"
		WORKLOAD_PID=""
		record_resources
		assert_iotracing_cli_workload_exit dd "${workload_status}"
		assert_iotracing_cli_schema

		# Accuracy: a row attributed to dd holds the private file with non-zero
		# write bps. Captured paths are relative to the filesystem root.
		# comm may be "dd" (BPF capture) or "dd if=/dev/zero ..."
		# (cmdline fallback when /proc still has the entry); match the leading
		# token. Preserve the matched rows so a successful run shows which
		# attribution data satisfied the accuracy check.
		assert_iotracing_cli_writes

		log_info "matched dd-attributed writes:"
		echo "${MATCHED_IO}" | jq '.'

		# The successful matching workload makes this exclusion check non-vacuous.
		major=${device%:*}
		minor=${device#*:}
		assert_iotracing_cli_device

		# Buffered device reads exercise bdevfs attribution independently of files.
		# Evict only a tail page on the owned disk so every read reaches block IO.
		local block_reader_pid block_read_status=0
		defer_interrupts
		setsid timeout --preserve-status --kill-after=1s "$((io_test_iotracing_ready_timeout + 30))s" \
			python3 "${ROOT_DIR}/integration/testdata/test_iotracing_workload.py" block-read \
			"${TEST_IO_DISK}" "${TOOL_WORK_DIR}/block-read.ready" \
			> "${TOOL_WORK_DIR}/block-read.log" 2>&1 &
		WORKLOAD_PID=$!
		record_resources
		wait_until 5 0.1 test -s "${TOOL_WORK_DIR}/block-read.ready" \
			|| fatal "buffered block reader did not complete its first read; inspect block-read.log"
		block_reader_pid=$(< "${TOOL_WORK_DIR}/block-read.ready")
		[[ ${block_reader_pid} =~ ^[1-9][0-9]*$ ]] || fatal "buffered block reader published an invalid PID"
		defer_interrupts
		setsid timeout --kill-after=5s "$((io_test_iotracing_ready_timeout + 1))s" "${TOOL_BIN}" --bpf-path "${TOOL_BPF}" \
			--duration 1 --device "${device}" --output json \
			> "${TOOL_WORK_DIR}/block-read.out" 2> "${TOOL_WORK_DIR}/block-read.err" &
		IO_PID=$!
		record_resources
		assert_iotracing_cli_completed buffered-block-read
		IO_PID=""
		kill -0 "${block_reader_pid}" 2> /dev/null || fatal "buffered block reader ended before capture completed"
		kill -TERM -- "-${WORKLOAD_PID}" 2> /dev/null || true
		wait "${WORKLOAD_PID}" || block_read_status=$?
		wait_until 3 0.1 process_stopped "${WORKLOAD_PID}" \
			|| fatal "buffered block-reader process group remains; inspect resources.txt"
		WORKLOAD_PID=""
		record_resources
		assert_iotracing_cli_workload_exit buffered-block-reader "${block_read_status}"
		assert_iotracing_cli_block_reads
		log_info "iotracing buffered block-device read retained pid=${block_reader_pid} device=${device}"

		# A valid unused device must be accepted, while malformed input must fail
		# before any capture. The largest valid device number is checked for absence.
		absent_device=4095:1048575
		[[ ! -e /sys/dev/block/${absent_device} ]] \
			|| fatal "empty-result fixture device unexpectedly exists: ${absent_device}"
		timeout --kill-after=5s "$((io_test_iotracing_ready_timeout + 1))s" "${TOOL_BIN}" --bpf-path "${TOOL_BPF}" \
			--duration 1 --device "${absent_device}" --output json \
			> "${TOOL_WORK_DIR}/empty.json" 2> "${TOOL_WORK_DIR}/empty.err" \
			|| fatal "iotracing rejected a valid nonexistent device"
		assert_iotracing_cli_empty

		assert_invalid_args() {
			local name=$1 status=0
			shift
			timeout --kill-after=1s 5s "${TOOL_BIN}" --bpf-path "${TOOL_BPF}" "$@" \
				> "${TOOL_WORK_DIR}/invalid-${name}.out" \
				2> "${TOOL_WORK_DIR}/invalid-${name}.err" || status=$?
			[[ ${status} -eq 1 ]] || fatal "invalid ${name}: exit=${status}, expected 1"
			[[ -s ${TOOL_WORK_DIR}/invalid-${name}.err ]] \
				|| fatal "invalid ${name}: stderr did not explain the rejection"
		}
		assert_invalid_args duration-zero --duration 0
		assert_invalid_args duration-negative --duration -1
		assert_invalid_args threshold-zero --schedule-threshold 0
		assert_invalid_args threshold-negative --schedule-threshold -1
		assert_invalid_args output --output xml
		assert_invalid_args device-format --device 8:0:1
		assert_invalid_args device-major --device 4096:0
		assert_invalid_args device-minor --device 8:1048576
		assert_invalid_args device-count --device \
			'8:0,8:1,8:2,8:3,8:4,8:5,8:6,8:7,8:8,8:9,8:10,8:11,8:12,8:13,8:14,8:15,8:16'
		assert_iotracing_cli_output_conflict

		# Stable writers mark a fresh IO round after each CLI reports readiness.
		for name in "${iotracing_worker_names[@]}"; do
			defer_interrupts
			setsid python3 "${ROOT_DIR}/integration/testdata/test_iotracing_workload.py" files "${io_test_dir}" "${name}" \
				"${TOOL_WORK_DIR}/${name}.ready" "$((4 * (io_test_iotracing_ready_timeout + 2) + 30))" \
				> "${TOOL_WORK_DIR}/${name}.log" 2>&1 &
			worker_pids+=("$!")
			record_resources
			wait_until 5 0.1 test -e "${TOOL_WORK_DIR}/${name}.ready" \
				|| fatal "${name} multi-file workload did not initialize"
		done

		capture_cli() {
			local name=$1 launched requested index
			shift
			iotracing_last_capture=${name}
			iotracing_batch_id=$((iotracing_batch_id + 1))
			launched=$(iotracing_monotonic_ns)
			defer_interrupts
			setsid timeout --kill-after=5s "$((io_test_iotracing_ready_timeout + 1))s" "${TOOL_BIN}" --bpf-path "${TOOL_BPF}" \
				--duration 1 --device "${device},${absent_device}" "$@" \
				> "${TOOL_WORK_DIR}/${name}.out" 2> "${TOOL_WORK_DIR}/${name}.err" &
			IO_PID=$!
			record_resources
			printf 'capture=%s cli_pid=%s duration_seconds=1 batch=%s launch_ns=%s\n' \
				"${name}" "${IO_PID}" "${iotracing_batch_id}" "${launched}" > "${TOOL_WORK_DIR}/${name}.inputs"
			wait_until "${io_test_iotracing_ready_timeout}" 0.05 iotracing_capture_is_ready "${TOOL_WORK_DIR}/${name}.err" \
				|| fatal "iotracing ${name} did not report readiness"
			requested=$(iotracing_monotonic_ns)
			printf 'ready_observed_ns=%s\nload_requested_ns=%s\n' "${requested}" "${requested}" \
				>> "${TOOL_WORK_DIR}/${name}.inputs"
			kill -0 "${IO_PID}" 2> /dev/null || fatal "iotracing ${name} ended before a fresh IO batch could start"
			for pid in "${worker_pids[@]}"; do
				kill -USR1 "${pid}" || fatal "cannot request IO batch from writer ${pid}"
			done
			wait_until 5 0.05 iotracing_batch_is_complete "${iotracing_batch_id}" "${requested}" \
				|| fatal "iotracing ${name} workload batch did not finish; inspect writer receipts"
			for index in "${!worker_pids[@]}"; do
				cp "${TOOL_WORK_DIR}/${iotracing_worker_names[index]}.ready" \
					"${TOOL_WORK_DIR}/${name}-${iotracing_worker_names[index]}.receipt.json"
			done
			assert_iotracing_cli_completed "${name}"
			printf 'exit_observed_ns=%s\n' "$(iotracing_monotonic_ns)" >> "${TOOL_WORK_DIR}/${name}.inputs"
			IO_PID=""
			record_resources
			for pid in "${worker_pids[@]}"; do
				kill -0 "${pid}" 2> /dev/null || fatal "multi-file workload ${pid} stopped during ${name}"
			done
		}

		capture_cli top-full --output json --max-process 100 --max-files-per-process 100
		assert_iotracing_cli_writers

		assert_iotracing_cli_order

		# Kernel workers can also issue IO on the private device. Keep both known
		# writers visible when checking file trimming; their rank may change between
		# capture windows, so the process limit has its own check below.
		capture_cli top-files --output json --max-process 100 --max-files-per-process 1
		assert_iotracing_cli_file_limit

		capture_cli top-process --output json --max-process 1 --max-files-per-process 100
		assert_iotracing_cli_process_limit

		capture_cli text --output text --max-process 100 --max-files-per-process 3
		assert_iotracing_cli_text

		for pid in "${worker_pids[@]}"; do
			stop_and_wait_by_pid "${pid}" 5 || fatal "multi-file workload ${pid} did not stop cleanly"
		done
		worker_pids=()
		record_resources
		log_info "T01-T04 CLI output, filtering, process/file top-N and invalid parameters verified"
	}

	if [[ ${filesystem} == xfs ]] && ! grep -qw xfs /proc/filesystems; then
		require_commands rmmod
		# Mount may autoload global probes even when qualification then skips.
		xfs_module_added=1
	fi
	io_test_prepare_storage "${filesystem}"
	run_filesystem_tests "${filesystem}"
}
