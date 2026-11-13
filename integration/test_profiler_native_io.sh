#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# One fixed capture, one joint-valued output. The workload reports actual file
# returns; phases before/after the cutoff never rely on periodic output.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_profiler.sh"
readonly IO_FIXTURE="${ROOT_DIR}/integration/testdata/test_profiler_io.py"
readonly IO_ITERATIONS=64
readonly IO_EVERY=16
require_commands python3 jq setsid findmnt timeout
bpf_tool_setup profiler native_io_profiler profiler-io
readonly IO_WORK_DIR=${TOOL_WORK_DIR}
trap cleanup_running_jobs EXIT

io_capture_ready() { grep -Fq 'file IO capture ready' "$1"; }

assert_io_json() {
	local directory=$1 mode=$2 batches=$3 duration=$4
	jq -se --arg pid "$(< "${directory}/target.pid")" --arg mode "${mode}" --argjson batches "${batches}" --argjson iterations "${IO_ITERATIONS}" --argjson duration "${duration}" '
  length == 1 and .[0].profile_type == "filesystem_io:bytes:bytes:operations:count"
  and (.[0].profile as $p |
    ($p.sample_type | map($p.string_table[.type])) == ["bytes","operations","duration","events"]
    and $p.time_nanos > 0 and $p.duration_nanos == $duration * 1000000000
    and ([ $p.sample[]? | . as $s | ([$s.label[]? | {key:$p.string_table[.key],value:$p.string_table[.str]}] | from_entries) as $labels |
      {labels:$labels,bytes:.value[0],count:.value[1],duration:.value[2],events:.value[3]} ] as $rows |
      all($rows[]; if .labels.kind == "io" then .labels.pid == $pid and .labels.io_stack_mode == $mode and .events == 0 else .labels.kind == "diagnostic" end)
      and all(["read","write"][]; . as $direction |
        [$rows[] | select(.labels.kind == "io" and .labels.direction == $direction and .labels.result == "success")] as $success |
        ($success | map(.bytes) | add) == $batches * ($iterations * 4096 + 17)
        and ($success | map(.count) | add) == $batches * ($iterations + 1)
        and ($success | map(.duration) | add) > 0)
      and all(["read","write"][]; . as $direction |
        ([$rows[] | select(.labels.direction == $direction and .labels.result == "zero_length") | .count] | add) == $batches)
      and ([$rows[] | select(.labels.result == "eof") | .count] | add) == $batches
      and ([$rows[] | select(.labels.result == "error") | .count] | add) == $batches
      and all($rows[] | select(.labels.kind == "diagnostic" and (.labels.reason | test("^(aggregate_failure|state_insert_failure|identity_failure|state_delete_failure)$"))); .events == 0)))
 ' "${directory}/profile.json" > /dev/null || fatal "single capture totals differ from actual file returns: ${directory}"
	jq '.profile as $p | reduce ($p.sample[]? | select(any(.label[]?; $p.string_table[.key] == "kind" and $p.string_table[.str] == "diagnostic"))) as $s
  ({}; ([$s.label[] | select($p.string_table[.key] == "reason") | $p.string_table[.str]][0]) as $reason | .[$reason] += $s.value[3])' \
		"${directory}/profile.json" > "${directory}/diagnostics.json"
	local attempts
	if [[ ${mode} == count ]]; then attempts=$((2 * (1 + (batches * (IO_ITERATIONS + 1) - 1) / IO_EVERY))); else attempts=4; fi
	assert_eq "$(jq -r '.stack_attempt' "${directory}/diagnostics.json")" "${attempts}" "one-shot ${mode} representative refreshes" || fatal "unexpected refresh count"
}

run_io_case() (
	local name=$1 mode=$2 duration=$3 batches=$4
	local directory="${IO_WORK_DIR}/${name}" profiler_pid="" input_fd output_fd target_pid target_start profiler_start line status=0
	local -a sampling=(--io-stack-every "${IO_EVERY}")
	[[ ${mode} != time ]] || sampling=(--io-stack-interval 1s)
	trap '[[ -z ${profiler_pid} ]] || kill -CONT "${profiler_pid}" 2>/dev/null || true; cleanup_running_jobs' EXIT
	mkdir -p "${directory}"
	start_piped_process "${directory}/workload" python3 -u "${IO_FIXTURE}" "${directory}/data"
	target_pid=${PROCESS_PID}
	target_start=${PROCESS_START_TIME}
	input_fd=${PROCESS_INPUT_FD}
	output_fd=${PROCESS_OUTPUT_FD}
	printf '%s\n' "${target_pid}" > "${directory}/target.pid"
	assert_process_message "${output_fd}" "${directory}/workload.log" io-workload-ready
	setsid "${TOOL_BIN}" --type io --language c --pid "${target_pid}" --kubelet-read-only-port 0 --kubelet-authorized-port 0 \
		--io-stack-mode "${mode}" "${sampling[@]}" --duration "${duration}" --output-format json --output-path "${directory}/profile.json" \
		--log-bpf-debug=true --log-level info --log-file stdout > "${directory}/profiler.out" 2> "${directory}/profiler.err" &
	profiler_pid=$!
	profiler_start=$(process_start_time "${profiler_pid}")
	wait_until 20 0.1 io_capture_ready "${directory}/profiler.out" || fatal "IO capture did not become ready"
	for ((batch = 0; batch < batches; batch++)); do
		if [[ ${mode} == time && ${batch} -gt 0 ]]; then
			local offset=600000000
			((batch != 2)) || offset=1200000000
			printf 'wait %s\n' "$(jq -sr --argjson offset "${offset}" '.[0].finished_ns + $offset' "${directory}/workload.json")" 1>&"${input_fd}"
			assert_process_message "${output_fd}" "${directory}/workload.log" io-wait-complete
		fi
		printf 'run %s\n' "${IO_ITERATIONS}" 1>&"${input_fd}"
		IFS= read -r -t 10 -u "${output_fd}" line || fatal "IO workload did not finish"
		printf '%s\n' "${line}" >> "${directory}/workload.json"
		[[ ! -s ${directory}/profile.json ]] || fatal "IO capture emitted data before its deadline"
	done
	if [[ ${name} == cutoff ]]; then
		kill -STOP "${profiler_pid}"
		printf 'wait %s\n' "$(jq -sr '.[0].finished_ns + 1500000000' "${directory}/workload.json")" 1>&"${input_fd}"
		assert_process_message "${output_fd}" "${directory}/workload.log" io-wait-complete
		printf 'run %s\n' "${IO_ITERATIONS}" 1>&"${input_fd}"
		IFS= read -r -t 10 -u "${output_fd}" line || fatal "late IO workload did not finish"
		printf '%s\n' "${line}" > "${directory}/late-workload.json"
		kill -CONT "${profiler_pid}"
	fi
	if [[ ${name} == cancel ]]; then kill -INT "${profiler_pid}"; fi
	wait_until 15 0.1 process_exited "${profiler_pid}" "${profiler_start}" || fatal "IO capture did not stop"
	wait "${profiler_pid}" || status=$?
	profiler_pid=""
	if [[ ${name} == cancel ]]; then
		assert_eq "${status}" 1 "cancelled IO capture" || fatal "cancellation was published as success"
		[[ ! -s ${directory}/profile.json ]] || fatal "cancelled capture published a partial result"
	else
		assert_eq "${status}" 0 "IO capture exit" || fatal "IO capture failed: $(< "${directory}/profiler.err")"
		assert_io_json "${directory}" "${mode}" "${batches}" "${duration}"
	fi
	assert_process_alive "${target_pid}" "${target_start}" "IO target during symbol resolution"
	printf 'stop\n' 1>&"${input_fd}"
	exec {input_fd}>&-
	wait "${target_pid}" || fatal "IO workload failed"
	exec {output_fd}<&-
)

case $(stat -f -c %t "${IO_WORK_DIR}") in
ef53 | 58465342) ;;
*) skip "IO capture requires ext4 or xfs in ${IO_WORK_DIR}" ;;
esac
run_io_case count count 2 2
run_io_case time time 3 3
run_io_case cutoff count 1 1
run_io_case cancel count 30 1
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp -a "${IO_WORK_DIR}" "${HUATUO_IO_ARTIFACT_DIR}/"
fi
