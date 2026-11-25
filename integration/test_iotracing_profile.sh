#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# One fixed capture, one joint-valued output. The workload reports actual file
# returns; phases before/after the cutoff never rely on periodic output.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_profiler.sh"
source "${ROOT_DIR}/integration/lib_iotracing.sh"
readonly IO_FIXTURE="${ROOT_DIR}/integration/testdata/test_io_profile.py"
readonly IO_ITERATIONS=64
readonly IO_EVERY=16
# Change comm to create more aggregation keys without relying on stack collisions.
readonly IO_AGGREGATE_CAPACITY=4096
readonly IO_OVERFLOW_KEYS=4200
require_commands python3 jq setsid findmnt timeout
bpf_tool_setup iotracing iotracing iotracing-profile
readonly IO_WORK_DIR=${TOOL_WORK_DIR}
trap 'cleanup_running_jobs; cleanup_iotracing_profile_data' EXIT
prepare_iotracing_profile_data
if command -v gcc > /dev/null 2>&1; then
	compile_user_fixture "${ROOT_DIR}/integration/testdata/test_io_profile_blocked_read.c" \
		"${IO_WORK_DIR}/blocked-read.so" -shared -fPIC -pthread
fi

io_capture_ready() { grep -Fq "$2" "$1"; }

assert_io_json() {
	local directory=$1 mode=$2 duration=$3
	local alternate_count=0
	[[ ${directory##*/} != count ]] || alternate_count=${IO_EVERY}
	jq -se --arg pid "$(< "${directory}/target.pid")" --arg mode "${mode}" --arg hostname "$(hostname)" \
		--argjson duration "${duration}" --argjson alternate_count "${alternate_count}" \
		--slurpfile workload "${directory}/workload.json" '
	def counters:
		group_by(.direction, .outcome) | map({
			direction: .[0].direction, outcome: .[0].outcome,
			bytes: (map(.bytes) | add), count: (map(.count) | add)
		});
	length == 1 and .[0].profile_type == "filesystem_io:bytes:bytes:operations:count"
	and ((.[0].dropped_samples // {}) | length == 0)
	and (.[0].profile as $p |
		($p.sample_type | map($p.string_table[.type])) == ["bytes","operations","duration"]
		and $p.string_table[$p.default_sample_type] == "bytes"
		and ($p.string_table | index("cgroup_css") == null and index("cgroup_id") == null)
		and $p.time_nanos > 0 and $p.duration_nanos == $duration * 1000000000
		and ([ $p.sample[]? | . as $s |
			([$s.label[]? | {key:$p.string_table[.key], value:$p.string_table[.str]}] | from_entries) as $labels |
			{labels:$labels, direction:$labels.direction, outcome:$labels.result,
				bytes:.value[0], count:.value[1], duration:.value[2], stack:.location_id} |
			select($labels.pid == $pid)] as $rows |
		([$workload[].results | to_entries[] | .key as $direction | .value | to_entries[] |
			.value + {direction:$direction, outcome:(if .key == "error" then "error" else "success" end)}]
			| counters) as $expected |
		($rows | counters) == $expected
		and all($rows[];
			.labels.pid == $pid and .labels.io_stack_mode == $mode and .labels.attribution == "other"
			and .labels.container_hostname == $hostname and (.labels | has("container_id") | not)
			and .duration > 0)
		and all(["read","write"][]; . as $direction |
			any($rows[]; .direction == $direction and .outcome == "success" and (.stack | length > 0)))
		and ([$rows[] | select(.direction == "write" and .outcome == "success"
			and (.stack | length > 0))] as $writes |
			if $mode == "io_time" then
				[$workload[] | .comm as $comm |
					[$writes[] | select(.labels.comm == $comm and .count == 1) | .stack]] as $stacks |
				($writes | length) == 4 and all($stacks[]; length == 1)
				and $stacks[0] == $stacks[1] and $stacks[0] == $stacks[2] and $stacks[0] != $stacks[3]
			else $alternate_count == 0 or any($writes[]; .count == $alternate_count)
			end)))
	' "${directory}/profile.json" > /dev/null || fatal "profile did not match measured file returns or sampled stacks: ${directory}"
}

assert_io_crossed_cutoff() {
	local directory=$1 entered
	if [[ -s ${directory}/crossed-read.json ]]; then
		entered=$(awk '/^io-cutoff-blocked / {print $2}' "${directory}/workload.log")
		jq -e --argjson entered "${entered}" --slurpfile crossed "${directory}/crossed-read.json" '
			.profile as $p | ($p.time_nanos + $p.duration_nanos) as $deadline |
			$p.time_nanos <= $entered and $entered < $deadline
			and $crossed[0].finished_ns >= $deadline and $crossed[0].bytes == 3072
		' "${directory}/profile.json" > /dev/null || fatal "fixture read did not span the IO deadline"
	fi
}

assert_io_svg_panel() {
	grep -Fq "$2" "$1" || fatal "combined SVG missing $2: $1"
}

assert_io_legacy_report() {
	local report=$1 pid=$2 name=$3
	jq -e --argjson pid "${pid}" --arg hostname "$(hostname)" '
		has("process_file_io_stats") and has("io_schedule_timeout_stacks")
		and any(.process_file_io_stats[]; .pid == $pid and .container_hostname == $hostname
			and .total_fs_read_bps > 0 and .total_fs_write_bps > 0)
	' "${report}" > /dev/null || fatal "legacy process statistics or UTS hostname changed: ${report}"
	case ${name} in
	count)
		jq -e --arg stack_warning "${IOTRACING_STACK_MAP_WARNING}" '
			.io_profile != null and (.io_profile_error |
				if type == "string" then test($stack_warning) else . == null end)
		' "${report}" > /dev/null || fatal "combined capture lost optional profile: ${report}"
		;;
	fallback)
		jq -e '.io_profile == null and (.io_profile_error | contains("--io-stack-period requires a positive integer IO count"))' "${report}" > /dev/null \
			|| fatal "optional setup failure did not preserve original report: ${report}"
		;;
	cancel)
		jq -e '.io_profile == null and .io_profile_error == "IO profile capture stopped before its deadline"' \
			"${report}" > /dev/null || fatal "cancelled capture published a partial profile: ${report}"
		;;
	esac
}

run_io_case() (
	local name=$1 mode=$2 duration=$3 batches=$4
	local directory="${IO_WORK_DIR}/${name}" profiler_pid="" input_fd output_fd target_pid target_start profiler_start line status=0
	local -a sampling=(--io-stack-period "${IO_EVERY}") fixture_args=()
	if [[ ${name} == cutoff && -f ${IO_WORK_DIR}/blocked-read.so ]]; then
		fixture_args+=("${IO_WORK_DIR}/blocked-read.so")
	fi
	[[ ${mode} != io_time ]] || sampling=(--io-stack-period 1)
	trap '[[ -z ${profiler_pid} ]] || kill -CONT "${profiler_pid}" 2>/dev/null || true; cleanup_running_jobs' EXIT
	mkdir -p "${directory}"
	start_piped_process "${directory}/workload" python3 -u "${IO_FIXTURE}" \
		"${iotracing_profile_data}/${name}.data" "${fixture_args[@]}"
	target_pid=${PROCESS_PID}
	target_start=${PROCESS_START_TIME}
	input_fd=${PROCESS_INPUT_FD}
	output_fd=${PROCESS_OUTPUT_FD}
	printf '%s\n' "${target_pid}" > "${directory}/target.pid"
	assert_process_message "${output_fd}" "${directory}/workload.log" io-workload-ready
	local result_path="${directory}/report.json"
	local -a capture=(--bpf-path "${TOOL_BPF}" --max-process 512 --max-files-per-process 512)
	local -a output=(--output json)
	case ${name} in
	text)
		output=()
		result_path="${directory}/report.txt"
		;;
	fallback)
		capture+=(--io-stack-period 0)
		;;
	*)
		capture+=(--io-stack-mode "${mode}" "${sampling[@]}")
		[[ ${name} != count ]] || capture+=(--io-profile-svg "${directory}/profile.svg")
		;;
	esac
	setsid "${TOOL_BIN}" "${capture[@]}" --duration "${duration}" "${output[@]}" \
		> "${result_path}" 2> "${directory}/profiler.err" &
	profiler_pid=$!
	profiler_start=$(process_start_time "${profiler_pid}")
	wait_until 20 0.1 io_capture_ready "${directory}/profiler.err" "iotracing: capture ready" || fatal "IO capture did not become ready"
	for ((batch = 0; batch < batches; batch++)); do
		if [[ ${mode} == io_time && ${batch} -gt 0 ]]; then
			local offset
			case ${batch} in
			1) offset=150000000 ;;
			2) offset=600000000 ;;
			3) offset=1200000000 ;;
			esac
			printf 'wait %s\n' "$(jq -sr --argjson offset "${offset}" '.[0].finished_ns + $offset' "${directory}/workload.json")" 1>&"${input_fd}"
			assert_process_message "${output_fd}" "${directory}/workload.log" io-wait-complete
		fi
		local alternate=-1
		if [[ ${name} == count && ${batch} == 0 ]]; then
			alternate=${IO_EVERY}
		fi
		if [[ ${name} == overflow ]]; then
			printf 'overflow %s\n' "${IO_OVERFLOW_KEYS}" 1>&"${input_fd}"
		elif [[ ${mode} == io_time ]]; then
			printf 'time-phase %s\n' "${batch}" 1>&"${input_fd}"
		else
			printf 'run %s %s\n' "${IO_ITERATIONS}" "${alternate}" 1>&"${input_fd}"
		fi
		IFS= read -r -t 10 -u "${output_fd}" line || fatal "IO workload did not finish"
		printf '%s\n' "${line}" >> "${directory}/workload.json"
		[[ ! -s ${result_path} ]] || fatal "IO capture emitted data before its deadline"
	done
	if [[ ${name} == cutoff ]]; then
		kill -STOP "${profiler_pid}"
		if ((${#fixture_args[@]} == 0)) || grep -q '^io-cutoff-unavailable ' "${directory}/workload.log"; then
			log_info "SKIP: cross-deadline read requires gcc and userfaultfd; testing entry after deadline"
			sleep "${duration}"
		else
			printf 'blocked-read\n' 1>&"${input_fd}"
			assert_process_message "${output_fd}" "${directory}/workload.log" io-cutoff-blocked
			sleep "${duration}"
			printf x 1>&"${input_fd}"
			IFS= read -r -t 10 -u "${output_fd}" line || fatal "cross-deadline read did not return"
			printf '%s\n' "${line}" > "${directory}/crossed-read.json"
		fi
		printf 'run %s\n' "${IO_ITERATIONS}" 1>&"${input_fd}"
		IFS= read -r -t 10 -u "${output_fd}" line || fatal "late IO workload did not finish"
		printf '%s\n' "${line}" > "${directory}/late-workload.json"
		# A signal pending when the process resumes must still keep the completed profile.
		kill -INT "${profiler_pid}"
		kill -CONT "${profiler_pid}"
	fi
	if [[ ${name} == cancel ]]; then kill -INT "${profiler_pid}"; fi
	wait_until 15 0.1 process_exited "${profiler_pid}" "${profiler_start}" || fatal "IO capture did not stop"
	wait "${profiler_pid}" || status=$?
	profiler_pid=""
	assert_eq "${status}" 0 "IO capture exit" || fatal "IO capture failed: $(< "${directory}/profiler.err")"
	if [[ ${name} == text ]]; then
		grep -Eq "^PID:[[:space:]]+${target_pid}[[:space:]]" "${result_path}" \
			|| fatal "default text report lost the workload's original diagnostics: ${result_path}"
		if grep -Eq '^IO PROFILE|^IO profile error:' "${result_path}"; then
			fatal "default text report included IO Profile output: ${result_path}"
		fi
	elif [[ ${name} == cancel ]]; then
		assert_io_legacy_report "${result_path}" "${target_pid}" "${name}"
	else
		case ${name} in
		count | fallback)
			assert_io_legacy_report "${result_path}" "${target_pid}" "${name}"
			;;
		esac
		case ${name} in
		fallback) ;;
		*) jq -e '.io_profile' "${result_path}" > "${directory}/profile.json" ;;
		esac
		if [[ ${name} == count ]]; then
			assert_io_svg_panel "${directory}/profile.svg" 'READ / host'
			assert_io_svg_panel "${directory}/profile.svg" 'WRITE / host'
		fi
		if [[ ${mode} == io_time ]]; then
			jq -se '
				length == 4
				and .[2].started_ns - .[0].finished_ns >= 500000000
				and .[2].finished_ns - .[0].started_ns < 1000000000
				and .[3].started_ns - .[0].finished_ns >= 1000000000
			' "${directory}/workload.json" > /dev/null || fatal "time sampling fixture missed its timing window: ${directory}"
		fi
		case ${name} in
		fallback) ;;
		overflow) assert_iotracing_profile_overflow "${directory}" "${IO_AGGREGATE_CAPACITY}" false ;;
		*) assert_io_json "${directory}" "${mode}" "${duration}" ;;
		esac
		if [[ ${name} == cutoff ]]; then
			assert_io_crossed_cutoff "${directory}"
		fi
	fi
	assert_process_alive "${target_pid}" "${target_start}" "IO target during symbol resolution"
	printf 'stop\n' 1>&"${input_fd}"
	exec {input_fd}>&-
	wait "${target_pid}" || fatal "IO workload failed"
	exec {output_fd}<&-
)

run_io_case count io_count 1 2
run_io_case time io_time 2 4
run_io_case cutoff io_count 2 1
run_io_case overflow io_count 2 1
run_io_case cancel io_count 30 1
run_io_case fallback io_count 1 1
run_io_case text io_count 1 1
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp -a "${IO_WORK_DIR}" "${HUATUO_IO_ARTIFACT_DIR}/"
fi
