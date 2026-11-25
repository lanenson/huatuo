#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# Exercise CLI container filtering and bamai's event attribution with two
# simultaneous writers on real Docker-managed ext4 or XFS volumes.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"
source "${ROOT_DIR}/integration/lib_iotracing.sh"
require_commands python3 jq ss docker openssl timeout
require_readable /sys/kernel/btf/vmlinux

readonly IO_TRIGGER_FIXTURE="${HUATUO_BAMAI_TEST_TMPDIR}/disk-fixture"
readonly IO_TRIGGER_EVENT="${HUATUO_BAMAI_TEST_TMPDIR}/events/iotracing"
readonly IO_CONTAINER_OWNER=$(test_docker_owner_label "${HUATUO_BAMAI_TEST_TMPDIR}")
readonly IO_CONTAINER_CLEANUP_MARKER="${HUATUO_BAMAI_TEST_TMPDIR}/docker-cleanup.pending"
readonly IO_CONTAINER_IMAGE=${NATIVE_PROFILER_DOCKER_IMAGE:-busybox:1.36.1}
# Match the bamai Pod.DockerAPIVersion default used by this fixture.
readonly IO_CONTAINER_DOCKER_API_VERSION=1.24
io_trigger_device=()
io_trigger_writer=""
io_kubelet_pid=""
io_kubelet_port=""
io_docker_driver=""
io_container_ids=()
io_container_pids=()
io_container_hostnames=()

cleanup_io_containers() {
	local status=$? id container_status=0
	for id in "${io_container_ids[@]}"; do
		remove_test_docker_container "${HUATUO_BAMAI_TEST_TMPDIR}" "${id}" || container_status=1
	done
	if ((container_status)); then
		status=1
	elif [[ ! -s ${IO_CONTAINER_CLEANUP_MARKER} ]]; then
		rm -f "${IO_CONTAINER_CLEANUP_MARKER}" || status=1
	fi
	huatuo_bamai_stop "${HUATUO_BAMAI_TEST_TMPDIR}" || status=1
	stop_iotracing_profile_fixture "${io_trigger_writer}" || status=1
	stop_iotracing_profile_fixture "${io_kubelet_pid}" || status=1
	exit "${status}"
}
trap cleanup_io_containers EXIT

prepare_io_docker() {
	io_docker_driver=$(DOCKER_API_VERSION="${IO_CONTAINER_DOCKER_API_VERSION}" \
		timeout --kill-after=2 10 docker info --format '{{.CgroupDriver}}') \
		|| skip "Docker daemon is unavailable or incompatible with bamai's default API ${IO_CONTAINER_DOCKER_API_VERSION}"
}

io_container_writing() {
	timeout --kill-after=2 5 docker exec "$1" test -s /work/data > /dev/null 2>&1
}

prepare_io_container_writers() {
	local name id pid hostname filesystem index prefix create_status create_error conflict
	local create_log="${HUATUO_BAMAI_TEST_TMPDIR}/docker-create.log"
	prefix="huatuo-io-${HUATUO_BAMAI_TEST_TMPDIR##*.}"
	for index in a b; do
		name="${prefix}-${index}"
		# Persist the unconfirmed name before the daemon can receive the request.
		printf '%s\n' "${name}" > "${IO_CONTAINER_CLEANUP_MARKER}.tmp"
		mv -f "${IO_CONTAINER_CLEANUP_MARKER}.tmp" "${IO_CONTAINER_CLEANUP_MARKER}"
		create_status=0
		id=$(timeout --foreground --kill-after=2 15 docker create --name "${name}" --label "${IO_CONTAINER_OWNER}" --pull never --network none \
			--mount type=volume,target=/work,volume-nocopy "${IO_CONTAINER_IMAGE}" awk '
				BEGIN {
					for (i = 0; i < 6000; i++) {
						printf "iotracing" > "/work/data"
						fflush("/work/data")
						system("sleep 0.02")
					}
				}
			' 2> "${create_log}") || create_status=$?
		if ((create_status != 0)); then
			create_error=$(< "${create_log}")
			conflict="Error response from daemon: Conflict. The container name \"/${name}\" is already in use by container "
			# Name reservation fails before creation. Leave ambiguous failures for runner recovery.
			if ((create_status == 1)) && [[ ${create_error} == "${conflict}"* && ${create_error} != *$'\n'* ]]; then
				: > "${IO_CONTAINER_CLEANUP_MARKER}" || log_error "cannot clear Docker create marker for ${name}"
			fi
			fatal "cannot create Docker IO writer ${name}${create_error:+: ${create_error}}"
		fi
		[[ ! -s ${create_log} ]] || cat "${create_log}" >&2
		[[ ${id} =~ ^[0-9a-f]{64}$ ]] || fatal "Docker did not return a full ID for IO writer ${name}"
		io_container_ids+=("${id}")
		: > "${IO_CONTAINER_CLEANUP_MARKER}"
		timeout --kill-after=2 15 docker start "${id}" > /dev/null || fatal "cannot start Docker IO writer ${name}"
		filesystem=$(timeout --kill-after=2 10 docker exec "${id}" awk '
			$5 == "/work" { for (i = 7; i < NF; i++) if ($i == "-") { print $(i + 1); exit } }
		' /proc/self/mountinfo) || fatal "cannot read Docker IO writer mount information"
		case ${filesystem} in
		ext4 | xfs) ;;
		"") fatal "Docker IO writer has no /work volume" ;;
		*) skip "Docker IO writer volume uses ${filesystem}; ext4 or XFS is required" ;;
		esac
		pid=$(timeout --kill-after=2 10 docker inspect --format '{{.State.Pid}}' "${id}")
		[[ ${pid} =~ ^[1-9][0-9]*$ ]] || fatal "Docker IO writer has no host PID: ${name}"
		io_container_pids+=("${pid}")
		hostname=$(timeout --kill-after=2 10 docker exec "${id}" hostname) \
			|| fatal "cannot read Docker IO writer hostname: ${name}"
		[[ -n ${hostname} ]] || fatal "Docker IO writer has an empty hostname: ${name}"
		io_container_hostnames+=("${hostname}")
		wait_until 5 0.1 io_container_writing "${id}" || fatal "Docker IO writer did not write: ${name}"
	done
}

assert_io_standalone_container_writers() {
	local report="${HUATUO_BAMAI_TEST_TMPDIR}/container-profile.json"
	[[ ${io_container_hostnames[0]} != "${io_container_hostnames[1]}" ]] \
		|| fatal "Docker IO writers need distinct hostnames to check PID attribution"
	timeout --kill-after=2 30 "${ROOT_DIR}/_output/bin/iotracing" \
		--bpf-path "${ROOT_DIR}/_output/bpf/iotracing.o" \
		--duration 1 --output json > "${report}" || fatal "standalone IO capture failed"
	jq -e --arg first "${io_container_pids[0]}" --arg second "${io_container_pids[1]}" \
		--arg first_hostname "${io_container_hostnames[0]}" --arg second_hostname "${io_container_hostnames[1]}" \
		--arg stack_warning "${IOTRACING_STACK_MAP_WARNING}" '
		(.io_profile_error | if type == "string" then test($stack_warning) else . == null end)
		and (.io_profile.profile as $p |
			[ $p.sample[]? | . as $sample |
				([$sample.label[]? | {key:$p.string_table[.key],value:$p.string_table[.str]}] | from_entries)
				+ {bytes:.value[0]} ] as $samples |
			all([[$first, $first_hostname], [$second, $second_hostname]][]; . as $writer |
				[$samples[] | select(.pid == $writer[0] and .direction == "write" and .bytes > 0)] |
				length > 0 and all(.[]; .attribution == "other" and .container_hostname == $writer[1])))
	' "${report}" > /dev/null || fatal "standalone IO capture lost a container writer or its hostname"
}

# Serve the actual runtime IDs to the normal PodManager path in isolation from
# the host kubelet. CSS resolution and collection use the real containers.
start_io_kubelet_fixture() {
	local directory="${HUATUO_BAMAI_TEST_TMPDIR}/kubelet"
	mkdir -p "${directory}"
	jq -n --arg first "${io_container_ids[0]}" --arg second "${io_container_ids[1]}" '
		{items: ([$first, $second] | to_entries | map(
			("io-writer-" + (.key | tostring)) as $name |
			{metadata: {name:$name, uid:$name, namespace:"integration"},
			 spec: {containers:[{name:"writer"}]},
			 status: {phase:"Running", qosClass:"BestEffort",
				containerStatuses:[{name:"writer", containerID:("docker://" + .value),
					state:{running:{startedAt:"2026-01-01T00:00:00Z"}}}]}}
		))}
	' > "${directory}/pods"
	jq -n --arg driver "${io_docker_driver}" '{kubeletconfig:{cgroupDriver:$driver}}' > "${directory}/configz"
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
		-keyout "${directory}/key.pem" -out "${directory}/cert.pem" > "${directory}/openssl.log" 2>&1 \
		|| fatal "cannot create the kubelet fixture certificate"
	python3 - "${directory}" > "${directory}/server.log" 2>&1 << 'PY' &
import http.server
import os
import ssl
import sys

class KubeletHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/pods", "/configz"):
            super().do_GET()
        else:
            self.send_error(404)


os.chdir(sys.argv[1])
with http.server.HTTPServer(("127.0.0.1", 0), KubeletHandler) as server:
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("cert.pem", "key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    with open("port", "w") as port:
        print(server.server_port, file=port)
    server.serve_forever()
PY
	io_kubelet_pid=$!
	wait_until 5 0.1 test -s "${directory}/port" || fatal "kubelet fixture did not start"
	io_kubelet_port=$(< "${directory}/port")
}

write_io_container_profile_config() {
	write_config_bamai_iotracing_profile
	write_config_bamai_kubelet "${io_kubelet_port}" \
		"${HUATUO_BAMAI_TEST_TMPDIR}/kubelet/cert.pem" "${HUATUO_BAMAI_TEST_TMPDIR}/kubelet/key.pem"
}

io_container_discovered() {
	curl -fsS "${CURL_TIMEOUT[@]}" -H 'Authorization: Bearer integration-node-token' \
		"${HUATUO_BAMAI_ADDR}/v1/containers/$1" > /dev/null
}

prepare_io_docker
timeout --kill-after=2 10 docker image inspect "${IO_CONTAINER_IMAGE}" > /dev/null 2>&1 \
	|| skip "local Docker image ${IO_CONTAINER_IMAGE} is unavailable"
prepare_iotracing_profile_trigger "${IO_TRIGGER_FIXTURE}"
prepare_io_container_writers
start_io_kubelet_fixture
# Container discovery still needs live procfs metadata when diskstats is replaced.
for pid in "${io_container_pids[@]}"; do
	ln -s "/proc/${pid}" "${IO_TRIGGER_FIXTURE}/proc/${pid}"
done

integration_huatuo_bamai_start write_io_container_profile_config \
	--region integration --procfs-prefix "${IO_TRIGGER_FIXTURE}" --log-debug
io_expected_containers=()
for index in "${!io_container_ids[@]}"; do
	id=${io_container_ids[index]}
	wait_until 15 0.2 io_container_discovered "${id}" || fatal "bamai did not discover Docker IO writer ${id}"
	io_expected_containers+=("${id}" "${io_container_pids[index]}")
done
start_iotracing_profile_trigger "${IO_TRIGGER_FIXTURE}"
# The detector takes two hot samples before it can start the bamai capture.
assert_io_standalone_container_writers
wait_until 50 0.2 assert_iotracing_profile_svg "${IO_TRIGGER_EVENT}" "${io_expected_containers[@]}" \
	|| fatal "IO event lacks one of the container writers or attributes it to the other container: ${IO_TRIGGER_EVENT}"
assert_iotracing_profile_logs "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "container IO trigger"
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp "${IO_TRIGGER_EVENT}" "${HUATUO_IO_ARTIFACT_DIR}/triggered-container-io-profile.json"
	cp "${HUATUO_BAMAI_TEST_TMPDIR}/container-profile.json" "${HUATUO_IO_ARTIFACT_DIR}/"
fi
