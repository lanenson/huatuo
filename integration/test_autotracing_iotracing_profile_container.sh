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
readonly IO_CONTAINER_IMAGE=${NATIVE_PROFILER_DOCKER_IMAGE:-busybox:1.36.1}
io_trigger_device=()
io_trigger_writer=""
io_kubelet_pid=""
io_kubelet_port=""
io_docker_api=""
io_container_names=()
io_container_ids=()
io_container_pids=()

remove_io_container() {
	local name=$1 remaining
	if timeout --kill-after=2 15 docker rm -fv "${name}" >> "${HUATUO_BAMAI_TEST_TMPDIR}/docker-cleanup.log" 2>&1; then
		return 0
	fi
	if remaining=$(timeout --kill-after=2 10 docker ps -a --filter "name=^/${name}$" --quiet) && [[ -z ${remaining} ]]; then
		return 0
	fi
	log_error "cannot remove owned Docker IO writer ${name}; see docker-cleanup.log"
	return 1
}

cleanup_io_containers() {
	local status=$? name
	huatuo_bamai_stop "${HUATUO_BAMAI_TEST_TMPDIR}" || status=1
	stop_iotracing_profile_fixture "${io_trigger_writer}" || status=1
	stop_iotracing_profile_fixture "${io_kubelet_pid}" || status=1
	for name in "${io_container_names[@]}"; do
		remove_io_container "${name}" || status=1
	done
	exit "${status}"
}
trap cleanup_io_containers EXIT

select_io_docker_api() {
	local versions minimum maximum sdk_api minor
	versions=$(timeout --kill-after=2 10 docker version --format '{{.Server.MinAPIVersion}} {{.Server.APIVersion}}') \
		|| skip "Docker daemon is unavailable"
	read -r minimum maximum <<< "${versions}"
	sdk_api=$(awk -F'"' '/^[[:space:]]*DefaultVersion = / {print $2; exit}' \
		"${ROOT_DIR}/vendor/github.com/docker/docker/api/common.go")
	[[ ${minimum} =~ ^1\.[0-9]+$ && ${maximum} =~ ^1\.[0-9]+$ && ${sdk_api} =~ ^1\.[0-9]+$ ]] \
		|| fatal "invalid Docker API version range: daemon=${versions}, SDK=${sdk_api}"
	# Use the daemon minimum, up to the protocol version supported by bamai's SDK.
	minor=${minimum#1.}
	if ((minor < 24)); then minor=24; fi
	((minor <= ${maximum#1.} && minor <= ${sdk_api#1.})) \
		|| skip "Docker API range ${minimum}–${maximum} is incompatible with bamai SDK ${sdk_api}"
	io_docker_api="1.${minor}"
}

io_container_writing() {
	timeout --kill-after=2 5 docker exec "$1" test -s /work/data > /dev/null 2>&1
}

prepare_io_container_writers() {
	local name id pid filesystem index prefix
	prefix="huatuo-io-${HUATUO_BAMAI_TEST_TMPDIR##*.}"
	for index in a b; do
		name="${prefix}-${index}"
		# Register before create so a start timeout cannot leave an untracked writer.
		io_container_names+=("${name}")
		id=$(timeout --kill-after=2 15 docker create --name "${name}" --pull never --network none \
			--mount type=volume,target=/work,volume-nocopy "${IO_CONTAINER_IMAGE}" awk '
				BEGIN {
					for (i = 0; i < 6000; i++) {
						printf "iotracing" > "/work/data"
						fflush("/work/data")
						system("sleep 0.02")
					}
				}
			') || fatal "cannot create Docker IO writer ${name}"
		timeout --kill-after=2 15 docker start "${name}" > /dev/null || fatal "cannot start Docker IO writer ${name}"
		filesystem=$(timeout --kill-after=2 10 docker exec "${name}" awk '
			$5 == "/work" { for (i = 7; i < NF; i++) if ($i == "-") { print $(i + 1); exit } }
		' /proc/self/mountinfo) || fatal "cannot read Docker IO writer mount information"
		case ${filesystem} in
		ext4 | xfs) ;;
		"") fatal "Docker IO writer has no /work volume" ;;
		*) skip "Docker IO writer volume uses ${filesystem}; ext4 or XFS is required" ;;
		esac
		io_container_ids+=("${id}")
		pid=$(timeout --kill-after=2 10 docker inspect --format '{{.State.Pid}}' "${name}")
		[[ ${pid} =~ ^[1-9][0-9]*$ ]] || fatal "Docker IO writer has no host PID: ${name}"
		io_container_pids+=("${pid}")
		wait_until 5 0.1 io_container_writing "${name}" || fatal "Docker IO writer did not write: ${name}"
	done
}

assert_io_container_filter() {
	local report="${HUATUO_BAMAI_TEST_TMPDIR}/container-profile.json"
	timeout --kill-after=2 30 "${ROOT_DIR}/_output/bin/iotracing" \
		--bpf-path "${ROOT_DIR}/_output/bpf/iotracing.o" --container-id "${io_container_ids[0]}" \
		--duration 2 --output json > "${report}" || fatal "container IO capture failed"
	jq -e --arg target "${io_container_pids[0]}" --arg other "${io_container_pids[1]}" '
		.io_profile_error == null and (.io_profile.profile as $p |
			[ $p.sample[]? | . as $sample |
				([$sample.label[]? | {key:$p.string_table[.key],value:$p.string_table[.str]}] | from_entries)
				+ {bytes:.value[0]} ] as $samples |
			any($samples[]; .pid == $target and .direction == "write" and .bytes > 0)
			and all($samples[]; .pid != $other))
	' "${report}" > /dev/null || fatal "container filter lost the target writer or included the other writer"
}

# Serve the actual runtime IDs to the normal PodManager path in isolation from
# the host kubelet. CSS resolution and collection use the real containers.
start_io_kubelet_fixture() {
	local directory="${HUATUO_BAMAI_TEST_TMPDIR}/kubelet"
	local driver
	driver=$(timeout --kill-after=2 10 docker info --format '{{.CgroupDriver}}')
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
	jq -n --arg driver "${driver}" '{kubeletconfig:{cgroupDriver:$driver}}' > "${directory}/configz"
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
	printf '    DockerAPIVersion = "%s"\n' "${io_docker_api}"
}

io_container_discovered() {
	curl -fsS "${CURL_TIMEOUT[@]}" -H 'Authorization: Bearer integration-node-token' \
		"${HUATUO_BAMAI_ADDR}/v1/containers/$1" > /dev/null
}

select_io_docker_api
timeout --kill-after=2 10 docker image inspect "${IO_CONTAINER_IMAGE}" > /dev/null 2>&1 \
	|| skip "local Docker image ${IO_CONTAINER_IMAGE} is unavailable"
prepare_iotracing_profile_trigger "${IO_TRIGGER_FIXTURE}"
prepare_io_container_writers
assert_io_container_filter
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
wait_until 50 1 assert_iotracing_profile_svg "${IO_TRIGGER_EVENT}" "${io_expected_containers[@]}" \
	|| fatal "IO event lacks one of the container writers or attributes it to the other container: ${IO_TRIGGER_EVENT}"
assert_log_has_no_failure "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "container IO trigger"
if [[ -n ${HUATUO_IO_ARTIFACT_DIR:-} ]]; then
	mkdir -p "${HUATUO_IO_ARTIFACT_DIR}"
	cp "${IO_TRIGGER_EVENT}" "${HUATUO_IO_ARTIFACT_DIR}/triggered-container-io-profile.json"
	cp "${HUATUO_BAMAI_TEST_TMPDIR}/container-profile.json" "${HUATUO_IO_ARTIFACT_DIR}/"
fi
