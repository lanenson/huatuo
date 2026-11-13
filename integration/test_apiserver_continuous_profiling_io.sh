#!/usr/bin/env bash
# Copyright 2026 The HuaTuo Authors.
# SPDX-License-Identifier: Apache-2.0

# Exercise real IO Job authorization, publication and Elasticsearch queries.
# Seed classified rows after collection to test result grouping independently
# of kubelet discovery; native IO capture is covered by the profiler case.
set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_storage.sh"
source "${ROOT_DIR}/integration/config.sh"
source "${ROOT_DIR}/integration/lib_continuous_profiling.sh"

readonly API_TOKEN=integration-admin
readonly OTHER_API_TOKEN=integration-io-owner
readonly IO_RESULT_OTHER_TOKEN=integration-io-other
readonly PROFILE_INTERVAL=4
readonly IO_RESULT_INDEX=$(storage_test_index huatuo_continuous_profiling_test)
readonly IO_RESULT_CONTAINER=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

require_commands docker jq curl ss timeout
docker info > /dev/null 2>&1 || skip "docker daemon is unavailable"
APISERVER_PORT=$(allocate_available_port) || fatal "cannot allocate apiserver port"
readonly APISERVER_PORT
readonly APISERVER_ADDR="http://127.0.0.1:${APISERVER_PORT}"

PROFILE_ID=""
cleanup_io_results() {
	local status=$?
	trap - EXIT
	continuous_profiling_cleanup "${status}" || status=1
	# An external shared endpoint has no owned container to remove. Producers
	# have stopped, so delete only this case's unique index.
	if [[ ${STORAGE_SHARED} == true && -z ${STORAGE_CONTAINER_ID} && -n ${STORAGE_ADDR} ]]; then
		storage_curl --fail "${CURL_TIMEOUT[@]}" -X DELETE \
			"${STORAGE_ADDR}/${IO_RESULT_INDEX}?ignore_unavailable=true" \
			> "${HUATUO_BAMAI_TEST_TMPDIR}/io-index-cleanup.json" || status=1
	fi
	exit "${status}"
}
trap cleanup_io_results EXIT

assert_io_result_request() {
	local suffix=$1 expected=$2 token=$3 status curl_status=0
	local response="${HUATUO_BAMAI_TEST_TMPDIR}/io-result-${suffix//\//-}.response"
	local -a headers=()
	[[ -z ${token} ]] || headers=(-H "Authorization: Bearer ${token}")
	status=$(curl -sS "${CURL_TIMEOUT[@]}" "${headers[@]}" -o "${response}" -w '%{http_code}' \
		"${APISERVER_ADDR}/v1/profiling/${PROFILE_ID}/${suffix}") || curl_status=$?
	assert_eq "${curl_status}" 0 "IO result transport" || fatal "IO result curl failed"
	assert_eq "${status}" "${expected}" "IO result ${suffix}" \
		|| fatal "IO result status ${status}, expected ${expected}: $(< "${response}")"
}

assert_io_storage_request() {
	local expected=$1 name=$2 status
	shift 2
	status=$(storage_curl "${CURL_TIMEOUT[@]}" -o "${HUATUO_BAMAI_TEST_TMPDIR}/${name}.json" -w '%{http_code}' "$@") \
		|| fatal "IO storage ${name} request failed"
	assert_eq "${status}" "${expected}" "IO storage ${name}" \
		|| fatal "IO storage ${name}: $(< "${HUATUO_BAMAI_TEST_TMPDIR}/${name}.json")"
}
assert_io_group_totals() {
	jq -e --arg container "${IO_RESULT_CONTAINER}" '
	.data.groups as $groups |
	([$groups[] | select(.direction == "read" and .scope == "host")][0].root.stats) as $host |
	([$groups[] | select(.direction == "read" and .scope == "other")][0].root.stats) as $other |
	([$groups[] | select(.direction == "read" and .scope == "container" and .container_id == $container)][0]) as $container |
	$container.root.stats == {bytes:4096,count:1,duration_ns:1000000}
	and $container.container.hostname == "io-pod" and $other.bytes >= 4096
	and $host.bytes == ($other.bytes + $container.root.stats.bytes)
	and $host.count == ($other.count + $container.root.stats.count)
	and $host.duration_ns == ($other.duration_ns + $container.root.stats.duration_ns)
' "${HUATUO_BAMAI_TEST_TMPDIR}/io-result-io.response" > /dev/null || fatal "host omitted container/other rows"

}

assert_io_svg_panels() {
	grep -Fq 'READ / host' "${HUATUO_BAMAI_TEST_TMPDIR}/io-result-io-flamegraph.response" || fatal "SVG has no host panel"
	grep -Fq "READ / container / ${IO_RESULT_CONTAINER}" "${HUATUO_BAMAI_TEST_TMPDIR}/io-result-io-flamegraph.response" || fatal "SVG has no container panel"
}

assert_io_result_link() {
	jq -e --arg path "/v1/profiling/${PROFILE_ID}/io/flamegraph" '.data.result_url == $path' \
		"${HUATUO_BAMAI_TEST_TMPDIR}/io-status.json" > /dev/null || fatal "IO result link is not the authenticated SVG reference"
}

storage_start
readonly ES_PASSWORD=${STORAGE_PASSWORD:-huatuo-integration}
integration_huatuo_bamai_start write_config_bamai_continuous_profiling --region integration --disable-kubelet --log-debug
integration_huatuo_apiserver_start write_config_apiserver_io_results

io_status=$(curl -sS "${CURL_TIMEOUT[@]}" -o "${HUATUO_BAMAI_TEST_TMPDIR}/io-create.json" -w '%{http_code}' \
	-H "Authorization: Bearer ${OTHER_API_TOKEN}" -H 'Content-Type: application/json' \
	-X POST "${APISERVER_ADDR}/v1/profiling" \
	-d '{"hostname":"127.0.0.1","duration_seconds":4,"scope":"host","type":"io","language":"c","mode":"count","io_sample_every":100}') \
	|| fatal "create IO task request failed"
log_info "create IO task: $(< "${HUATUO_BAMAI_TEST_TMPDIR}/io-create.json")"
assert_eq "${io_status}" 201 "create IO task" || fatal "IO task creation failed"
PROFILE_ID=$(jq -er '.data.request_id' "${HUATUO_BAMAI_TEST_TMPDIR}/io-create.json")
wait_until 20 0.1 continuous_profile_status_is "${PROFILE_ID}" running "${HUATUO_BAMAI_TEST_TMPDIR}/io-status.json" \
	|| fatal "IO task did not enter running"
for io_suffix in io io/flamegraph; do
	assert_io_result_request "${io_suffix}" 409 "${OTHER_API_TOKEN}"
done
wait_until 90 1 continuous_profile_status_is "${PROFILE_ID}" completed "${HUATUO_BAMAI_TEST_TMPDIR}/io-status.json" \
	|| fatal "IO task did not publish a completed result"

assert_io_result_request raw 200 "${OTHER_API_TOKEN}"
io_source_hostname=$(jq -er '.data.items[0].hostname' "${HUATUO_BAMAI_TEST_TMPDIR}/io-result-raw.response")

# Add classified samples to the one complete capture. Kernel sampling and
# kubelet discovery are independently tested; this checks the real result path.
assert_io_storage_request 200 source -X POST "${STORAGE_ADDR}/${IO_RESULT_INDEX}/_search" -H 'Content-Type: application/json' \
	--data-binary "$(jq -nc --arg task "${PROFILE_ID}" '{size:2,query:{term:{"tracer_id.keyword":$task}}}')"
io_document_id=$(jq -er '.hits.hits | if length == 1 then .[0]._id else error("expected one capture") end' "${HUATUO_BAMAI_TEST_TMPDIR}/source.json")
jq --arg container "${IO_RESULT_CONTAINER}" '
 .hits.hits[0]._source |
 (.profile_data.profile.string_table | length) as $base |
 .profile_data.profile.string_table += ["kind","io","direction","read","attribution","container","other","result","success","container_id",$container,"container_hostname","io-pod","container_type","normal","container_qos","burstable"] |
 .profile_data.profile.sample += [
  {value:[4096,1,1000000,0],label:[{key:$base,str:($base+1)},{key:($base+2),str:($base+3)},{key:($base+4),str:($base+5)},{key:($base+7),str:($base+8)},{key:($base+9),str:($base+10)},{key:($base+11),str:($base+12)},{key:($base+13),str:($base+14)},{key:($base+15),str:($base+16)}]},
  {value:[4096,1,1000000,0],label:[{key:$base,str:($base+1)},{key:($base+2),str:($base+3)},{key:($base+4),str:($base+6)},{key:($base+7),str:($base+8)}]}]
' "${HUATUO_BAMAI_TEST_TMPDIR}/source.json" > "${HUATUO_BAMAI_TEST_TMPDIR}/io-capture.json"
assert_io_storage_request 200 seed -X PUT "${STORAGE_ADDR}/${IO_RESULT_INDEX}/_doc/${io_document_id}?refresh=true" \
	-H 'Content-Type: application/json' --data-binary "@${HUATUO_BAMAI_TEST_TMPDIR}/io-capture.json"

assert_io_result_request io 200 "${OTHER_API_TOKEN}"

assert_io_group_totals
assert_io_result_request io/flamegraph 200 "${OTHER_API_TOKEN}"
assert_io_svg_panels

for io_suffix in io io/flamegraph; do
	assert_io_result_request "${io_suffix}" 401 ""
	assert_io_result_request "${io_suffix}" 403 "${IO_RESULT_OTHER_TOKEN}"
	assert_io_result_request "${io_suffix}" 200 "${API_TOKEN}"
done

assert_io_storage_request 200 publication "${STORAGE_ADDR}/${IO_RESULT_INDEX}/_doc/profiling-publication:${PROFILE_ID}"
jq -c '._source' "${HUATUO_BAMAI_TEST_TMPDIR}/publication.json" > "${HUATUO_BAMAI_TEST_TMPDIR}/publication-source.json"
assert_io_storage_request 200 unpublish -X DELETE "${STORAGE_ADDR}/${IO_RESULT_INDEX}/_doc/profiling-publication:${PROFILE_ID}?refresh=true"
for io_suffix in io io/flamegraph; do
	assert_io_result_request "${io_suffix}" 404 "${OTHER_API_TOKEN}"
done
assert_io_storage_request 201 republish -X PUT "${STORAGE_ADDR}/${IO_RESULT_INDEX}/_doc/profiling-publication:${PROFILE_ID}?refresh=true" \
	-H 'Content-Type: application/json' --data-binary "@${HUATUO_BAMAI_TEST_TMPDIR}/publication-source.json"
for io_suffix in io io/flamegraph; do
	assert_io_result_request "${io_suffix}" 200 "${OTHER_API_TOKEN}"
done

assert_io_result_link
