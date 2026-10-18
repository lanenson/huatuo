#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
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

# Check disk selection and write authorization using isolated fixtures.
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
require_commands unshare mount mknod

unshare --mount --propagation private bash -s << 'FIXTURE'
set -euo pipefail
source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/lib_io.sh"
assert_io_disk_selection() {
    [[ ${io_test_disks[*]} == "$1" && ${io_test_disk_writable} == "$2" ]] \
        || fatal "unexpected disk selection: disks=${io_test_disks[*]} writable=${io_test_disk_writable}, expected $1/$2"
}

assert_io_disk_nonexclusive() {
    [[ ${TEST_IOLATENCY_IO_EXCLUSIVE} == 0 ]] || fatal "existing disk fallback was marked exclusive"
}

assert_io_disk_not_free() {
    ! io_test_disk_is_free "$1" || fatal "ineligible disk accepted as free: $1"
}

assert_io_fallback_cleanup() {
    [[ -b /dev/vda && -b /dev/vdb && -b /dev/sda ]] || fatal "cleanup removed an existing device"
    grep -q 'stage=released' "${HUATUO_BAMAI_TEST_TMPDIR}/io-disks.resources" || fatal "resource cleanup was not recorded"
}

fixture="${HUATUO_BAMAI_TEST_TMPDIR}/io-selection"
mkdir -p "${fixture}/bin"
cat > "${fixture}/bin/modinfo" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cat > "${fixture}/bin/modprobe" <<'EOF'
#!/usr/bin/env bash
printf 'unexpected module mutation\n' >&2
exit 1
EOF
cat > "${fixture}/bin/lsblk" <<'EOF'
#!/usr/bin/env bash
device=${!#}
cat "/sys/block/${device##*/}/mounted"
EOF
chmod +x "${fixture}/bin/"*
export PATH="${fixture}/bin:${PATH}"
mount -t tmpfs tmpfs /sys
mount -t tmpfs tmpfs /dev
mknod /dev/null c 1 3
for name in vda vdb sda; do
    mkdir -p "/sys/block/${name}/queue" "/sys/block/${name}/holders"
    printf '1\n' > "/sys/block/${name}/queue/iostats"
    printf '262144\n' > "/sys/block/${name}/size"
    printf '0 0\n' > "/sys/block/${name}/inflight"
    : > "/sys/block/${name}/mounted"
    mknod "/dev/${name}" b 240 0
done
printf '/\n' > /sys/block/vda/mounted
# The default-policy fixture must not inherit the caller's write permission.
unset TEST_IO_ALLOW_FREE_DISK_WRITES
io_test_prepare_disks 1
assert_io_disk_selection vdb 0
TEST_IO_ALLOW_FREE_DISK_WRITES=1 io_test_prepare_disks 1
assert_io_disk_selection vdb 1
assert_io_disk_nonexclusive
printf '1 0\n' > /sys/block/vdb/inflight
assert_io_disk_not_free vdb
printf '0 0\n' > /sys/block/vdb/inflight
mkdir /sys/block/vdb/holders/dm-0
assert_io_disk_not_free vdb
TEST_IO_ALLOW_FREE_DISK_WRITES=1 io_test_prepare_disks 1
assert_io_disk_selection sda 0
printf '/data\n' > /sys/block/sda/mounted
TEST_IO_ALLOW_FREE_DISK_WRITES=1 io_test_prepare_disks 1
assert_io_disk_selection vda 0
io_test_cleanup_disks
assert_io_fallback_cleanup
FIXTURE
log_info "IO disk selection, explicit write authorization and fallback cleanup passed"
