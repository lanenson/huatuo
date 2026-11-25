/*
 * Copyright 2026 The HuaTuo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Share profile accounting between profile-only and combined iotracing. */
#ifndef __BPF_IO_PROFILE_H__
#define __BPF_IO_PROFILE_H__

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_dbg.h"
#include "bpf_map.h"
#include "bpf_cgroup.h"
#include "abi/iotracing_types.h"

enum {
	IO_STATE_MAX_ENTRIES = 32768,
	IO_AGGREGATE_MAX_ENTRIES = 4096,
	IO_PROFILE_STACK_MAP_ENTRIES = 16384,
};

/* Linux UAPI errno-base.h. */
#define IO_PROFILE_ENOMEM 12
#define IO_PROFILE_EEXIST 17

volatile const u32 io_profile_sampling_mode = IOTRACING_PROFILE_SAMPLING_TIME;
volatile const u64 io_profile_interval_ns = 1000000;
volatile const u64 io_profile_duration_ns = 0;
volatile const u64 io_profile_every = 0;
volatile const u32 io_profile_self_pid = 0;

struct io_representative {
	u64 last_count;
	u64 last_time_ns;
	s32 user_stack;
	u32 pad0;
};

struct task_struct___io_start {
	u64 start_boottime;
	u64 real_start_time;
} __attribute__((preserve_access_index));

/* A capture owns one fixed monotonic deadline; zero disables admission. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} io_profile_control SEC(".maps");

/* Stack IDs remain valid until the one-shot result has been built. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, IO_PROFILE_STACK_MAP_ENTRIES);
} stack_map_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct iotracing_profile_pending);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_inflight SEC(".maps");

/* This counter only coordinates count-mode refreshes, not exported totals. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct iotracing_profile_group_key);
	__type(value, u64);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_success_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct iotracing_profile_group_key);
	__type(value, struct io_representative);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_representatives SEC(".maps");

/* A claim lasts for one BPF invocation; contenders keep the old stack. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct iotracing_profile_group_key);
	__type(value, u8);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_refresh_claims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct iotracing_profile_key);
	__type(value, struct iotracing_profile_value);
	__uint(max_entries, IO_AGGREGATE_MAX_ENTRIES);
} io_counts SEC(".maps");

/* Hash insertion failures must not lose measurements already taken. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct iotracing_profile_value);
	__uint(max_entries, IOTRACING_PROFILE_DIRECTION_MAX * IOTRACING_PROFILE_RESULT_MAX);
} io_overflow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, IOTRACING_PROFILE_DROP_MAX);
} io_dropped SEC(".maps");

static __always_inline void io_count_drop(u32 counter)
{
	u64 *value;

	value = bpf_map_lookup_elem(&io_dropped, &counter);
	if (value)
		(*value)++;
}

static __always_inline void io_drop(void)
{
	io_count_drop(IOTRACING_PROFILE_DROP_COLLECTION);
}

static __always_inline bool io_process_identity(struct task_struct *task,
						 u64 *start_ns)
{
	struct task_struct___io_start *leader;
	int err;

	leader = (void *)BPF_CORE_READ(task, group_leader);
	if (!leader) {
		io_drop();
		return false;
	}
	/* Match /proc/PID/stat's boot clock despite the older field name. */
	if (bpf_core_field_exists(leader->start_boottime))
		err = BPF_CORE_READ_INTO(start_ns, leader, start_boottime);
	else
		err = BPF_CORE_READ_INTO(start_ns, leader, real_start_time);
	if (err) {
		io_drop();
		return false;
	}
	return true;
}

static __always_inline void io_aggregate(const struct iotracing_profile_pending *call,
						 s32 stack, u32 result, u64 bytes,
						 u64 duration_ns)
{
	struct iotracing_profile_key key = {};
	struct iotracing_profile_value zero = {};
	struct iotracing_profile_value *value;
	u32 bucket;

	key.group = call->group;
	key.user_stack = stack;
	key.result = result;
	__builtin_memcpy(key.comm, call->comm, sizeof(key.comm));

	value = bpf_map_lookup_elem(&io_counts, &key);
	if (!value) {
		/* Another CPU may create the key; its per-CPU value is independent. */
		bpf_map_update_elem(&io_counts, &key, &zero, BPF_NOEXIST);
		value = bpf_map_lookup_elem(&io_counts, &key);
	}
	if (!value) {
		bucket = key.group.direction * IOTRACING_PROFILE_RESULT_MAX + result;
		value = bpf_map_lookup_elem(&io_overflow, &bucket);
		if (!value) {
			io_drop();
			return;
		}
	}
	value->bytes += bytes;
	value->count++;
	value->duration_sum_ns += duration_ns;
}

static __always_inline bool io_refresh_due(const struct io_representative *rep,
					    u64 count, u64 now)
{
	u64 mark;

	if (!rep)
		return true;
	if (io_profile_sampling_mode == IOTRACING_PROFILE_SAMPLING_COUNT) {
		mark = rep->last_count;
		return count >= mark && count - mark >= io_profile_every;
	}
	mark = rep->last_time_ns;
	return now >= mark && now - mark >= io_profile_interval_ns;
}

static __always_inline s32 io_representative_stack(void *ctx,
						  const struct iotracing_profile_group_key *key,
						  u64 now)
{
	struct io_representative initial = { .user_stack = -1 };
	struct io_representative *rep;
	u64 count = 0;
	u64 zero = 0;
	u64 *counter;
	s32 stack;
	u8 claim = 1;

	if (io_profile_sampling_mode == IOTRACING_PROFILE_SAMPLING_COUNT) {
		counter = bpf_map_lookup_elem(&io_success_counts, key);
		if (!counter) {
			bpf_map_update_elem(&io_success_counts, key, &zero,
					    BPF_NOEXIST);
			counter = bpf_map_lookup_elem(&io_success_counts, key);
		}
		if (!counter)
			return -1;
		/* No returned atomic value: 4.18 only supports plain XADD. */
		__sync_fetch_and_add(counter, 1);
		count = *counter;
	}

	rep = bpf_map_lookup_elem(&io_representatives, key);
	stack = rep ? rep->user_stack : -1;
	if (!io_refresh_due(rep, count, now))
		return stack;

	if (bpf_map_update_elem(&io_refresh_claims, key, &claim, BPF_NOEXIST))
		return stack;

	/* A previous refresh may have published before this claim was acquired. */
	rep = bpf_map_lookup_elem(&io_representatives, key);
	if (!io_refresh_due(rep, count, now)) {
		stack = rep->user_stack;
		goto release;
	}
	if (!rep) {
		initial.last_count = count;
		initial.last_time_ns = now;
		bpf_map_update_elem(&io_representatives, key, &initial,
				    BPF_NOEXIST);
		rep = bpf_map_lookup_elem(&io_representatives, key);
		if (!rep)
			goto release;
	}

	stack = bpf_get_stackid(ctx, &stack_map_a, COMPAT_BPF_F_USER_STACK);
	if (stack < 0) {
		if (stack == -IO_PROFILE_EEXIST || stack == -IO_PROFILE_ENOMEM)
			io_count_drop(IOTRACING_PROFILE_DROP_STACK_MAP);
		stack = -1;
	}

	/*
	 * Only this claim's owner writes the fixed record. Readers may use either
	 * aligned stack ID during publication; refresh thresholds are approximate.
	 * A failed attempt also advances the selected threshold.
	 */
	rep->last_count = count;
	rep->last_time_ns = now;
	rep->user_stack = stack;

release:
	bpf_map_delete_elem(&io_refresh_claims, key);
	return stack;
}

/* Keep profile pending storage out of the legacy path-walk caller frame. */
static __noinline int io_profile_enter(struct pt_regs *ctx, u32 direction)
{
	struct iotracing_profile_pending call = {};
	struct iotracing_profile_pending *pending;
	struct task_struct *task;
	struct kiocb *iocb;
	u64 pid_tgid;
	u64 *deadline;
	u64 end_ns;
	u64 complete;
	u32 zero = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	/* Host profiles must not feed back symbol reads or profile output. */
	if (io_profile_self_pid && (pid_tgid >> 32) == io_profile_self_pid)
		return 0;
	deadline = bpf_map_lookup_elem(&io_profile_control, &zero);
	if (!deadline)
		return 0;
	end_ns = *deadline;
	call.start_ns = bpf_ktime_get_ns();
	if (!end_ns || call.start_ns >= end_ns ||
	    call.start_ns < end_ns - io_profile_duration_ns)
		return 0;
	pending = bpf_map_lookup_elem(&io_inflight, &pid_tgid);
	if (pending) {
		pending->depth++;
		return 0;
	}

	call.group.css = current_task_cpu_css_addr();
	iocb = (void *)PT_REGS_PARM1(ctx);
	if (!iocb || BPF_CORE_READ_INTO(&complete, iocb, ki_complete)) {
		io_drop();
		return 0;
	}
	if (complete)
		return 0;

	task = (void *)bpf_get_current_task();
	if (!io_process_identity(task, &call.group.process_start_ns))
		return 0;
	call.group.tgid = pid_tgid >> 32;
	call.group.direction = direction;
	call.group.cgroup_id = cgroup_id_from_css(call.group.css);
	bpf_get_current_comm(call.comm, sizeof(call.comm));
	if (bpf_map_update_elem(&io_inflight, &pid_tgid, &call, BPF_NOEXIST))
		io_drop();
	return 0;
}

SEC("kretprobe/ext4_file_read_iter")
int io_profile_return(struct pt_regs *ctx)
{
	struct iotracing_profile_pending *pending;
	struct iotracing_profile_pending call;
	u64 now = bpf_ktime_get_ns();
	u64 pid_tgid;
	u64 bytes = 0;
	s64 returned;
	s32 stack = -1;
	/* Keep zero-byte calls out of the byte-weighted unknown-stack frames. */
	u32 result = IOTRACING_PROFILE_ZERO_BYTES;
	u32 zero = 0;
	u64 *deadline;

	deadline = bpf_map_lookup_elem(&io_profile_control, &zero);
	if (!deadline || !*deadline || now >= *deadline)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&io_inflight, &pid_tgid);
	if (!pending)
		return 0;
	if (pending->depth) {
		pending->depth--;
		return 0;
	}
	call = *pending;
	bpf_map_delete_elem(&io_inflight, &pid_tgid);

	returned = PT_REGS_RC(ctx);
	if (returned > 0) {
		result = IOTRACING_PROFILE_SUCCESS;
		bytes = returned;
		stack = io_representative_stack(ctx, &call.group, now);
	} else if (returned < 0) {
		result = IOTRACING_PROFILE_ERROR;
	}

	io_aggregate(&call, stack, result, bytes, now - call.start_ns);
	return 0;
}

/* Inflight entries belong to threads; remove abandoned entries before TID reuse. */
SEC("raw_tracepoint/sched_process_exit")
int io_profile_exit(struct bpf_raw_tracepoint_args *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();

	if (bpf_map_lookup_elem(&io_inflight, &pid_tgid))
		bpf_map_delete_elem(&io_inflight, &pid_tgid);
	return 0;
}

#endif /* __BPF_IO_PROFILE_H__ */
