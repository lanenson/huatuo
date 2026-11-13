/*
 * Filesystem IO profiling measures every synchronous operation. Periodic
 * user stacks provide approximate attribution without sampling the counters.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_dbg.h"
#include "bpf_map.h"
#include "bpf_profiler.h"

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
	IO_STATE_MAX_ENTRIES = 32768,
	IO_AGGREGATE_MAX_ENTRIES = 4096,
	IO_EEXIST = 17,
};

volatile const u32 profiler_io_sampling_mode = PROFILER_IO_SAMPLING_TIME;
volatile const u64 profiler_io_interval_ns = 1000000;
volatile const u64 profiler_io_every = 0;
volatile const u32 profiler_io_self_pid = 0;

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
} profiler_io_control SEC(".maps");

/* Stack IDs remain valid until the one-shot result has been built. */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, STACK_MAP_ENTRIES);
} stack_map_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct profiler_io_pending);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_inflight SEC(".maps");

/* This counter only coordinates count-mode refreshes, not exported totals. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct profiler_io_group_key);
	__type(value, u64);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_success_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct profiler_io_group_key);
	__type(value, struct io_representative);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_representatives SEC(".maps");

/* A claim lasts for one BPF invocation; contenders keep the old stack. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct profiler_io_group_key);
	__type(value, u8);
	__uint(max_entries, IO_STATE_MAX_ENTRIES);
} io_refresh_claims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct profiler_io_key);
	__type(value, struct profiler_io_value);
	__uint(max_entries, IO_AGGREGATE_MAX_ENTRIES);
} io_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, PROFILER_IO_STAT_MAX);
} io_stats SEC(".maps");

static __always_inline void io_stat_inc(enum profiler_io_stat stat)
{
	u64 *value;

	value = bpf_map_lookup_elem(&io_stats, &stat);
	if (value)
		(*value)++;
}

static __always_inline bool io_process_identity(struct task_struct *task,
						 u64 *start_ns)
{
	struct task_struct___io_start *leader;
	int err;

	leader = (void *)BPF_CORE_READ(task, group_leader);
	if (!leader) {
		io_stat_inc(PROFILER_IO_STAT_IDENTITY_FAILURE);
		return false;
	}
	/* Match /proc/PID/stat's boot clock despite the older field name. */
	if (bpf_core_field_exists(leader->start_boottime))
		err = BPF_CORE_READ_INTO(start_ns, leader, start_boottime);
	else
		err = BPF_CORE_READ_INTO(start_ns, leader, real_start_time);
	if (err) {
		io_stat_inc(PROFILER_IO_STAT_IDENTITY_FAILURE);
		return false;
	}
	return true;
}

static __always_inline void io_aggregate_to(void *map,
					   const struct profiler_io_key *key,
					   u64 bytes, u64 duration_ns)
{
	struct profiler_io_value zero = {};
	struct profiler_io_value *value;

	value = bpf_map_lookup_elem(map, key);
	if (!value) {
		/* Another CPU may create the key; its per-CPU value is independent. */
		bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
		value = bpf_map_lookup_elem(map, key);
		if (!value) {
			io_stat_inc(PROFILER_IO_STAT_AGGREGATE_FAILURE);
			return;
		}
	}
	value->bytes += bytes;
	value->count++;
	value->duration_sum_ns += duration_ns;
}

static __always_inline void io_aggregate(const struct profiler_io_pending *call,
					 s32 stack, u32 result, u64 bytes,
					 u64 duration_ns)
{
	struct profiler_io_key key = {};

	key.group = call->group;
	key.user_stack = stack;
	key.result = result;
	__builtin_memcpy(key.comm, call->comm, sizeof(key.comm));
	io_aggregate_to(&io_counts, &key, bytes, duration_ns);
}

static __always_inline bool io_refresh_due(const struct io_representative *rep,
					    u64 count, u64 now)
{
	u64 mark;

	if (!rep)
		return true;
	if (profiler_io_sampling_mode == PROFILER_IO_SAMPLING_COUNT) {
		mark = rep->last_count;
		return count >= mark && count - mark >= profiler_io_every;
	}
	mark = rep->last_time_ns;
	return now >= mark && now - mark >= profiler_io_interval_ns;
}

static __always_inline s32 io_representative_stack(void *ctx,
						  const struct profiler_io_group_key *key,
						  u64 now)
{
	struct io_representative initial = { .user_stack = -1 };
	struct io_representative *rep;
	u64 count = 0;
	u64 zero = 0;
	u64 *counter;
	s32 stack;
	u8 claim = 1;
	int err;

	if (profiler_io_sampling_mode == PROFILER_IO_SAMPLING_COUNT) {
		counter = bpf_map_lookup_elem(&io_success_counts, key);
		if (!counter) {
			bpf_map_update_elem(&io_success_counts, key, &zero,
					    BPF_NOEXIST);
			counter = bpf_map_lookup_elem(&io_success_counts, key);
		}
		if (!counter) {
			io_stat_inc(PROFILER_IO_STAT_REFRESH_FAILURE);
			return -1;
		}
		/* No returned atomic value: 4.18 only supports plain XADD. */
		__sync_fetch_and_add(counter, 1);
		count = *counter;
	}

	rep = bpf_map_lookup_elem(&io_representatives, key);
	stack = rep ? rep->user_stack : -1;
	if (!io_refresh_due(rep, count, now))
		return stack;

	err = bpf_map_update_elem(&io_refresh_claims, key, &claim, BPF_NOEXIST);
	if (err) {
		if (err != -IO_EEXIST)
			io_stat_inc(PROFILER_IO_STAT_REFRESH_FAILURE);
		return stack;
	}

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
		if (!rep) {
			io_stat_inc(PROFILER_IO_STAT_REFRESH_FAILURE);
			goto release;
		}
	}

	io_stat_inc(PROFILER_IO_STAT_STACK_ATTEMPT);
	stack = bpf_get_stackid(ctx, &stack_map_a, USER_STACKID_FLAGS);
	if (stack < 0) {
		stack = -1;
		io_stat_inc(PROFILER_IO_STAT_STACK_FAILURE);
	} else {
		io_stat_inc(PROFILER_IO_STAT_STACK_SUCCESS);
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
	if (bpf_map_delete_elem(&io_refresh_claims, key))
		io_stat_inc(PROFILER_IO_STAT_REFRESH_FAILURE);
	return stack;
}

static __always_inline int io_enter(struct pt_regs *ctx, u32 direction)
{
	struct profiler_io_pending call = {};
	struct profiler_io_pending *pending;
	struct task_struct *task;
	struct iov_iter *iter;
	struct kiocb *iocb;
	u64 pid_tgid;
	u64 complete;
	u32 zero = 0;
	u64 *deadline;

	pid_tgid = bpf_get_current_pid_tgid();
	/* Host profiles must not feed back symbol reads or profile output. */
	if (profiler_io_self_pid && (pid_tgid >> 32) == profiler_io_self_pid)
		return 0;
	deadline = bpf_map_lookup_elem(&profiler_io_control, &zero);
	call.start_ns = bpf_ktime_get_ns();
	if (!deadline || !*deadline || call.start_ns >= *deadline)
		return 0;
	pending = bpf_map_lookup_elem(&io_inflight, &pid_tgid);
	if (pending) {
		pending->depth++;
		io_stat_inc(PROFILER_IO_STAT_NESTED_CALL);
		return 0;
	}

	call.group.css = current_task_cpu_css_addr();
	if (!profiler_should_trace(pid_tgid, call.group.css))
		return 0;

	iocb = (void *)PT_REGS_PARM1(ctx);
	iter = (void *)PT_REGS_PARM2(ctx);
	if (!iocb || !iter ||
	    BPF_CORE_READ_INTO(&complete, iocb, ki_complete) ||
	    BPF_CORE_READ_INTO(&call.requested_bytes, iter, count)) {
		io_stat_inc(PROFILER_IO_STAT_IDENTITY_FAILURE);
		return 0;
	}
	if (complete) {
		io_stat_inc(PROFILER_IO_STAT_ASYNC_SKIPPED);
		return 0;
	}

	task = (void *)bpf_get_current_task();
	if (!io_process_identity(task, &call.group.process_start_ns))
		return 0;

	call.group.tgid = pid_tgid >> 32;
	call.group.direction = direction;
	call.group.cgroup_id = cgroup_id_from_css(call.group.css);
	if (bpf_get_current_comm(call.comm, sizeof(call.comm)))
		io_stat_inc(PROFILER_IO_STAT_IDENTITY_FAILURE);
	if (bpf_map_update_elem(&io_inflight, &pid_tgid, &call, BPF_NOEXIST)) {
		io_stat_inc(PROFILER_IO_STAT_STATE_INSERT_FAILURE);
		return 0;
	}
	io_stat_inc(PROFILER_IO_STAT_ENTRY);
	return 0;
}

SEC("kprobe/ext4_file_read_iter")
int native_io_read_entry(struct pt_regs *ctx)
{
	return io_enter(ctx, PROFILER_IO_READ);
}

SEC("kprobe/ext4_file_write_iter")
int native_io_write_entry(struct pt_regs *ctx)
{
	return io_enter(ctx, PROFILER_IO_WRITE);
}

SEC("kretprobe/ext4_file_read_iter")
int native_io_return(struct pt_regs *ctx)
{
	struct profiler_io_pending *pending;
	struct profiler_io_pending call;
	u64 now = bpf_ktime_get_ns();
	u64 pid_tgid;
	u64 bytes = 0;
	s64 returned;
	s32 stack = -1;
	u32 result;
	u32 zero = 0;
	u64 *deadline;

	deadline = bpf_map_lookup_elem(&profiler_io_control, &zero);
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
	if (bpf_map_delete_elem(&io_inflight, &pid_tgid))
		io_stat_inc(PROFILER_IO_STAT_STATE_DELETE_FAILURE);

	returned = PT_REGS_RC(ctx);
	if (returned > 0) {
		result = PROFILER_IO_SUCCESS;
		bytes = returned;
		stack = io_representative_stack(ctx, &call.group, now);
	} else if (returned < 0) {
		result = PROFILER_IO_ERROR;
	} else if (!call.requested_bytes) {
		result = PROFILER_IO_ZERO_LENGTH;
	} else if (call.group.direction == PROFILER_IO_READ) {
		result = PROFILER_IO_EOF;
	} else {
		result = PROFILER_IO_ZERO_RESULT;
	}

	io_aggregate(&call, stack, result, bytes, now - call.start_ns);
	io_stat_inc(PROFILER_IO_STAT_COMPLETED);
	return 0;
}

/* Inflight entries belong to threads; remove abandoned entries before TID reuse. */
SEC("raw_tracepoint/sched_process_exit")
int native_io_exit(struct bpf_raw_tracepoint_args *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();

	if (bpf_map_lookup_elem(&io_inflight, &pid_tgid))
		if (bpf_map_delete_elem(&io_inflight, &pid_tgid))
			io_stat_inc(PROFILER_IO_STAT_STATE_DELETE_FAILURE);
	return 0;
}
