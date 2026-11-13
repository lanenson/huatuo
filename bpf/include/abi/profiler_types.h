// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __BPF_ABI_PROFILER_H__
#define __BPF_ABI_PROFILER_H__

#include "bpf_abi.h"

struct profiler_event_base {
	u64 pid_tgid;
	u8 comm[COMPAT_TASK_COMM_LEN];
	s32 kernstack;
	s32 userstack;
	s64 value;
};

struct profiler_oncpu_event {
	struct profiler_event_base base;
	/* Host CLOCK_MONOTONIC at observation; excludes system suspend. */
	u64 kernel_observed_ns;
	u32 cpu;
	u32 pad0;
};

enum profiler_offcpu_event_kind {
	PROFILER_OFFCPU_EVENT_UNKNOWN = 0,
	PROFILER_OFFCPU_EVENT_BLOCKED,
	PROFILER_OFFCPU_EVENT_RUNQUEUE,
	PROFILER_OFFCPU_EVENT_RUNQUEUE_PREEMPTED,
	PROFILER_OFFCPU_EVENT_RUNQUEUE_YIELDED,
	PROFILER_OFFCPU_EVENT_RUNQUEUE_MISSED_WAKEUP,
};

enum profiler_offcpu_stat {
	PROFILER_OFFCPU_STAT_STACK_FAILURE = 0,
	PROFILER_OFFCPU_STAT_STATE_UPDATE_FAILURE,
	PROFILER_OFFCPU_STAT_OUTPUT_FAILURE,
	PROFILER_OFFCPU_STAT_MISSED_WAKEUP,
	PROFILER_OFFCPU_STAT_STATE_CLEANUP,
	PROFILER_OFFCPU_STAT_MAX,
};

struct profiler_offcpu_event {
	struct profiler_event_base base;
	enum profiler_offcpu_event_kind kind;
	u32 pad0;
};

/* IO counters and periodic representative stacks have separate lifetimes. */
enum profiler_io_direction {
	PROFILER_IO_READ = 0,
	PROFILER_IO_WRITE,
};

enum profiler_io_sampling_mode {
	PROFILER_IO_SAMPLING_TIME = 1,
	PROFILER_IO_SAMPLING_COUNT,
};

enum profiler_io_result {
	PROFILER_IO_SUCCESS = 0,
	PROFILER_IO_EOF,
	PROFILER_IO_ZERO_LENGTH,
	PROFILER_IO_ZERO_RESULT,
	PROFILER_IO_ERROR,
};

enum profiler_io_stat {
	PROFILER_IO_STAT_ENTRY = 0,
	PROFILER_IO_STAT_COMPLETED,
	PROFILER_IO_STAT_ASYNC_SKIPPED,
	PROFILER_IO_STAT_STACK_ATTEMPT,
	PROFILER_IO_STAT_STACK_SUCCESS,
	PROFILER_IO_STAT_STACK_FAILURE,
	PROFILER_IO_STAT_STATE_INSERT_FAILURE,
	PROFILER_IO_STAT_STATE_DELETE_FAILURE,
	PROFILER_IO_STAT_AGGREGATE_FAILURE,
	PROFILER_IO_STAT_REFRESH_FAILURE,
	PROFILER_IO_STAT_NESTED_CALL,
	PROFILER_IO_STAT_IDENTITY_FAILURE,
	PROFILER_IO_STAT_MAX,
};

struct profiler_io_group_key {
	/* Group leader boot-clock start; /proc/PID/stat exports this in ticks. */
	u64 process_start_ns;
	u64 css;
	u64 cgroup_id;
	u32 tgid;
	u32 direction;
};

struct profiler_io_key {
	struct profiler_io_group_key group;
	s32 user_stack;
	u32 result;
	u8 comm[COMPAT_TASK_COMM_LEN];
};

struct profiler_io_value {
	u64 bytes;
	u64 count;
	u64 duration_sum_ns;
};

struct profiler_io_pending {
	struct profiler_io_group_key group;
	u64 start_ns;
	u64 requested_bytes;
	u8 comm[COMPAT_TASK_COMM_LEN];
	u32 depth;
	u32 pad0;
};

struct profiler_io_process_key {
	u64 process_start_ns;
	u32 tgid;
	u32 pad0;
};

BPF_ABI_EXPORT(profiler_event_base);
BPF_ABI_EXPORT(profiler_oncpu_event);
BPF_ABI_EXPORT(profiler_offcpu_event);
BPF_ABI_EXPORT_ENUM(profiler_offcpu_event_kind);
BPF_ABI_EXPORT_ENUM(profiler_offcpu_stat);
BPF_ABI_EXPORT(profiler_io_group_key);
BPF_ABI_EXPORT(profiler_io_key);
BPF_ABI_EXPORT(profiler_io_value);
BPF_ABI_EXPORT(profiler_io_pending);
BPF_ABI_EXPORT(profiler_io_process_key);
BPF_ABI_EXPORT_ENUM(profiler_io_direction);
BPF_ABI_EXPORT_ENUM(profiler_io_sampling_mode);
BPF_ABI_EXPORT_ENUM(profiler_io_result);
BPF_ABI_EXPORT_ENUM(profiler_io_stat);

#endif /* __BPF_ABI_PROFILER_H__ */
