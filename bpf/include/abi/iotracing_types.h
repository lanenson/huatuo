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

#ifndef __BPF_ABI_IOTRACING_H__
#define __BPF_ABI_IOTRACING_H__

#include "bpf_abi.h"

struct iotracing_schedule_delay_event {
	u64 stack[PERF_MIN_STACK_DEPTH];
	u64 start_ns;
	u64 duration_ns;
	s32 stack_size;
	u32 tgid;
	u32 tid;
	u32 cpu;
	u8 comm[COMPAT_TASK_COMM_LEN];
};

BPF_ABI_EXPORT(iotracing_schedule_delay_event);

/* IO counters and periodic representative stacks have separate lifetimes. */
enum iotracing_profile_direction {
	IOTRACING_PROFILE_READ = 0,
	IOTRACING_PROFILE_WRITE,
	IOTRACING_PROFILE_DIRECTION_MAX,
};

enum iotracing_profile_sampling_mode {
	IOTRACING_PROFILE_SAMPLING_TIME = 1,
	IOTRACING_PROFILE_SAMPLING_COUNT,
};

enum iotracing_profile_result {
	IOTRACING_PROFILE_SUCCESS = 0,
	IOTRACING_PROFILE_EOF,
	IOTRACING_PROFILE_ZERO_LENGTH,
	IOTRACING_PROFILE_ZERO_RESULT,
	IOTRACING_PROFILE_ERROR,
	IOTRACING_PROFILE_RESULT_MAX,
};

struct iotracing_profile_group_key {
	/* Group leader boot-clock start; /proc/PID/stat exports this in ticks. */
	u64 process_start_ns;
	u64 css;
	u64 cgroup_id;
	u32 tgid;
	u32 direction;
};

struct iotracing_profile_key {
	struct iotracing_profile_group_key group;
	s32 user_stack;
	u32 result;
	u8 comm[COMPAT_TASK_COMM_LEN];
};

struct iotracing_profile_value {
	u64 bytes;
	u64 count;
	u64 duration_sum_ns;
};

struct iotracing_profile_pending {
	struct iotracing_profile_group_key group;
	u64 start_ns;
	u64 requested_bytes;
	u8 comm[COMPAT_TASK_COMM_LEN];
	u32 depth;
	u32 pad0;
};

struct iotracing_profile_process_key {
	u64 process_start_ns;
	u32 tgid;
	u32 pad0;
};

BPF_ABI_EXPORT(iotracing_profile_group_key);
BPF_ABI_EXPORT(iotracing_profile_key);
BPF_ABI_EXPORT(iotracing_profile_value);
BPF_ABI_EXPORT(iotracing_profile_pending);
BPF_ABI_EXPORT(iotracing_profile_process_key);
BPF_ABI_EXPORT_ENUM(iotracing_profile_direction);
BPF_ABI_EXPORT_ENUM(iotracing_profile_sampling_mode);
BPF_ABI_EXPORT_ENUM(iotracing_profile_result);

#endif /* __BPF_ABI_IOTRACING_H__ */
