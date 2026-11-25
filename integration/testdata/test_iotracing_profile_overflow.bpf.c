// Copyright 2026 The HuaTuo Authors.
// SPDX-License-Identifier: Apache-2.0

/* Restrict admission to one fixture so real IO overflow counters are exact. */
#include "vmlinux.h"
#include "bpf_common.h"
#include "io_profile.h"

static __always_inline int fixture_profile_enter(struct pt_regs *ctx,
						  u32 direction)
{
	if ((bpf_get_current_pid_tgid() >> 32) != IO_FIXTURE_TGID)
		return 0;
	return io_profile_enter(ctx, direction);
}

#define io_profile_enter fixture_profile_enter
#include "../../bpf/iotracing.c"
