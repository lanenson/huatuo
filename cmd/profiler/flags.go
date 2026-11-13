// Copyright 2025, 2026 The HuaTuo Authors
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

package main

import "github.com/urfave/cli/v2"

var appFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "type",
		Aliases: []string{"t"},
		Usage:   "Profiling type: cpu|memory|io",
	},
	&cli.StringFlag{
		Name:    "language",
		Aliases: []string{"l"},
		Usage:   "Target language: java|go|python|c|c++",
	},
	&cli.StringFlag{
		Name:  "memory-mode",
		Usage: "Memory mode; Java: object_alloc|object_usage; native: virtual_alloc|physical_alloc|physical_usage",
	},
	&cli.StringFlag{
		Name:    "pid",
		Aliases: []string{"p"},
		Usage:   "Target PID(s); native accepts one PID, IO uses a process TGID and all threads; Java/Python accept lists",
	},
	&cli.StringFlag{
		Name:  "cpuid",
		Usage: "CPU IDs to profile: comma-separated list and ranges (e.g., 1,3,5-10). Empty for all CPUs",
	},
	&cli.StringFlag{
		Name:  "cpu-mode",
		Usage: "Native CPU profiling mode: oncpu|offcpu",
		Value: "oncpu",
	},
	&cli.StringFlag{
		Name:  "io-stack-mode",
		Usage: "Native file IO representative-stack sampling: time|count; required for --type=io",
	},
	&cli.DurationFlag{
		Name:  "io-stack-interval",
		Usage: "Positive representative-stack interval for IO time mode (e.g. 1ms); excludes --io-stack-every",
	},
	&cli.Uint64Flag{
		Name:  "io-stack-every",
		Usage: "Positive operation count per representative stack for IO count mode; excludes --io-stack-interval",
	},
	&cli.UintFlag{
		Name:  "kubelet-read-only-port",
		Usage: "Kubelet read-only port for IO container metadata discovery; 0 disables this endpoint",
		Value: 10255,
	},
	&cli.UintFlag{
		Name:  "kubelet-authorized-port",
		Usage: "Kubelet authorized port for IO container metadata discovery; 0 disables this endpoint",
		Value: 10250,
	},
	&cli.StringFlag{
		Name:  "kubelet-client-cert-path",
		Usage: "Existing kubelet client certificate path for IO container metadata discovery",
	},
	&cli.StringFlag{
		Name:  "docker-api-version",
		Usage: "Docker API version used by IO container metadata discovery",
		Value: "1.24",
	},
	&cli.StringFlag{
		Name:  "offcpu-phase",
		Usage: "Off-CPU phase to attribute: all|blocked|runqueue",
		Value: "all",
	},
	&cli.Uint64Flag{
		Name:  "offcpu-min-duration-us",
		Usage: "Minimum off-CPU phase duration to record in microseconds",
		Value: 1000,
	},
	&cli.BoolFlag{
		Name:  "offcpu-stats",
		Usage: "Enable off-CPU diagnostics",
	},
	&cli.StringFlag{
		Name:  "container-id",
		Usage: "Target container ID",
	},
	&cli.BoolFlag{
		Name:  "thread-group",
		Usage: "Profile all threads in the target process; always enabled for IO, optional for native CPU/memory",
	},
	&cli.IntFlag{
		Name:    "freq",
		Aliases: []string{"F"},
		Usage:   "The number of samples to collect per second",
		Value:   99,
	},
	&cli.BoolFlag{
		Name:  "require-hardware-pmu",
		Usage: "Require native on-CPU profiling to use the hardware PMU",
	},
	&cli.UintFlag{
		Name:  "physical-memory-probability",
		Usage: "Native physical-memory sampling probability, from 1 to 100 percent",
		Value: 100,
	},
	&cli.IntFlag{
		Name:  "max-concurrent-procs",
		Usage: "Maximum concurrent profiler subprocesses; 0 means unlimited",
	},
	&cli.IntFlag{
		Name:  "aggr-interval",
		Usage: "interval for profiling of aggregate process",
		Value: 10,
	},
	&cli.IntFlag{
		Name:    "duration",
		Aliases: []string{"d"},
		Usage:   "Profiling duration in seconds",
		Value:   10,
	},
	&cli.StringFlag{
		Name:  "output-path",
		Usage: "Output path: file|directory|socket|stdout (WARNING: stdout may expose data)",
	},
	&cli.StringFlag{
		Name:  "output-format",
		Usage: "Output format: collapsed|flamegraph|svg|json|remote-store",
		Value: "collapsed",
	},
	&cli.StringFlag{
		Name:  "log-level",
		Usage: "Log level: trace|debug|info|warn|error",
		Value: "error",
	},
	&cli.StringFlag{
		Name:  "log-file",
		Usage: "Log output destination: file path for rotating logs, or \"stdout\" for standard output",
		Value: "stdout",
	},
	&cli.IntFlag{
		Name:  "log-size",
		Usage: "Log rotation size in MB; 0 disables rotation",
		Value: 100,
	},
	&cli.BoolFlag{
		Name:  "log-bpf-debug",
		Usage: "Log bpf_dbg events (native profiler only)",
	},
	&cli.BoolFlag{
		Name:  "verbose",
		Usage: "Shorthand for --log-level debug --log-file stdout; overrides explicit values of both flags",
	},
	&cli.BoolFlag{
		Name:  "enable-pprof",
		Usage: "Serve Go runtime profiles on port 6000",
	},
	&cli.StringFlag{
		Name:  "tool-path",
		Usage: "Tool directory containing bin/asprof and lib/libasyncProfiler.so for Java, or py-spy for Python",
	},
	&cli.StringFlag{
		Name:  "binary-match-path",
		Usage: "Binary path used to match target processes",
	},
	&cli.StringFlag{
		Name:  "task-id",
		Usage: "Profiling task ID; required for remote output, generated when empty for local output",
	},
}
