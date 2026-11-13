---
title: profiler CLI Parameters
type: docs
author: HUATUO Team
date: 2026-10-21
weight: 6
---

This reference lists `profiler` parameters, defaults, and applicability. See [CLI Collection](/docs/best-practice/continuous-profiling_en.md#cli-collection) for prerequisites and examples, and [Output Formats](/docs/best-practice/continuous-profiling_en.md#output-formats) to choose a format.

Both `--output-path` and `--output-format` must be explicit. The declared default for `--output-format` is `collapsed`, but validation does not allow the flag to be omitted.

## General

| Parameter | Default | Applies To | Description |
| --- | --- | --- | --- |
| `--type`, `-t` | None | All | Observation type: `cpu`, `memory`, or `io`; required |
| `--language`, `-l` | None | All | Target language: `c`, `c++`, `go`, `java`, or `python`; required |
| `--pid`, `-p` | None | All | Target PID; Java and Python accept comma-separated PIDs, native collection accepts at most one |
| `--container-id` | None | All | Target container ID; native CPU and IO combine it with `--pid` as an AND filter using the host PID; otherwise mutually exclusive with `--pid` |
| `--duration`, `-d` | `10` | All | Total collection duration in seconds, minimum 1 |
| `--aggr-interval` | `10` | CPU/memory | Aggregation interval in seconds; cannot exceed duration |
| `--freq`, `-F` | `99` | CPU | Samples per second; Java maximum: 1000 |
| `--output-path` | Required | All | Local file, directory, or `stdout`; Unix socket for `remote-store`. End new directory paths with `/` |
| `--output-format` | `collapsed` | All | `collapsed`, `flamegraph`, `svg`, `json`, or `remote-store`; IO rejects `collapsed`; must be explicit together with `--output-path` |
| `--max-concurrent-procs` | `0` | Java, Python | Maximum concurrent collection child processes; `0` is unlimited |
| `--tool-path` | None | Java, Python | Shared root directory for external tools; required |
| `--binary-match-path` | None | Java, Python | Match target container processes by executable path |
| `--task-id` | Empty; generated internally for local output | All; required for `remote-store` | Stable collection task ID shared by toolstream and remote storage |
| `--enable-pprof` | `false` | The tool itself | Serve this process's Go runtime profiles on `127.0.0.1:6000` |
| `--version-format` | `text` | Version queries | Format for `--version`: `text`, `json`, or `short` |
| `--help`, `-h` | - | All | Show command help |
| `--version`, `-v` | - | All | Show version and build information |

These pprof endpoints describe the profiler process's own Go runtime, not the `--pid` target or Java/Python collector subprocesses. The listener is now restricted to loopback rather than all interfaces; an occupied port fails startup.

## Collection

Native on-CPU, memory, and IO collection require Linux `MEMBARRIER_CMD_GLOBAL` support (`CONFIG_MEMBARRIER` enabled and `NO_HZ_FULL` inactive). Buffer swaps depend on this command providing a sched-RCU grace period on Linux 4.18 and a unified RCU grace period on Linux 5.0 and later; expedited membarrier commands cannot replace it. An RCU stall can delay a swap and collection shutdown.


| Parameter | Default | Applies To | Description |
| --- | --- | --- | --- |
| `--memory-mode` | None | Native and Java memory | Memory measurement; required with `--type memory` |
| `--cpuid` | All CPUs | Native CPU | CPU list or ranges; off-CPU filtering uses the CPU where the task switches out |
| `--cpu-mode` | `oncpu` | Native CPU | `oncpu` samples by frequency; `offcpu` attributes blocked and runnable scheduling delays |
| `--io-stack-mode` | None | Native IO | `time` or `count`; required with `--type io`, selecting how representative user stacks are refreshed |
| `--io-stack-interval` | None | Native IO time | Required positive duration, such as `1ms`; mutually exclusive with `--io-stack-every`, including an explicit zero |
| `--io-stack-every` | None | Native IO count | Required positive operation count between representative-stack refreshes; mutually exclusive with `--io-stack-interval` |
| `--require-hardware-pmu` | `false` | Native on-CPU | Require hardware PMU sampling; fail if unavailable without falling back to software CPU clock |
| `--offcpu-phase` | `all` | Native off-CPU | Accumulate `all`, `blocked`, or `runqueue` time |
| `--offcpu-min-duration-us` | `1000` | Native off-CPU | Discard phases shorter than this duration in microseconds |
| `--offcpu-stats` | `false` | Native off-CPU | Collect BPF diagnostic statistics; adds overhead to error and cleanup paths |
| `--thread-group` | `false` for CPU/memory; always `true` for IO | Native | IO treats `--pid` as a process TGID and covers all its threads; explicitly setting `--thread-group=false` is rejected for IO |
| `--physical-memory-probability` | `100` | Native physical memory | Physical-memory event sampling probability from 1 to 100 |
| `--log-bpf-debug` | `false` | Native | Emit BPF debug events; not recommended for routine collection |

IO is a fixed-duration capture: no periodic output or `--aggr-interval`. It emits one joint-valued pprof/SVG after expiry; cancellation publishes nothing. Only calls starting and returning inside the capture window are counted.

IO supports synchronous ext4/XFS file reads and writes for `c`, `c++`, and `go`, with host, PID, and container filters.
The collector excludes its own file accesses so symbol reads and result output do not feed back into observed traffic.
IO output must use `svg`, `flamegraph`, `json`, or `remote-store`. Collapsed output has one weight and cannot combine bytes, counts, and durations.
Numerical counters cover observed calls; sampling controls only the representative user stack. Different call paths in one process and direction can share that stack.
Latency measures elapsed filesystem-function time, not disk wait time. Bytes describe logical file IO, not disk traffic.
Asynchronous IO, mmap accesses, standalone fsync operations, and Java/Python IO stacks are not covered.

Set `TARGET_PID` to the host PID, then collect representative stacks by operation count and produce a static SVG:

```bash
profiler --type io --language c --pid "${TARGET_PID}" \
  --io-stack-mode count --io-stack-every 100 \
  --duration 30 \
  --output-format svg --output-path io-profile.svg
```

For time-based sampling, replace the two sampling arguments with `--io-stack-mode time --io-stack-interval 1ms`.
On hosts without a kubelet, set both kubelet ports below to `0`; unattributed operations remain in host/other totals.

IO container attribution reuses the existing Pod manager. Standalone collection accepts these settings; bamai forwards its Pod configuration and preserves `--disable-kubelet`:

| Parameter | Default | Description |
| --- | --- | --- |
| `--kubelet-read-only-port` | `10255` | Kubelet read-only port; `0` disables this endpoint |
| `--kubelet-authorized-port` | `10250` | Kubelet authorized port; `0` disables this endpoint |
| `--kubelet-client-cert-path` | Empty | Existing kubelet client certificate path |
| `--docker-api-version` | `1.24` | Docker API version used by the Pod manager |

These discovery flags apply only to IO profiling. Ports must not exceed `65535`.

When the hardware PMU event or sampling is unsupported, the command exits with code `1` and identifies the error on stderr with `Error: hardware_pmu_unavailable:`. Permission and other startup errors do not use this marker.

## Logging

| Parameter | Default | Description |
| --- | --- | --- |
| `--log-level` | `error` | `trace`, `debug`, `info`, `warn`, or `error` |
| `--log-file` | `stdout` | Log file path or `stdout` |
| `--log-size` | `100` | Log rotation size in MB; `0` disables rotation. File output only |
| `--verbose` | `false` | Equivalent to `--log-level debug --log-file stdout`, overriding explicit log settings |
