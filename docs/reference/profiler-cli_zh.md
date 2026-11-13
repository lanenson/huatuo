---
title: profiler 命令行参数
type: docs
author: HUATUO Team
date: 2026-10-21
weight: 6
---

本文列出 `profiler` 的参数、默认值和适用范围。构建条件与采集示例见[命令行采集](/docs/best-practice/continuous-profiling_zh.md#命令行采集)，格式选择见[输出格式](/docs/best-practice/continuous-profiling_zh.md#输出格式)。

`--output-path` 和 `--output-format` 都必须显式传入。`--output-format` 的声明默认值为 `collapsed`，但不能依靠该默认值省略参数。

## 通用参数

| 参数 | 默认值 | 适用范围 | 说明 |
| --- | --- | --- | --- |
| `--type`, `-t` | 无 | 全部 | 观测类型：`cpu`、`memory` 或 `io`，必填 |
| `--language`, `-l` | 无 | 全部 | 目标语言：`c`、`c++`、`go`、`java` 或 `python`，必填 |
| `--pid`, `-p` | 无 | 全部 | 目标 PID；Java、Python 可使用逗号分隔多个 PID，原生采集最多一个 PID |
| `--container-id` | 无 | 全部 | 目标容器 ID；原生 CPU、IO 采集可与 `--pid`（宿主机 PID）组合，两个过滤条件同时生效；其他采集类型与 `--pid` 互斥 |
| `--duration`, `-d` | `10` | 全部 | 总采集时长，单位为秒，最小为 1 |
| `--aggr-interval` | `10` | CPU／内存 | 聚合周期，单位为秒，不得大于采集时长 |
| `--freq`, `-F` | `99` | CPU | 每秒采样次数；Java 最大为 1000 |
| `--output-path` | 必填 | 全部 | 本地文件、目录或 `stdout`，`remote-store` 时为 Unix socket；新目录路径以 `/` 结尾 |
| `--output-format` | `collapsed` | 全部 | `collapsed`、`flamegraph`、`svg`、`json` 或 `remote-store`；IO 不接受 `collapsed`；必须与 `--output-path` 一起显式指定 |
| `--max-concurrent-procs` | `0` | Java、Python | 并发采集子进程上限；`0` 表示不限制 |
| `--tool-path` | 无 | Java、Python | 外部采集工具统一根目录，必填 |
| `--binary-match-path` | 无 | Java、Python | 按可执行文件路径匹配容器内目标进程 |
| `--task-id` | 空；本地输出时内部生成 | 全部；`remote-store` 必填 | toolstream 和远端存储共用的稳定采集任务 ID |
| `--enable-pprof` | `false` | 工具自身 | 在 `127.0.0.1:6000` 暴露工具自身的 Go runtime profile |
| `--version-format` | `text` | 版本查询 | `--version` 的输出格式：`text`、`json` 或 `short` |
| `--help`, `-h` | - | 全部 | 显示命令帮助 |
| `--version`, `-v` | - | 全部 | 显示版本与构建信息 |

这些 pprof 接口描述 profiler 进程自身的 Go runtime，不是 `--pid` 指定的目标或 Java/Python 采集子进程。监听范围由所有网卡收紧为 loopback；端口被占用时启动失败。

## 采集参数

原生 on-CPU、内存和 IO 采集要求内核支持 `MEMBARRIER_CMD_GLOBAL`（启用 `CONFIG_MEMBARRIER` 且未启用 full dynticks（`NO_HZ_FULL`）模式）。缓冲切换依赖该命令在 Linux 4.18 中提供 sched-RCU grace period、在 Linux 5.0 及之后提供统一 RCU grace period；不能替换为 expedited membarrier 命令。RCU stall 可能延迟切换和采集结束。


| 参数 | 默认值 | 适用范围 | 说明 |
| --- | --- | --- | --- |
| `--memory-mode` | 无 | 原生内存、Java 内存 | 内存观测维度；使用 `--type memory` 时必填 |
| `--cpuid` | 全部 CPU | 原生 CPU | CPU 列表或范围；off-CPU 样本按任务切出时所在 CPU 过滤 |
| `--cpu-mode` | `oncpu` | 原生 CPU | `oncpu` 按频率采样，`offcpu` 归因阻塞与可运行调度延迟 |
| `--io-stack-mode` | 无 | 原生 IO | `time` 或 `count`；使用 `--type io` 时必填，选择代表用户栈的更新方式 |
| `--io-stack-interval` | 无 | 原生 IO time | 必填正时长，例如 `1ms`；不得同时传入 `--io-stack-every`，即使另一参数为零 |
| `--io-stack-every` | 无 | 原生 IO count | 必填正整数；按成功读写操作次数更新代表栈，不得同时传入 `--io-stack-interval` |
| `--require-hardware-pmu` | `false` | 原生 on-CPU | 强制使用硬件 PMU 采样；不可用时失败，不回退软件 CPU clock |
| `--offcpu-phase` | `all` | 原生 off-CPU | 累计 `all`、`blocked` 或 `runqueue` 时间 |
| `--offcpu-min-duration-us` | `1000` | 原生 off-CPU | 丢弃持续时间小于该微秒数的阶段 |
| `--offcpu-stats` | `false` | 原生 off-CPU | 收集 BPF 诊断统计；错误和清理路径会产生额外开销 |
| `--thread-group` | CPU/内存为 `false`；IO 固定为 `true` | 原生 | IO 的 `--pid` 表示进程 TGID，并覆盖其全部线程；IO 不接受显式 `--thread-group=false` |
| `--physical-memory-probability` | `100` | 原生物理内存 | 物理内存事件采样概率，范围为 1～100 |
| `--log-bpf-debug` | `false` | 原生 | 输出 BPF 调试事件，常规采集不建议启用 |

IO 支持 `c`、`c++`、`go` 的 ext4/XFS 同步文件读写，支持整机、PID 和容器过滤。
IO 不记录 profiler 自身的文件访问，避免符号读取和结果输出再次进入被观测流量。
IO 输出须选 `svg`、`flamegraph`、`json` 或 `remote-store`；collapsed 只有单个权重，不能混合字节、次数和耗时。
IO 是固定时长的一次性采集，不接受 `--aggr-interval`，到期后只输出一份联合数值 pprof／SVG。采集期间不输出；中途取消不发布结果。
只计入采集窗口内开始且返回的调用，截止后返回的调用直接忽略。数值统计覆盖这些调用，采样参数只控制代表用户栈；同一进程和方向的多条调用路径可能共享代表栈。
耗时为文件函数经过时间，不等同于磁盘等待；字节数为逻辑读写量，不等同于磁盘流量。
当前不覆盖异步 IO、mmap 访问或独立 fsync 操作，也不支持 Java/Python IO 栈。短命进程退出后可能只能保留栈地址。

设置 `TARGET_PID` 为目标宿主机 PID 后，可按次数采栈并生成静态 SVG：

```bash
profiler --type io --language c --pid "${TARGET_PID}" \
  --io-stack-mode count --io-stack-every 100 \
  --duration 30 \
  --output-format svg --output-path io-profile.svg
```

按时间采栈时，将两个采样参数替换为 `--io-stack-mode time --io-stack-interval 1ms`。
主机没有 kubelet 时，可将下面两个 kubelet 端口都设为 `0`；未解析到容器的操作仍计入 host/other。

IO 容器归属复用已有 Pod manager。独立运行时可配置以下参数；由 bamai 启动时沿用其 Pod 配置，
并继承 `--disable-kubelet` 的禁用状态：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--kubelet-read-only-port` | `10255` | kubelet 只读端口，`0` 禁用此端点 |
| `--kubelet-authorized-port` | `10250` | kubelet 鉴权端口，`0` 禁用此端点 |
| `--kubelet-client-cert-path` | 空 | 既有 kubelet 客户端证书路径 |
| `--docker-api-version` | `1.24` | Pod manager 使用的 Docker API 版本 |

这些容器发现参数仅适用于 IO 采集；端口不得超过 `65535`。

硬件 PMU 事件或采样不受支持时，命令退出码为 `1`，标准错误以 `Error: hardware_pmu_unavailable:` 标识该错误；权限及其他启动错误不使用此标识。

## 日志参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--log-level` | `error` | `trace`、`debug`、`info`、`warn` 或 `error` |
| `--log-file` | `stdout` | 日志文件路径，或 `stdout` |
| `--log-size` | `100` | 日志轮转大小，单位 MB；`0` 表示不轮转，仅用于文件输出 |
| `--verbose` | `false` | 等价于 `--log-level debug --log-file stdout`，并覆盖显式日志设置 |
