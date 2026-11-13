// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/bpf/abi"
	"github.com/ccfos/huatuo/internal/cgroups/subsystem"
	"github.com/ccfos/huatuo/internal/log"
	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/internal/profiling/bpfmap"
	"github.com/ccfos/huatuo/internal/profiling/fileio"
	"github.com/ccfos/huatuo/internal/symbol"
	"github.com/ccfos/huatuo/pkg/profiling"
	"github.com/ccfos/huatuo/pkg/types"
)

// One capture owns its maps until probes detach and the final result is encoded.
//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/native_io_profiler.c -o $BPF_DIR/native_io_profiler.o

type ioNativeProfiler struct {
	config                Config
	bpf                   bpf.BPF
	stacks                nativeStackResolver
	windowStart           time.Time
	captureEnd            time.Time
	containerSubscription *pod.ContainerSubscription
	containers            map[pod.CgroupCSSRef]*types.ProfilingContainer
	containerKeys         map[pod.ContainerKey]pod.CgroupCSSRef
	processes             map[abi.ProfilerIOProcessKey]bool
	processSymbols        map[abi.ProfilerIOProcessKey]*symbol.UsymResolver
	stopDebug             func()
	isPodManagerStarted   bool
}

func (p *ioNativeProfiler) Start(ctx context.Context) (returnErr error) {
	if p.config.Duration <= 0 {
		return errors.New("file IO capture duration must be positive")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := validateNativePIDs("IO", p.config.PIDs); err != nil {
		return err
	}
	if p.config.Mode != profiling.ModeIOTime && p.config.Mode != profiling.ModeIOCount {
		return fmt.Errorf("unsupported IO stack sampling mode %q", p.config.Mode)
	}
	if (p.config.Mode == profiling.ModeIOTime && (p.config.IOSampleInterval <= 0 || p.config.IOSampleEvery != 0)) ||
		(p.config.Mode == profiling.ModeIOCount && (p.config.IOSampleEvery == 0 || p.config.IOSampleInterval != 0)) {
		return errors.New("file IO requires one positive sampling parameter matching time or count mode")
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, p.Stop())
		}
	}()
	if err := pod.InitManager(&p.config.PodManager); err != nil {
		return fmt.Errorf("initialize IO container metadata: %w", err)
	}
	p.isPodManagerStarted = true
	p.containers = make(map[pod.CgroupCSSRef]*types.ProfilingContainer)
	p.containerKeys = make(map[pod.ContainerKey]pod.CgroupCSSRef)
	subscription, err := pod.SubscribeContainers(ctx)
	if err == nil {
		p.containerSubscription = subscription
	} else if !errors.Is(err, pod.ErrContainerManagerDisabled) {
		return fmt.Errorf("subscribe IO container metadata: %w", err)
	}
	p.refreshContainers()
	cgroupRef, err := resolveContainerCgroupCSSRef(&p.config, subsystem.SubsystemCPU)
	if err != nil {
		return err
	}
	constants := newNativeBPFConstants(p.config.PID(), cgroupRef, true)
	mode := uint32(abi.ProfilerIOSamplingTime)
	if p.config.Mode == profiling.ModeIOCount {
		mode = uint32(abi.ProfilerIOSamplingCount)
	}
	constants["profiler_io_sampling_mode"] = mode
	constants["profiler_io_self_pid"] = uint32(os.Getpid())
	constants["profiler_io_interval_ns"] = uint64(p.config.IOSampleInterval)
	constants["profiler_io_every"] = p.config.IOSampleEvery
	dbg := bpf.NewDbg(p.config.LogBpfDebug)
	p.bpf, err = bpf.LoadBPF("native_io_profiler.o", dbg.WithBpfDbg(constants))
	if err != nil {
		return fmt.Errorf("load file IO profiler: %w", err)
	}
	p.stacks = nativeStackResolver{
		bpf:        p.bpf,
		stackMapID: p.bpf.MapIDByName("stack_map_a"),
	}
	options, err := nativeIOAttachOptions()
	if err != nil {
		return err
	}
	if err := p.bpf.AttachWithOptions(options); err != nil {
		return fmt.Errorf("attach file IO profiler: %w", err)
	}
	if dbg.Enabled() {
		p.stopDebug, err = dbg.StartDebugEventLoop(ctx, p.bpf, "bpf_dbg_events")
		if err != nil {
			return err
		}
	}
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return err
	}
	p.windowStart = time.Now()
	p.captureEnd = p.windowStart.Add(p.config.Duration)
	return p.setDeadline(uint64(monotonic.Nano()) + uint64(p.config.Duration))
}

func nativeIOAttachOptions() ([]bpf.AttachOption, error) {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return nil, fmt.Errorf("read supported filesystems: %w", err)
	}
	filesystems := strings.Fields(string(data))
	options := []bpf.AttachOption{}
	for _, filesystem := range []string{"ext4", "xfs"} {
		found := false
		for _, entry := range filesystems {
			if entry == filesystem {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		for _, direction := range []string{"read", "write"} {
			symbolName := filesystem + "_file_" + direction + "_iter"
			options = append(options,
				bpf.AttachOption{
					ProgramName: "native_io_" + direction + "_entry",
					Symbol:      symbolName,
				},
				bpf.AttachOption{
					ProgramName: "native_io_return",
					Symbol:      symbolName,
				},
			)
		}
	}
	if len(options) == 0 {
		return nil, errors.New("file IO profiling requires ext4 or xfs")
	}
	options = append(options, bpf.AttachOption{
		ProgramName: "native_io_exit",
		Symbol:      "sched_process_exit",
	})
	return options, nil
}

func (p *ioNativeProfiler) refreshContainers() {
	containers, err := pod.Containers()
	if err != nil {
		log.WithError(err).Debug("file IO container metadata unavailable")
		return
	}
	for id, container := range containers {
		instance, err := pod.ContainerRefByID(id)
		if err != nil {
			continue
		}
		css := container.CgroupCss[subsystem.SubsystemCPU]
		if known, ok := p.containerKeys[instance.Key]; ok && known.CSSAddr == css {
			continue
		}
		ref, err := pod.ContainerCSSBySubsys(id, subsystem.SubsystemCPU)
		if err != nil {
			continue
		}
		namespace, ok := container.Labels["HostNamespace"].(string)
		if !ok {
			continue
		}
		p.containers[ref] = &types.ProfilingContainer{
			ID:            id,
			Hostname:      container.Hostname,
			HostNamespace: namespace,
			Type:          container.Type.String(),
			QoS:           container.Qos.String(),
		}
		p.containerKeys[instance.Key] = ref
	}
}

func (p *ioNativeProfiler) setDeadline(deadline uint64) error {
	var key [4]byte
	value := binary.LittleEndian.AppendUint64(nil, deadline)
	return p.bpf.WriteMapItems(p.bpf.MapIDByName("profiler_io_control"), []bpf.MapItem{{
		Key:   key[:],
		Value: value,
	}})
}

func (p *ioNativeProfiler) capture(ctx context.Context) (data *types.ProfilingWindow, returnErr error) {
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, p.Stop()) }()
	log.Info("file IO capture ready")
	timer := time.NewTimer(time.Until(p.captureEnd))
	defer timer.Stop()
	var updates <-chan struct{}
	if p.containerSubscription != nil {
		updates = p.containerSubscription.Notify()
	}
collect:
	for {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-timer.C:
			break collect
		case _, ok := <-updates:
			if !ok {
				updates = nil
				continue
			}
			if _, err := p.containerSubscription.DrainEvents(); err != nil {
				log.WithError(err).Debug("file IO container update unavailable")
			}
			p.refreshContainers()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if err := p.bpf.Detach(); err != nil {
		return nil, fmt.Errorf("stop file IO capture: %w", err)
	}
	p.refreshContainers()
	p.processes = make(map[abi.ProfilerIOProcessKey]bool)
	p.processSymbols = make(map[abi.ProfilerIOProcessKey]*symbol.UsymResolver)
	builder := fileio.NewBuilder(p.windowStart.UnixNano(), p.config.Duration.Nanoseconds())
	items, err := p.bpf.DumpMapByName("io_counts")
	if err != nil {
		return nil, fmt.Errorf("read file IO capture: %w", err)
	}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, context.Cause(ctx)
		}
		var key abi.ProfilerIOKey
		if _, err := binary.Decode(item.Key, binary.NativeEndian, &key); err != nil {
			return nil, err
		}
		value, err := sumIOPerCPU(item.Value)
		if err != nil {
			return nil, err
		}
		if value.Count == 0 {
			continue
		}
		if err := p.appendIORecord(builder, &key, &value); err != nil {
			return nil, err
		}
	}
	stats, err := p.bpf.DumpMapByName("io_stats")
	if err != nil {
		return nil, err
	}
	for _, item := range stats {
		if len(item.Key) != 4 || len(item.Value)%8 != 0 {
			return nil, errors.New("invalid file IO diagnostic layout")
		}
		var total uint64
		for offset := 0; offset < len(item.Value); offset += 8 {
			value := binary.NativeEndian.Uint64(item.Value[offset : offset+8])
			if value > math.MaxInt64-total {
				return nil, errors.New("file IO diagnostic counter overflow")
			}
			total += value
		}
		if err := builder.AddDiagnostic(ioStatName(binary.NativeEndian.Uint32(item.Key)), int64(total)); err != nil {
			return nil, err
		}
	}
	profile, err := builder.Profile(ctx)
	if err != nil {
		return nil, err
	}
	return &types.ProfilingWindow{
		ProfileType: fileio.ProfileType,
		Profile:     profile,
	}, nil
}

func (p *ioNativeProfiler) appendIORecord(builder *fileio.Builder, key *abi.ProfilerIOKey, value *abi.ProfilerIOValue) error {
	direction := fileio.DirectionRead
	if key.Group.Direction == uint32(abi.ProfilerIOWrite) {
		direction = fileio.DirectionWrite
	} else if key.Group.Direction != uint32(abi.ProfilerIORead) {
		return fmt.Errorf("invalid file IO direction %d", key.Group.Direction)
	}
	result, err := ioResultName(key.Result)
	if err != nil {
		return err
	}
	labels := append(nativeProcessLabels(key.Group.TGID, taskCommString(key.Comm)),
		types.ProfileStringLabel("direction", direction),
		types.ProfileStringLabel("result", result),
		types.ProfileStringLabel("process_start_ns", fmt.Sprint(key.Group.ProcessStartNS)),
		types.ProfileStringLabel("io_stack_mode", string(p.config.Mode)))
	if container := p.containers[pod.CgroupCSSRef{
		CSSAddr:  key.Group.CSS,
		CgroupID: key.Group.CgroupID,
	}]; container != nil {
		labels = append(labels, types.ProfileStringLabel("attribution", fileio.ScopeContainer), types.ProfileStringLabel("container_id", container.ID),
			types.ProfileStringLabel("container_hostname", container.Hostname), types.ProfileStringLabel("container_host_namespace", container.HostNamespace),
			types.ProfileStringLabel("container_type", container.Type), types.ProfileStringLabel("container_qos", container.QoS))
	} else {
		labels = append(labels, types.ProfileStringLabel("attribution", fileio.ScopeOther))
	}
	if p.config.Mode == profiling.ModeIOTime {
		labels = append(labels, types.ProfileStringLabel("io_stack_interval_ns", fmt.Sprint(p.config.IOSampleInterval.Nanoseconds())))
	} else {
		labels = append(labels, types.ProfileStringLabel("io_stack_every", fmt.Sprint(p.config.IOSampleEvery)))
	}
	frames, err := p.resolveIOFrames(key)
	if err != nil && !errors.Is(err, bpfmap.ErrStackNotFound) {
		return err
	}
	return builder.Add(frames, labels, fileio.Stats{
		Bytes:      int64(value.Bytes),
		Count:      int64(value.Count),
		DurationNS: int64(value.DurationSumNS),
	})
}

func sumIOPerCPU(raw []byte) (abi.ProfilerIOValue, error) {
	var total abi.ProfilerIOValue
	size := binary.Size(total)
	stride := (size + 7) &^ 7
	if len(raw)%stride != 0 {
		return total, fmt.Errorf("invalid file IO per-CPU value size %d", len(raw))
	}
	for offset := 0; offset < len(raw); offset += stride {
		var value abi.ProfilerIOValue
		if _, err := binary.Decode(raw[offset:offset+size], binary.NativeEndian, &value); err != nil {
			return total, err
		}
		if value.Bytes > math.MaxInt64-total.Bytes || value.Count > math.MaxInt64-total.Count ||
			value.DurationSumNS > math.MaxInt64-total.DurationSumNS {
			return total, errors.New("file IO counters exceed int64 capacity")
		}
		total.Bytes += value.Bytes
		total.Count += value.Count
		total.DurationSumNS += value.DurationSumNS
	}
	return total, nil
}

func (p *ioNativeProfiler) resolveIOFrames(key *abi.ProfilerIOKey) ([]types.ProfileFrame, error) {
	if key.UserStack < 0 {
		return nil, nil
	}

	identity := abi.ProfilerIOProcessKey{
		ProcessStartNS: key.Group.ProcessStartNS,
		TGID:           key.Group.TGID,
	}
	isCurrent, ok := p.processes[identity]
	if !ok {
		proc, err := procfs.NewProc(int(identity.TGID))
		if err == nil {
			stat, statErr := proc.Stat()
			// /proc uses Linux USER_HZ, also used by procfs on supported architectures.
			isCurrent = statErr == nil && stat.Starttime == identity.ProcessStartNS/uint64(time.Second/100)
		}
		p.processes[identity] = isCurrent
	}
	if isCurrent {
		resolver := p.processSymbols[identity]
		if resolver == nil {
			resolver = symbol.NewUsymResolver()
			p.processSymbols[identity] = resolver
		}
		stacks := p.stacks
		stacks.usym = resolver
		return stacks.resolveUserFrames(key.UserStack, key.Group.TGID)
	}
	trace, err := bpfmap.ReadStackTrace(p.bpf, p.stacks.stackMapID, uint32(key.UserStack))
	if err != nil {
		return nil, err
	}
	frames := []types.ProfileFrame{}
	for _, address := range &trace {
		if address == 0 {
			break
		}
		frames = append(frames, types.ProfileFrame{Name: fmt.Sprintf("0x%x", address)})
	}
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	return frames, nil
}

func ioResultName(result uint32) (string, error) {
	switch result {
	case uint32(abi.ProfilerIOSuccess):
		return "success", nil
	case uint32(abi.ProfilerIOEof):
		return "eof", nil
	case uint32(abi.ProfilerIOZeroLength):
		return "zero_length", nil
	case uint32(abi.ProfilerIOZeroResult):
		return "zero_result", nil
	case uint32(abi.ProfilerIOError):
		return "error", nil
	default:
		return "", fmt.Errorf("invalid file IO result %d", result)
	}
}

func ioStatName(stat uint32) string {
	switch stat {
	case uint32(abi.ProfilerIOStatEntry):
		return "entry"
	case uint32(abi.ProfilerIOStatCompleted):
		return "completed"
	case uint32(abi.ProfilerIOStatAsyncSkipped):
		return "async_skipped"
	case uint32(abi.ProfilerIOStatStackAttempt):
		return "stack_attempt"
	case uint32(abi.ProfilerIOStatStackSuccess):
		return "stack_success"
	case uint32(abi.ProfilerIOStatStackFailure):
		return "stack_failure"
	case uint32(abi.ProfilerIOStatStateInsertFailure):
		return "state_insert_failure"
	case uint32(abi.ProfilerIOStatStateDeleteFailure):
		return "state_delete_failure"
	case uint32(abi.ProfilerIOStatAggregateFailure):
		return "aggregate_failure"
	case uint32(abi.ProfilerIOStatRefreshFailure):
		return "refresh_failure"
	case uint32(abi.ProfilerIOStatNestedCall):
		return "nested_call"
	case uint32(abi.ProfilerIOStatIdentityFailure):
		return "identity_failure"
	default:
		return fmt.Sprintf("unknown_%d", stat)
	}
}

func (p *ioNativeProfiler) Stop() error {
	if p.stopDebug != nil {
		p.stopDebug()
		p.stopDebug = nil
	}
	err := closeBPF(p.bpf)
	p.bpf = nil
	if p.containerSubscription != nil {
		p.containerSubscription.Close()
		p.containerSubscription = nil
	}
	if p.isPodManagerStarted {
		pod.ReleaseManager()
		p.isPodManagerStarted = false
	}
	return err
}
