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

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/internal/log"
	"github.com/ccfos/huatuo/internal/process"
	"github.com/ccfos/huatuo/internal/symbol"
	"github.com/ccfos/huatuo/internal/timeutil"
	"github.com/ccfos/huatuo/internal/utils/bytesutil"
	"github.com/ccfos/huatuo/pkg/types"
)

type traceStopError struct {
	monotonicNS uint64
	cause       error
}

func (s traceStopError) Error() string { return s.cause.Error() }
func (s traceStopError) Unwrap() error { return s.cause }

// Record the stop before waking the perf reader, which may still be polling
// when the BPF deadline passes.
func traceContext(
	parent context.Context, signals <-chan os.Signal, timeout <-chan struct{},
) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	stop := func(cause error) {
		nowNS, err := timeutil.MonotonicNowNS()
		if err != nil {
			cancel(err)
			return
		}
		cancel(traceStopError{monotonicNS: nowNS, cause: cause})
	}
	if parent.Err() != nil {
		stop(context.Cause(parent))
		return ctx, cancel
	}
	go func() {
		cause := context.Canceled
		select {
		case <-parent.Done():
			cause = context.Cause(parent)
		case <-signals:
		case <-timeout:
		case <-ctx.Done():
			return
		}
		stop(cause)
	}()

	return ctx, cancel
}

// runTrace captures one diagnostic report and attaches an IO profile when available.
func runTrace(
	ctx context.Context,
	cfg ioConfig,
	filters map[string]any,
	options *ioProfileOptions,
	profileErr error,
) (*types.IOTracingSnapshot, error) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	timeout := make(chan struct{})
	captureCtx, cancel := traceContext(ctx, signals, timeout)
	defer cancel(nil)

	var object bpf.BPF
	var reader bpf.PerfEventReader
	var started, profileStarted time.Time
	var profileDeadlineNS uint64
	var captureWait time.Duration
	if profileErr == nil {
		profileErr = resolveIOProfileFilter(options)
	}
	if profileErr == nil {
		constants := options.config.BPFConstants()
		for key, value := range filters {
			constants[key] = value
		}
		object, reader, started, profileErr = prepareTrace(captureCtx, options.bpfPath, constants, true)
		if profileErr == nil {
			profileStarted, profileDeadlineNS, profileErr = ioprofile.Arm(object, options.config.Duration)
			if profileErr == nil {
				var nowNS uint64
				nowNS, profileErr = timeutil.MonotonicNowNS()
				captureWait = time.Duration(int64(profileDeadlineNS) - int64(nowNS))
			}
			if profileErr != nil {
				profileErr = errors.Join(profileErr, reader.Close(), object.Close())
			}
		}
	}
	if profileErr != nil {
		if err := captureCtx.Err(); err != nil {
			return nil, context.Cause(captureCtx)
		}
		var err error
		object, reader, started, err = prepareTrace(captureCtx, options.bpfPath, filters, false)
		if err != nil {
			return nil, err
		}
		captureWait = time.Duration(cfg.durationSecond) * time.Second
		profileDeadlineNS = 0
		options = nil
	}
	defer object.Close()
	defer reader.Close()
	timer := time.AfterFunc(captureWait, func() { close(timeout) })
	defer timer.Stop()

	snapshot, err := collectTraceReport(
		captureCtx,
		object,
		reader,
		cfg,
		options,
		started,
		profileStarted,
		profileDeadlineNS,
	)
	if snapshot != nil && profileErr != nil {
		snapshot.IOProfileError = profileErr.Error()
	}
	return snapshot, err
}

func prepareTrace(
	ctx context.Context,
	path string,
	filters map[string]any,
	withProfile bool,
) (bpf.BPF, bpf.PerfEventReader, time.Time, error) {
	object, err := loadIOTracingBPF(path, filters, withProfile)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("load iotracing BPF: %w", err)
	}

	// Existing probes can account IO as soon as they are attached.
	started := time.Now()
	reader, err := attachAndEventPipe(ctx, object)
	if err != nil {
		return nil, nil, time.Time{}, errors.Join(err, object.Close())
	}
	return object, reader, started, nil
}

// Detach before dumping so partial output includes a stable final IO snapshot.
func collectReport(b bpf.BPF, reader bpf.PerfEventReader, cfg ioConfig, started time.Time) (*types.IOTracingSnapshot, error) {
	stalls, collectErr := collectStalls(reader, cfg.maxStack)

	if err := b.Detach(); err != nil {
		return nil, fmt.Errorf("detach bpf: %w", err)
	}

	// The configured deadline is not the sample duration after an early exit.
	elapsed := time.Since(started)
	processes, err := dumpAndAggregate(b, cfg, elapsed)
	if err != nil {
		return nil, err
	}

	snapshot := &types.IOTracingSnapshot{Processes: processes, StallStacks: stalls}
	if collectErr != nil {
		snapshot.FailureReason = types.IOTracingFailureReader
	}
	return snapshot, collectErr
}

// collectStalls drains the iodelay perf reader until ctx cancellation
// and returns the most recent maxStack samples in chronological order.
// A ring buffer is used so that long traces don't lose the events that
// are usually most relevant for diagnosis — the ones closest to the end
// of the window.
func collectStalls(reader bpf.PerfEventReader, maxStack uint64) ([]types.IOScheduleEvent, error) {
	var (
		event   bpfScheduleDelay
		ring    []types.IOScheduleEvent
		readErr error
		head    uint64
		count   uint64
	)

	if maxStack > 0 {
		ring = make([]types.IOScheduleEvent, maxStack)
	}

	for {
		if err := reader.ReadInto(&event); err != nil {
			if errors.Is(err, bpf.ErrPerfEventSamplesLost) {
				log.WithError(err).Warn("lost BPF perf event samples")
				continue
			}
			if errors.Is(err, types.ErrExitByCancelCtx) {
				break
			}

			readErr = fmt.Errorf("read event: %w", err)
			break
		}

		if maxStack == 0 {
			continue
		}

		hostname, _ := process.Hostname(int(event.TGID))

		ring[head] = types.IOScheduleEvent{
			Comm:              bytesutil.ToStr(event.Comm[:]),
			ContainerHostname: hostname,
			PID:               event.TGID,
			TID:               event.TID,
			CPU:               event.CPU,
			ScheduleLatencyUS: event.DurationNS / 1000,
			Stack:             symbol.KsymStackStrs(event.Stack[:], symbol.KsymStackMinDepth),
		}

		head = (head + 1) % maxStack
		if count < maxStack {
			count++
		}
	}

	if count < maxStack {
		return ring[:count], readErr
	}

	// Buffer wrapped: head points to the oldest entry. Stitch
	// [head:] + [:head] so output stays oldest-to-newest.
	out := make([]types.IOScheduleEvent, 0, maxStack)
	out = append(out, ring[head:]...)
	out = append(out, ring[:head]...)

	return out, readErr
}

// dumpAndAggregate reads io_source_map after detach and reduces it into
// per-process stats, ordered by total block IO and capped by
// cfg.maxProcess / cfg.maxFilesPerProcess.
func dumpAndAggregate(b bpf.BPF, cfg ioConfig, elapsed time.Duration) ([]types.ProcessFileIOStats, error) {
	iodata, err := b.DumpMapByName(bpfSourceMapName)
	if err != nil {
		return nil, fmt.Errorf("dump %s: %w", bpfSourceMapName, err)
	}

	table := make(ProcessIOTable)

	for _, dataRaw := range iodata {
		var record bpfFilesystemIO

		if err := binary.Read(bytes.NewReader(dataRaw.Value), binary.LittleEndian, &record); err != nil {
			return nil, fmt.Errorf("decode %s entry: %w", bpfSourceMapName, err)
		}

		blkSize := record.BlockWriteBytes + record.BlockReadBytes
		table.Add(record.TGID, &fileEntry{Record: &record, Size: blkSize})
	}

	groups := table.TopN(int(cfg.maxProcess))

	processes := make([]types.ProcessFileIOStats, 0, len(groups))
	for _, g := range groups {
		processes = append(processes, buildProcessFileIOStats(g, cfg, elapsed))
	}

	return processes, nil
}
