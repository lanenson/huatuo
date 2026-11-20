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

// Optional profiling owns its maps and final processing. The original report
// is frozen first so symbols, hostnames and SVG output cannot change its rates.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"
	"google.golang.org/protobuf/proto"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/cgroups/subsystem"
	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/internal/profiling/formatter/flamegraph"
	"github.com/ccfos/huatuo/pkg/types"
)

const (
	cliFlagIOProfileSVG            = "io-profile-svg"
	cliFlagIOStackMode             = "io-stack-mode"
	cliFlagIOStackInterval         = "io-stack-interval"
	cliFlagIOStackEvery            = "io-stack-every"
	cliFlagProfilePID              = "pid"
	cliFlagProfileContainerID      = "container-id"
	ioProfileCombinedOutputTimeout = 5 * time.Second
	maxIOProfileBytes              = 64 << 20
	maxCombinedReportBytes         = 63 << 20
)

type ioProfileOptions struct {
	config      ioprofile.Config
	bpfPath     string
	svgPath     string
	containerID string
	isLocal     bool
}

func ioProfileFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  cliFlagIOProfileSVG,
			Usage: "write the local IO profile SVG to this file",
		},
		&cli.StringFlag{
			Name:  cliFlagIOStackMode,
			Value: string(ioprofile.ModeCount),
			Usage: "profile stack sampling mode: io_time or io_count",
		},
		&cli.DurationFlag{
			Name:  cliFlagIOStackInterval,
			Usage: "io_time refresh interval; default 1ms, excludes --io-stack-every",
		},
		&cli.Uint64Flag{
			Name:  cliFlagIOStackEvery,
			Usage: "io_count operations per stack; default 100, excludes --io-stack-interval",
		},
		&cli.IntFlag{
			Name:  cliFlagProfilePID,
			Usage: "profile this process and its threads; diagnostics retain their device filter",
		},
		&cli.StringFlag{
			Name:  cliFlagProfileContainerID,
			Usage: "profile this container using local cgroup identity",
		},
	}
}

func validateIOProfileFlags(c *cli.Context) error {
	if c.String(cliFlagIOProfileSVG) != "" {
		if c.String(cliFlagOutputStorage) != "" {
			return errors.New("--io-profile-svg is local output; it cannot be used with --output-storage")
		}
		if c.String(cliFlagIOProfileSVG) == "-" {
			return errors.New("--io-profile-svg requires a file path; stdout is reserved for the report")
		}
	}
	return nil
}

func loadIOProfileOptions(c *cli.Context, duration uint64) (ioProfileOptions, error) {
	options := ioProfileOptions{
		bpfPath:     c.String(cliFlagBpfPath),
		isLocal:     c.String(cliFlagOutputStorage) == "",
		svgPath:     c.String(cliFlagIOProfileSVG),
		containerID: c.String(cliFlagProfileContainerID),
	}
	if duration > uint64(math.MaxInt64/int64(time.Second)) {
		return options, errors.New("IO profile duration exceeds the supported duration")
	}
	if c.IsSet(cliFlagProfilePID) && c.Int(cliFlagProfilePID) <= 0 {
		return options, errors.New("--pid must be positive when specified")
	}
	if c.IsSet(cliFlagIOStackInterval) && c.IsSet(cliFlagIOStackEvery) {
		return options, errors.New("--io-stack-interval and --io-stack-every are mutually exclusive")
	}
	options.config = ioprofile.Config{
		PID:      c.Int(cliFlagProfilePID),
		Duration: time.Duration(duration) * time.Second,
		Mode:     ioprofile.SamplingMode(c.String(cliFlagIOStackMode)),
		Interval: c.Duration(cliFlagIOStackInterval),
		Every:    c.Uint64(cliFlagIOStackEvery),
	}
	switch options.config.Mode {
	case ioprofile.ModeTime:
		if c.IsSet(cliFlagIOStackEvery) {
			return options, errors.New("io_time excludes --io-stack-every")
		}
		if !c.IsSet(cliFlagIOStackInterval) {
			options.config.Interval = ioprofile.DefaultStackInterval
		}
	case ioprofile.ModeCount:
		if c.IsSet(cliFlagIOStackInterval) {
			return options, errors.New("io_count excludes --io-stack-interval")
		}
		if !c.IsSet(cliFlagIOStackEvery) {
			options.config.Every = ioprofile.DefaultStackEvery
		}
	}
	if err := options.config.Validate(); err != nil {
		return options, err
	}
	return options, nil
}

func resolveIOProfileFilter(options *ioProfileOptions) error {
	if options.config.PID > 0 {
		ticks, err := ioprofile.ProcessStartTicks(options.config.PID)
		if err != nil {
			return fmt.Errorf("profile PID %d is unavailable: %w", options.config.PID, err)
		}
		options.config.PIDStartTicks = ticks
	}
	if options.containerID == "" {
		return nil
	}
	dir, err := filepath.Abs(filepath.Dir(options.bpfPath))
	if err != nil {
		return fmt.Errorf("resolve IO profile BPF directory: %w", err)
	}
	bpf.DefaultObjDir = dir
	ref, err := pod.ContainerCSSBySubsys(options.containerID, subsystem.SubsystemCPU)
	if err != nil {
		return fmt.Errorf("resolve profile container %q locally: %w", options.containerID, err)
	}
	options.config.CSSAddr, options.config.CgroupID = ref.CSSAddr, ref.CgroupID
	return nil
}

func collectTraceReport(
	ctx context.Context,
	object bpf.BPF,
	reader bpf.PerfEventReader,
	cfg ioConfig,
	options *ioProfileOptions,
	started time.Time,
	profileStarted time.Time,
	profileDeadlineNS uint64,
) (*types.IOTracingSnapshot, error) {
	fmt.Fprintln(os.Stderr, "iotracing: capture ready")

	snapshot, traceErr := collectReport(object, reader, cfg, started)
	if snapshot == nil || options == nil {
		return snapshot, traceErr
	}
	// A failed reader can stop probes before the timer while the legacy dump
	// crosses its deadline. Its profile may cover only a partial window.
	if traceErr != nil {
		snapshot.IOProfileError = fmt.Sprintf("IO profile stopped after diagnostic collection failed: %v", traceErr)
		return snapshot, traceErr
	}
	var stop traceStopError
	if cause := context.Cause(ctx); !errors.As(cause, &stop) {
		snapshot.IOProfileError = fmt.Sprintf("determine IO profile stop time: %v", cause)
		return snapshot, traceErr
	}
	if stop.monotonicNS < profileDeadlineNS {
		snapshot.IOProfileError = "IO profile capture stopped before its deadline"
		return snapshot, traceErr
	}
	outputCtx, outputCancel := context.WithTimeout(context.WithoutCancel(ctx), ioProfileCombinedOutputTimeout)
	defer outputCancel()
	data, err := ioprofile.ReadCapture(
		outputCtx,
		object,
		options.config,
		profileStarted,
	)
	if err != nil {
		snapshot.IOProfileError = err.Error()
		return snapshot, traceErr
	}
	if options.isLocal {
		if err := ioprofile.ResolveHostnames(outputCtx, data.Profile); err != nil {
			snapshot.IOProfileError = err.Error()
			return snapshot, traceErr
		}
	}
	if err := outputCtx.Err(); err != nil {
		snapshot.IOProfileError = err.Error()
		return snapshot, traceErr
	}
	snapshot.IOProfile = data
	limitIOProfileSupplement(snapshot, maxCombinedReportBytes)
	if snapshot.IOProfile != nil && options.isLocal {
		if err := writeIOProfileSVG(outputCtx, options.svgPath, data); err != nil {
			snapshot.IOProfileError = err.Error()
		}
	}
	if err := outputCtx.Err(); err != nil {
		snapshot.IOProfile = nil
		snapshot.IOProfileError = err.Error()
	}
	return snapshot, traceErr
}

func writeIOProfileSVG(ctx context.Context, path string, data *types.ProfilingWindow) (returnErr error) {
	if path == "" || data == nil {
		return nil
	}
	decoded, err := ioprofile.Decode(data.Profile, data.DroppedSamples)
	if err != nil {
		return err
	}
	// Publish only a complete SVG; a timeout must not leave a partial graph
	// or destroy a previously written graph at the requested path.
	output, err := os.CreateTemp(filepath.Dir(path), ".iotracing-profile-*.svg")
	if err != nil {
		return fmt.Errorf("create IO profile SVG: %w", err)
	}
	defer func() {
		if err := os.Remove(output.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary IO profile SVG: %w", err))
		}
	}()
	renderErr := flamegraph.RenderIOProfile(ctx, output, decoded)
	if err := errors.Join(renderErr, output.Close(), ctx.Err()); err != nil {
		return err
	}
	if err := os.Rename(output.Name(), path); err != nil {
		return fmt.Errorf("publish IO profile SVG: %w", err)
	}
	return nil
}

func writeIOProfileSummary(writer io.Writer, data *types.ProfilingWindow) error {
	decoded, err := ioprofile.Decode(data.Profile, data.DroppedSamples)
	if err != nil {
		return err
	}
	if !decoded.NumericComplete {
		if _, err := fmt.Fprintln(writer, "IO profile totals are incomplete: some measurements were lost"); err != nil {
			return err
		}
	}

	const heading = "IO PROFILE  DIRECTION  BYTES  OPERATIONS  " +
		"MEAN_SIZE(B)  MEAN_LATENCY(ns)"
	if _, err := fmt.Fprintln(writer, heading); err != nil {
		return err
	}
	for _, group := range decoded.Groups {
		if group.Scope != ioprofile.ScopeHost {
			continue
		}
		stats := group.Root.Stats
		if _, err := fmt.Fprintf(
			writer,
			"            %-9s %d  %d  %.2f  %.2f\n",
			group.Direction,
			stats.Bytes,
			stats.Count,
			stats.MeanSizeBytes(),
			stats.MeanDurationNS(),
		); err != nil {
			return err
		}
	}
	return nil
}

// The optional result cannot prevent an otherwise valid diagnostic report from
// reaching its output. Reserve framing room below the result's 64 MiB budget.
func limitIOProfileSupplement(snapshot *types.IOTracingSnapshot, maxBytes int) {
	if snapshot.IOProfile == nil {
		return
	}
	if proto.Size(snapshot.IOProfile.Profile) > maxIOProfileBytes {
		snapshot.IOProfile = nil
		snapshot.IOProfileError = "IO profile exceeds its 64 MiB result budget"
		return
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > maxBytes {
		snapshot.IOProfile = nil
		snapshot.IOProfileError = "IO profile exceeds the combined report output budget"
	}
}
