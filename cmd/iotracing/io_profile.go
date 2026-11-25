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
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/urfave/cli/v2"
	"google.golang.org/protobuf/proto"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/pkg/types"
)

const (
	cliFlagIOProfileSVG            = "io-profile-svg"
	cliFlagIOStackMode             = "io-stack-mode"
	cliFlagIOStackPeriod           = "io-stack-period"
	ioProfileCombinedOutputTimeout = 5 * time.Second
	maxIOProfileBytes              = 64 << 20
	maxCombinedReportBytes         = 63 << 20
)

type ioProfileOptions struct {
	config  ioprofile.Config
	svgPath string
	isLocal bool
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
		&cli.StringFlag{
			Name:  cliFlagIOStackPeriod,
			Usage: "stack refresh period: IO count for io_count (default 100), seconds for io_time (default 0.001)",
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
		isLocal: c.String(cliFlagOutputStorage) == "",
		svgPath: c.String(cliFlagIOProfileSVG),
	}
	if duration > uint64(math.MaxInt64/int64(time.Second)) {
		return options, errors.New("IO profile duration exceeds the supported duration")
	}

	options.config = ioprofile.Config{
		Duration: time.Duration(duration) * time.Second,
		Mode:     ioprofile.SamplingMode(c.String(cliFlagIOStackMode)),
	}
	period := c.String(cliFlagIOStackPeriod)
	switch options.config.Mode {
	case ioprofile.ModeTime:
		options.config.Interval = ioprofile.DefaultStackInterval
		if c.IsSet(cliFlagIOStackPeriod) {
			seconds, err := strconv.ParseFloat(period, 64)
			nanos := seconds * float64(time.Second)
			if err != nil || !(nanos >= 1 && nanos < float64(math.MaxInt64)) {
				return options, errors.New("--io-stack-period requires a positive number of seconds with a representable nanosecond duration")
			}
			options.config.Interval = time.Duration(nanos)
		}
	case ioprofile.ModeCount:
		options.config.Every = ioprofile.DefaultStackEvery
		if c.IsSet(cliFlagIOStackPeriod) {
			count, err := strconv.ParseUint(period, 10, 64)
			if err != nil || count == 0 {
				return options, errors.New("--io-stack-period requires a positive integer IO count")
			}
			options.config.Every = count
		}
	}
	if err := options.config.Validate(); err != nil {
		return options, err
	}
	return options, nil
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
	data, stackMapDrops, err := ioprofile.ReadCapture(
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
	if stackMapDrops != 0 {
		snapshot.IOProfileError = fmt.Sprintf(
			"IO profile stack map rejected %d samples due to hash collisions or unavailable entries, leaving affected IO under unknown user stacks",
			stackMapDrops,
		)
	}
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
	renderErr := ioprofile.RenderSVG(ctx, output, decoded)
	if err := errors.Join(renderErr, output.Close(), ctx.Err()); err != nil {
		return err
	}
	if err := os.Rename(output.Name(), path); err != nil {
		return fmt.Errorf("publish IO profile SVG: %w", err)
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
