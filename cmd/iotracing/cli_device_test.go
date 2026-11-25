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

package main

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"testing"
	"time"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"
	"github.com/urfave/cli/v2"

	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/pkg/types"
)

func TestParseDeviceNumbersRejectsInvalidSpecs(t *testing.T) {
	cases := []string{
		"",
		" ",
		",",
		"4096:0",
		"8:1048576",
		"8",
		"8:0:1",
	}

	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := parseDeviceNumbers(tc); err == nil {
				t.Fatalf("parseDeviceNumbers(%q) error = nil, want error", tc)
			}
		})
	}
}

func TestParseDeviceNumbersAcceptsBoundaryValues(t *testing.T) {
	got, err := parseDeviceNumbers("8:0,4095:1048575")
	if err != nil {
		t.Fatalf("parseDeviceNumbers() error = %v", err)
	}

	want := []uint32{
		8 << 20,
		4095<<20 | 1048575,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("device[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func newIOProfileCLIContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	var parsed *cli.Context
	app := &cli.App{
		Flags:     appFlags(),
		Writer:    io.Discard,
		ErrWriter: io.Discard,
		Before:    validateFlags,
		Action: func(c *cli.Context) error {
			parsed = c
			return nil
		},
	}
	argv := append([]string{"iotracing", "--bpf-path", "/test/iotracing.o"}, args...)
	if err := app.RunContext(context.Background(), argv); err != nil {
		t.Fatalf("parse profile CLI: %v", err)
	}
	return parsed
}

func TestIOProfileSamplingOptions(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		mode      ioprofile.SamplingMode
		interval  time.Duration
		every     uint64
		wantError bool
	}{
		{
			name:  "combined by default",
			mode:  ioprofile.ModeCount,
			every: 100,
		},
		{
			name:     "time default",
			args:     []string{"--io-stack-mode", "io_time"},
			mode:     ioprofile.ModeTime,
			interval: time.Millisecond,
		},
		{
			name:     "time explicit",
			args:     []string{"--io-stack-mode", "io_time", "--io-stack-period", "0.002"},
			mode:     ioprofile.ModeTime,
			interval: 2 * time.Millisecond,
		},
		{
			name:  "count explicit",
			args:  []string{"--io-stack-mode", "io_count", "--io-stack-period", "17"},
			mode:  ioprofile.ModeCount,
			every: 17,
		},
		{
			name:      "zero time interval",
			args:      []string{"--io-stack-mode", "io_time", "--io-stack-period", "0"},
			wantError: true,
		},
		{
			name:      "negative time interval",
			args:      []string{"--io-stack-mode", "io_time", "--io-stack-period", "-1"},
			wantError: true,
		},
		{
			name:      "zero operation count",
			args:      []string{"--io-stack-mode", "io_count", "--io-stack-period", "0"},
			wantError: true,
		},
		{
			name:      "unqualified mode",
			args:      []string{"--io-stack-mode", "time"},
			wantError: true,
		},
		{
			name:      "fractional operation count",
			args:      []string{"--io-stack-period", "0.5"},
			wantError: true,
		},
		{
			name:      "time needs a number in seconds",
			args:      []string{"--io-stack-mode", "io_time", "--io-stack-period", "1ms"},
			wantError: true,
		},
		{
			name:      "non-finite seconds",
			args:      []string{"--io-stack-mode", "io_time", "--io-stack-period", "NaN"},
			wantError: true,
		},
		{
			name:      "time exceeds duration range",
			args:      []string{"--io-stack-mode", "io_time", "--io-stack-period", "9223372037"},
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newIOProfileCLIContext(t, test.args...)
			options, err := loadIOProfileOptions(c, 8)
			if (err != nil) != test.wantError {
				t.Fatalf("sampling error = %v, want error %t", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if options.config.Mode != test.mode || options.config.Interval != test.interval ||
				options.config.Every != test.every {
				t.Fatalf(
					"sampling = %+v, want mode=%s interval=%s every=%d",
					options.config,
					test.mode,
					test.interval,
					test.every,
				)
			}
		})
	}
}

func TestIOProfileFlagsDoNotChangeDiagnosticDefaults(t *testing.T) {
	c := newIOProfileCLIContext(t)
	cfg, filters, err := loadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.durationSecond != 8 || cfg.maxProcess != 10 || cfg.maxFilesPerProcess != 5 ||
		cfg.maxStack != 10 || cfg.scheduleThreshold != 100 {
		t.Fatalf("diagnostic defaults changed: %+v", cfg)
	}
	want := map[string]any{bpfFilterEventTimeout: uint64(100000000)}
	if !reflect.DeepEqual(filters, want) {
		t.Fatalf("diagnostic filter changed: %#v", filters)
	}
	snapshot := &types.IOTracingSnapshot{}
	var old, current bytes.Buffer
	printIOTracingSnapshot(&old, snapshot)
	if err := (&textWriter{w: &current}).Write(snapshot); err != nil {
		t.Fatal(err)
	}
	if old.String() != current.String() {
		t.Fatal("disabled profile changed diagnostic text output")
	}
}

func TestIOProfileOutputBudgetRetainsOriginalReport(t *testing.T) {
	snapshot := &types.IOTracingSnapshot{
		Processes:   []types.ProcessFileIOStats{{PID: 42}},
		StallStacks: []types.IOScheduleEvent{{PID: 42, TID: 43}},
		IOProfile: &types.ProfilingWindow{
			Profile: &profilev1.Profile{StringTable: []string{"", "optional payload"}},
		},
	}
	limitIOProfileSupplement(snapshot, 1)
	if snapshot.IOProfile != nil || snapshot.IOProfileError == "" {
		t.Fatal("oversized profile did not degrade to an optional-result error")
	}
	if len(snapshot.Processes) != 1 || snapshot.Processes[0].PID != 42 || len(snapshot.StallStacks) != 1 ||
		snapshot.StallStacks[0].TID != 43 {
		t.Fatalf("profile budget changed original observations: %+v", snapshot)
	}
}

func TestIOProfileFlagCompatibility(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		wantError bool
	}{
		{
			name: "old output",
			args: []string{"--output", "json"},
		},
		{
			name: "combined profile",
			args: []string{"--io-stack-mode", "io_count"},
		},
		{
			name: "diagnostic device filter with profile",
			args: []string{"--device", "8:0"},
		},
		{
			name:      "removed process filter",
			args:      []string{"--pid", "1"},
			wantError: true,
		},
		{
			name:      "removed container filter",
			args:      []string{"--container-id", "container"},
			wantError: true,
		},
		{
			name: "SVG excludes remote output",
			args: []string{
				"--io-profile-svg", "profile.svg",
				"--output-storage", "/test/socket",
			},
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := &cli.App{
				Flags:     appFlags(),
				Writer:    io.Discard,
				ErrWriter: io.Discard,
				Action:    validateFlags,
			}
			args := append([]string{"iotracing", "--bpf-path", "/test/iotracing.o"}, test.args...)
			err := app.Run(args)
			if (err != nil) != test.wantError {
				t.Fatalf("CLI error = %v, want error %t", err, test.wantError)
			}
		})
	}
}
