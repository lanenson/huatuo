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

// The existing disk trigger owns one iotracing task. Its optional raw profile
// is enriched and rendered after receipt without a second collector handoff.
package autotracing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/internal/profiling/formatter/flamegraph"
	"github.com/ccfos/huatuo/internal/timeutil"
	"github.com/ccfos/huatuo/pkg/types"
)

const maxIOProfileBytes = 64 << 20

type ioProfileSampling struct {
	mode     ioprofile.SamplingMode
	interval time.Duration
	every    uint64
}

func (s ioProfileSampling) validate() error {
	switch s.mode {
	case ioprofile.ModeTime:
		if s.interval <= 0 || s.every != 0 {
			return errors.New("time sampling requires a positive interval and zero operation count")
		}
	case ioprofile.ModeCount:
		if s.every == 0 || s.interval != 0 {
			return errors.New("count sampling requires a positive operation count and zero interval")
		}
	default:
		return fmt.Errorf("unsupported IO stack sampling mode %q", s.mode)
	}

	return nil
}

type ioProfileSummary struct {
	Scope       string                     `json:"scope"`
	ContainerID string                     `json:"container_id,omitempty"`
	Labels      []types.ProfileLabel       `json:"labels,omitempty"`
	Direction   string                     `json:"direction"`
	Stats       ioprofile.Stats            `json:"stats"`
	Unknown     ioprofile.Stats            `json:"unknown"`
	Outcomes    map[string]ioprofile.Stats `json:"outcomes,omitempty"`
}

type ioProfileReport struct {
	StartedTimestamp timeutil.Timestamp `json:"started_timestamp"`
	DurationNS       int64              `json:"duration_ns"`
	Groups           []ioProfileSummary `json:"groups"`
	DroppedSamples   map[string]uint64  `json:"dropped_samples,omitempty"`
	NumericComplete  bool               `json:"numeric_complete"`
	FlamegraphSVG    string             `json:"flamegraph_svg"`
}

type ioProfileSVGBuffer struct{ bytes.Buffer }

func (b *ioProfileSVGBuffer) Write(data []byte) (int, error) {
	if len(data) > maxIOProfileBytes-b.Len() {
		return 0, errors.New("IO flamegraph exceeds its output budget")
	}
	return b.Buffer.Write(data)
}

func decodeIOProfileCapture(ctx context.Context, window *types.ProfilingWindow) (*ioProfileReport, error) {
	if window == nil || window.Profile == nil || window.ProfileType != ioprofile.ProfileType ||
		window.ContainerID != "" {
		return nil, errors.New("IO event requires one complete capture")
	}
	if proto.Size(window.Profile) > maxIOProfileBytes {
		return nil, errors.New("IO capture exceeds its output budget")
	}
	if err := ioprofile.ResolveContainers(window.Profile); err != nil {
		return nil, err
	}
	data, err := ioprofile.Decode(window.Profile, window.DroppedSamples)
	if err != nil {
		return nil, err
	}
	var svg ioProfileSVGBuffer
	if err := flamegraph.RenderIOProfile(ctx, &svg, data); err != nil {
		return nil, err
	}
	report := &ioProfileReport{
		StartedTimestamp: timeutil.Timestamp{Time: time.Unix(0, window.Profile.TimeNanos).UTC()},
		DurationNS:       window.Profile.DurationNanos,
		DroppedSamples:   data.DroppedSamples,
		NumericComplete:  data.NumericComplete,
		FlamegraphSVG:    svg.String(),
		Groups:           make([]ioProfileSummary, 0, len(data.Groups)),
	}
	for i := range data.Groups {
		group := &data.Groups[i]
		report.Groups = append(report.Groups, ioProfileSummary{
			Scope:       group.Scope,
			ContainerID: group.ContainerID,
			Labels:      group.Root.Labels,
			Direction:   group.Direction,
			Stats:       group.Root.Stats,
			Unknown:     group.Unknown,
			Outcomes:    group.Outcomes,
		})
	}
	return report, nil
}

// Sampling options tune the existing iotracing invocation.
func ioProfileArguments(sampling *ioProfileSampling) ([]string, error) {
	if err := sampling.validate(); err != nil {
		return nil, err
	}
	if sampling.mode == ioprofile.ModeCount && sampling.every == ioprofile.DefaultStackEvery {
		return nil, nil
	}

	args := []string{"--io-stack-mode", string(sampling.mode)}
	if sampling.mode == ioprofile.ModeTime {
		args = append(args, "--io-stack-interval", strconv.FormatInt(sampling.interval.Microseconds(), 10)+"us")
	} else {
		args = append(args, "--io-stack-every", strconv.FormatUint(sampling.every, 10))
	}
	return args, nil
}
