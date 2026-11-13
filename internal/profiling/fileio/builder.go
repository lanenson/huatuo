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

// A single pprof sample carries bytes, operations and duration together. Frame
// encoding reuses the established scalar encoder without changing its model.
package fileio

import (
	"context"
	"fmt"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/internal/profiling/window"
	"github.com/ccfos/huatuo/pkg/types"
)

type Builder struct {
	window types.AggregationWindow
	frames map[types.ProfileFrame]uint32
	values [][4]int64
}

func NewBuilder(startNS, durationNS int64) *Builder {
	return &Builder{
		window: types.AggregationWindow{
			ProfileType: ProfileType,
			Aggregated: types.AggregatedProfile{
				TimeNanos:     startNS,
				DurationNanos: durationNS,
			},
		},
		frames: make(map[types.ProfileFrame]uint32),
	}
}

func (b *Builder) Add(frames []types.ProfileFrame, labels []types.ProfileLabel, stats Stats) error {
	labels = append(append([]types.ProfileLabel(nil), labels...), types.ProfileStringLabel("kind", "io"))
	return b.append(frames, labels, [4]int64{stats.Bytes, stats.Count, stats.DurationNS, 0})
}

func (b *Builder) AddDiagnostic(reason string, count int64) error {
	if count == 0 {
		return nil
	}
	return b.append(nil, []types.ProfileLabel{types.ProfileStringLabel("kind", "diagnostic"), types.ProfileStringLabel("reason", reason)}, [4]int64{0, 0, 0, count})
}

func (b *Builder) append(frames []types.ProfileFrame, labels []types.ProfileLabel, values [4]int64) error {
	for _, value := range values {
		if value < 0 {
			return fmt.Errorf("file io measured values must be nonnegative")
		}
	}
	normalized, err := types.NormalizeLabels(labels)
	if err != nil {
		return err
	}
	a := &b.window.Aggregated
	sample := types.AggregatedSample{Value: values[0]}
	if len(frames) > 0 {
		stack := make([]uint32, 0, len(frames))
		for _, frame := range frames {
			id, exists := b.frames[frame]
			if !exists {
				id = uint32(len(a.Frames))
				b.frames[frame] = id
				a.Frames = append(a.Frames, frame)
			}
			stack = append(stack, id)
		}
		a.Stacks = append(a.Stacks, stack)
		sample.UserStack = uint32(len(a.Stacks))
	}
	if len(normalized) > 0 {
		a.LabelSets = append(a.LabelSets, normalized)
		sample.LabelSet = uint32(len(a.LabelSets))
	}
	a.Samples = append(a.Samples, sample)
	b.values = append(b.values, values)
	return nil
}

func (b *Builder) Profile(ctx context.Context) (*profilev1.Profile, error) {
	if err := window.Validate(&b.window); err != nil {
		return nil, err
	}
	p, err := window.BuildProfile(ctx, &b.window)
	if err != nil {
		return nil, err
	}
	intern := func(value string) int64 {
		id := int64(len(p.StringTable))
		p.StringTable = append(p.StringTable, value)
		return id
	}
	for _, spec := range [][2]string{{"operations", "count"}, {"duration", "nanoseconds"}, {"events", "count"}} {
		p.SampleType = append(p.SampleType, &profilev1.ValueType{
			Type: intern(spec[0]),
			Unit: intern(spec[1]),
		})
	}
	for i, sample := range p.Sample {
		values := b.values[i]
		sample.Value = []int64{values[0], values[1], values[2], values[3]}
	}
	return p, nil
}
