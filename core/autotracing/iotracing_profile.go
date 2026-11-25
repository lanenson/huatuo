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
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/internal/timeutil"
	"github.com/ccfos/huatuo/pkg/types"
)

const maxIOProfileBytes = 64 << 20

type ioProfileSummary struct {
	Scope            string               `json:"scope"`
	ContainerID      string               `json:"container_id,omitempty"`
	Labels           []types.ProfileLabel `json:"labels,omitempty"`
	Direction        string               `json:"direction"`
	Stats            ioprofile.Stats      `json:"stats"`
	FailedOperations int64                `json:"failed_operations,omitempty"`
}

type ioProfileReport struct {
	StartedTimestamp timeutil.Timestamp `json:"started_timestamp"`
	DurationNS       int64              `json:"duration_ns"`
	Groups           []ioProfileSummary `json:"groups"`
	DroppedSamples   map[string]uint64  `json:"dropped_samples,omitempty"`
	FlamegraphSVG    string             `json:"flamegraph_svg,omitempty"`
}

// trimIOProfile preserves the base diagnostic and keeps as much of the
// supplement as fits in one local file record.
func (data *ioStatusData) trimIOProfile(fits func() bool) string {
	if data.IOProfile == nil && data.IOProfileError == "" {
		return ""
	}
	if fits() {
		return data.IOProfileError
	}

	if data.IOProfile != nil {
		const budgetError = "IO profile exceeds the event size budget"
		if data.IOProfileError == "" {
			data.IOProfileError = budgetError
		} else {
			data.IOProfileError += "; " + budgetError
		}
		if data.IOProfile.FlamegraphSVG != "" {
			data.IOProfile.FlamegraphSVG = ""
			if fits() {
				return data.IOProfileError
			}
		}
		data.IOProfile = nil
		if fits() {
			return data.IOProfileError
		}
	}

	reason := data.IOProfileError
	data.IOProfileError = ""
	return reason
}

type ioProfileSVGBuffer struct{ bytes.Buffer }

func (b *ioProfileSVGBuffer) Write(data []byte) (int, error) {
	if len(data) > maxIOProfileBytes-b.Len() {
		return 0, fmt.Errorf("IO flamegraph exceeds the %d MiB render budget", maxIOProfileBytes>>20)
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
	if err := ioprofile.RenderSVG(ctx, &svg, data); err != nil {
		return nil, fmt.Errorf("render IO flamegraph: %w", err)
	}
	report := &ioProfileReport{
		StartedTimestamp: timeutil.Timestamp{Time: time.Unix(0, window.Profile.TimeNanos).UTC()},
		DurationNS:       window.Profile.DurationNanos,
		DroppedSamples:   data.DroppedSamples,
		FlamegraphSVG:    svg.String(),
		Groups:           make([]ioProfileSummary, 0, len(data.Groups)),
	}
	for i := range data.Groups {
		group := &data.Groups[i]
		report.Groups = append(report.Groups, ioProfileSummary{
			Scope:            group.Scope,
			ContainerID:      group.ContainerID,
			Labels:           group.Root.Labels,
			Direction:        group.Direction,
			Stats:            group.Root.Stats,
			FailedOperations: group.FailedOperations,
		})
	}
	return report, nil
}
