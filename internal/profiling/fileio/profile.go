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

// Package fileio represents one bounded file IO capture. Its three measured
// values travel together, independently of the scalar CPU/memory pipeline.
package fileio

import (
	"strings"

	"github.com/ccfos/huatuo/internal/profiling/window"
	"github.com/ccfos/huatuo/pkg/types"
)

const (
	DirectionRead  = "read"
	DirectionWrite = "write"
	ScopeHost      = "host"
	ScopeContainer = "container"
	ScopeOther     = "other"
	ProfileType    = "filesystem_io:bytes:bytes:operations:count"
)

// Stats contains measured totals, never sampling-scaled estimates.
type Stats struct {
	Bytes      int64 `json:"bytes"`
	Count      int64 `json:"count"`
	DurationNS int64 `json:"duration_ns"`
}

func (s Stats) MeanDurationNS() float64 {
	if s.Count == 0 {
		return 0
	}

	return float64(s.DurationNS) / float64(s.Count)
}

func (s Stats) MeanSizeBytes() float64 {
	if s.Count == 0 {
		return 0
	}

	return float64(s.Bytes) / float64(s.Count)
}

func (s *Stats) add(other Stats) error {
	bytes, err := window.AddValues(s.Bytes, other.Bytes)
	if err != nil {
		return err
	}
	count, err := window.AddValues(s.Count, other.Count)
	if err != nil {
		return err
	}
	duration, err := window.AddValues(s.DurationNS, other.DurationNS)
	if err != nil {
		return err
	}

	s.Bytes, s.Count, s.DurationNS = bytes, count, duration

	return nil
}

// Node totals include descendants; Self contains only stacks ending here.
type Node struct {
	Frame    types.ProfileFrame   `json:"frame"`
	IsKernel bool                 `json:"is_kernel,omitempty"`
	Stats    Stats                `json:"stats"`
	Self     Stats                `json:"self"`
	Labels   []types.ProfileLabel `json:"labels,omitempty"`
	Children []*Node              `json:"children,omitempty"`
}

// Group owns one independently normalized byte-width tree.
type Group struct {
	Scope          string                    `json:"scope"`
	ContainerID    string                    `json:"container_id,omitempty"`
	Container      *types.ProfilingContainer `json:"container,omitempty"`
	Direction      string                    `json:"direction"`
	Root           *Node                     `json:"root"`
	Unknown        Stats                     `json:"unknown"`
	DroppedSamples map[string]uint64         `json:"dropped_samples,omitempty"`
	Outcomes       map[string]Stats          `json:"outcomes,omitempty"`
}

// NumericComplete reports whether numeric totals have no reported losses.
// It does not assert coverage of uninstrumented paths or exact stack attribution.
func NumericComplete(groups []Group, diagnostics map[string]uint64) bool {
	for reason, count := range diagnostics {
		if count == 0 {
			continue
		}
		switch reason {
		case "aggregate_failure", "state_insert_failure", "identity_failure", "state_delete_failure",
			"dropped_" + types.DropReasonCollection, "dropped_" + types.DropReasonAggregationQueue:
			return false
		}
	}
	for i := range groups {
		for _, count := range groups[i].DroppedSamples {
			if count != 0 {
				return false
			}
		}
	}

	return true
}

// Result is one capture's measured totals and representative-stack trees.
type Result struct {
	Groups          []Group           `json:"groups"`
	Diagnostics     map[string]uint64 `json:"diagnostics"`
	NumericComplete bool              `json:"numeric_complete"`
}

func IsProfile(profileType string) bool {
	return strings.HasPrefix(profileType, "filesystem_io:")
}
