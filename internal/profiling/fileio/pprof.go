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

// Decode validates the complete, jointly-valued pprof capture at its input
// boundary. There are no partial windows or independently joinable columns.
package fileio

import (
	"fmt"
	"math"
	"sort"
	"strings"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/pkg/types"
)

func Decode(profile *profilev1.Profile) (*Result, error) {
	if profile == nil || profile.TimeNanos <= 0 || profile.DurationNanos <= 0 ||
		len(profile.StringTable) == 0 || profile.StringTable[0] != "" || len(profile.SampleType) != 4 {
		return nil, fmt.Errorf("file io requires one timed capture with four sample types")
	}
	decoder := profileDecoder{
		profile:   profile,
		locations: make(map[uint64]*profilev1.Location),
		functions: make(map[uint64]*profilev1.Function),
	}
	specs := [][2]string{{"bytes", "bytes"}, {"operations", "count"}, {"duration", "nanoseconds"}, {"events", "count"}}
	var indices [4]int
	for i, spec := range specs {
		index, err := decoder.valueIndex(spec[0], spec[1])
		if err != nil {
			return nil, err
		}
		indices[i] = index
	}
	for _, location := range profile.Location {
		if location == nil || location.Id == 0 || decoder.locations[location.Id] != nil {
			return nil, fmt.Errorf("file io has an invalid or duplicate location")
		}
		decoder.locations[location.Id] = location
	}
	for _, function := range profile.Function {
		if function == nil || function.Id == 0 || decoder.functions[function.Id] != nil {
			return nil, fmt.Errorf("file io has an invalid or duplicate function")
		}
		decoder.functions[function.Id] = function
	}
	groups := make(map[groupKey]*Group)
	result := &Result{Diagnostics: make(map[string]uint64)}
	for _, sample := range profile.Sample {
		if sample == nil || len(sample.Value) != 4 {
			return nil, fmt.Errorf("file io sample must contain four measured values")
		}
		for _, value := range sample.Value {
			if value < 0 {
				return nil, fmt.Errorf("file io values must be nonnegative")
			}
		}
		identity, err := decoder.identity(sample)
		if err != nil {
			return nil, err
		}
		labels := make(map[string]string)
		for _, label := range identity.Labels {
			switch label.Name {
			case "kind", "direction", "attribution", "result", "reason", "container_id", "container_hostname", "container_host_namespace", "container_type", "container_qos":
				if label.Kind != types.ProfileLabelString {
					return nil, fmt.Errorf("file io label %q must be a string", label.Name)
				}
				labels[label.Name] = label.StringValue
			}
		}
		if labels["kind"] == "diagnostic" {
			if len(identity.Labels) != 2 || labels["reason"] == "" || len(sample.LocationId) != 0 ||
				sample.Value[indices[0]] != 0 || sample.Value[indices[1]] != 0 || sample.Value[indices[2]] != 0 {
				return nil, fmt.Errorf("file io diagnostic requires only a reason and an event count")
			}
			count := uint64(sample.Value[indices[3]])
			if count > math.MaxUint64-result.Diagnostics[labels["reason"]] {
				return nil, fmt.Errorf("file io diagnostic counter overflows uint64")
			}
			result.Diagnostics[labels["reason"]] += count
			continue
		}
		if labels["kind"] != "io" || sample.Value[indices[3]] != 0 {
			return nil, fmt.Errorf("file io sample has an invalid kind or diagnostic value")
		}
		direction := labels["direction"]
		if direction != DirectionRead && direction != DirectionWrite {
			return nil, fmt.Errorf("file io direction must be read or write")
		}
		stats := Stats{
			Bytes:      sample.Value[indices[0]],
			Count:      sample.Value[indices[1]],
			DurationNS: sample.Value[indices[2]],
		}
		outcome, err := resultLabel(identity.Labels)
		if err != nil {
			return nil, err
		}
		if stats.Count == 0 || (outcome == "success" && stats.Bytes < stats.Count) || (outcome != "success" && stats.Bytes != 0) {
			return nil, fmt.Errorf("file io sample has inconsistent returned bytes and operation count")
		}
		containerID := labels["container_id"]
		scope, err := sampleScope(containerID, identity.Labels)
		if err != nil {
			return nil, err
		}
		retained := identity.Labels[:0]
		for _, label := range identity.Labels {
			switch label.Name {
			case "kind", "direction", "container_hostname", "container_host_namespace", "container_type", "container_qos":
				continue
			}
			retained = append(retained, label)
		}
		identity.Labels = retained
		group := getGroup(groups, groupKey{
			scope:       scope,
			containerID: containerID,
			direction:   direction,
		})
		if containerID != "" {
			metadata := types.ProfilingContainer{
				ID:            containerID,
				Hostname:      labels["container_hostname"],
				HostNamespace: labels["container_host_namespace"],
				Type:          labels["container_type"],
				QoS:           labels["container_qos"],
			}
			if group.Container != nil && *group.Container != metadata {
				return nil, fmt.Errorf("file io container metadata is inconsistent")
			}
			group.Container = &metadata
		}
		if err := addResult(group, &identity, stats, outcome); err != nil {
			return nil, err
		}
		if err := addResult(getGroup(groups, groupKey{
			scope:     ScopeHost,
			direction: direction,
		}), &identity, stats, outcome); err != nil {
			return nil, err
		}
	}
	result.Groups = make([]Group, 0, len(groups))
	for _, group := range groups {
		sortNodes(group.Root)
		result.Groups = append(result.Groups, *group)
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		a, b := &result.Groups[i], &result.Groups[j]
		if a.Scope != b.Scope {
			if a.Scope == ScopeHost {
				return true
			}
			if b.Scope == ScopeHost {
				return false
			}
			return a.Scope < b.Scope
		}
		if a.ContainerID != b.ContainerID {
			return a.ContainerID < b.ContainerID
		}
		return a.Direction < b.Direction
	})
	result.NumericComplete = NumericComplete(result.Groups, result.Diagnostics)
	return result, nil
}

type profileDecoder struct {
	profile   *profilev1.Profile
	locations map[uint64]*profilev1.Location
	functions map[uint64]*profilev1.Function
}

func (d *profileDecoder) text(index int64) (string, error) {
	if index < 0 || index >= int64(len(d.profile.StringTable)) {
		return "", fmt.Errorf("file io profile references missing string %d", index)
	}

	return d.profile.StringTable[index], nil
}

func (d *profileDecoder) valueIndex(name, unit string) (int, error) {
	index := -1
	for i, sampleType := range d.profile.SampleType {
		if sampleType == nil {
			return 0, fmt.Errorf("file io profile has nil sample type")
		}
		typeName, err := d.text(sampleType.Type)
		if err != nil {
			return 0, err
		}
		typeUnit, err := d.text(sampleType.Unit)
		if err != nil {
			return 0, err
		}
		if typeName == name && typeUnit == unit {
			if index >= 0 {
				return 0, fmt.Errorf("file io profile has duplicate sample type %q", name)
			}
			index = i
		}
	}
	if index < 0 {
		return 0, fmt.Errorf("file io profile lacks sample type %s/%s", name, unit)
	}

	return index, nil
}

func (d *profileDecoder) identity(sample *profilev1.Sample) (stackIdentity, error) {
	var identity stackIdentity
	for i := len(sample.LocationId) - 1; i >= 0; i-- {
		location := d.locations[sample.LocationId[i]]
		if location == nil {
			return identity, fmt.Errorf("file io sample references missing location %d", sample.LocationId[i])
		}
		if len(location.Line) == 0 {
			identity.UserFrames = append(identity.UserFrames, types.ProfileFrame{Name: fmt.Sprintf("0x%x", location.Address)})
		}
		for j := len(location.Line) - 1; j >= 0; j-- {
			line := location.Line[j]
			if line == nil || d.functions[line.FunctionId] == nil {
				return identity, fmt.Errorf("file io location has missing function")
			}
			function := d.functions[line.FunctionId]
			name, err := d.text(function.Name)
			if err != nil {
				return identity, err
			}
			filename, err := d.text(function.Filename)
			if err != nil {
				return identity, err
			}
			frame := types.ProfileFrame{
				Name: strings.TrimSuffix(name, "_[k]"),
				File: filename,
				Line: line.Line,
			}
			if strings.HasSuffix(name, "_[k]") {
				identity.KernelFrames = append(identity.KernelFrames, frame)
			} else {
				identity.UserFrames = append(identity.UserFrames, frame)
			}
		}
	}
	for _, label := range sample.Label {
		if label == nil {
			return identity, fmt.Errorf("file io profile has nil label")
		}
		name, err := d.text(label.Key)
		if err != nil {
			return identity, err
		}
		item := types.ProfileLabel{Name: name}
		if label.Str != 0 {
			item.Kind = types.ProfileLabelString
			item.StringValue, err = d.text(label.Str)
		} else {
			item.Kind = types.ProfileLabelNumber
			item.NumberValue = label.Num
			item.NumberUnit, err = d.text(label.NumUnit)
		}
		if err != nil {
			return identity, err
		}
		identity.Labels = append(identity.Labels, item)
	}
	labels, err := types.NormalizeLabels(identity.Labels)
	if err != nil {
		return identity, err
	}
	identity.Labels = labels

	return identity, nil
}
