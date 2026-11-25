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

// Container attribution is performed once on the completed capture. Missing
// containers remain in other; metadata discovery never discards measured IO.
package ioprofile

import (
	"fmt"
	"strconv"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/internal/cgroups/subsystem"
	"github.com/ccfos/huatuo/internal/log"
	"github.com/ccfos/huatuo/internal/pod"
)

// ResolveContainers uses bamai's current PodManager view, without retaining
// container history or subscribing to lifecycle updates.
func ResolveContainers(profile *profilev1.Profile) error {
	if profile == nil {
		return fmt.Errorf("raw IO profile is required")
	}
	needed := make(map[uint64]bool)
	for _, sample := range profile.Sample {
		ref, err := rawContainerRef(profile, sample)
		if err != nil {
			return err
		}
		if ref.CSSAddr != 0 && ref.CgroupID != 0 {
			needed[ref.CSSAddr] = true
		}
	}
	current, err := pod.Containers()
	if err != nil {
		log.WithError(err).Debug("file IO container metadata unavailable")
	}
	containers := make(map[pod.CgroupCSSRef]*pod.Container)
	for id, container := range current {
		css := container.CgroupCss[subsystem.SubsystemCPU]
		if !needed[css] {
			continue
		}
		ref, err := pod.ContainerCSSBySubsys(id, subsystem.SubsystemCPU)
		if err != nil {
			log.WithError(err).Debug("file IO cgroup identity unavailable")
			continue
		}
		containers[ref] = container
	}
	return AttributeContainers(profile, containers)
}

// AttributeContainers binds raw cgroup identities to one end-of-capture view.
// CSS and cgroup ID must both match; host totals remain unchanged.
func AttributeContainers(profile *profilev1.Profile, containers map[pod.CgroupCSSRef]*pod.Container) error {
	if profile == nil {
		return fmt.Errorf("raw IO profile is required")
	}
	strings := make(map[string]int64, len(profile.StringTable))
	for i, value := range profile.StringTable {
		strings[value] = int64(i)
	}
	intern := func(value string) int64 {
		if id, ok := strings[value]; ok && id != 0 {
			return id
		}
		id := int64(len(profile.StringTable))
		profile.StringTable = append(profile.StringTable, value)
		strings[value] = id
		return id
	}
	for _, sample := range profile.Sample {
		ref, err := rawContainerRef(profile, sample)
		if err != nil {
			return err
		}
		retained := sample.Label[:0]
		for _, label := range sample.Label {
			switch profile.StringTable[label.Key] {
			case "attribution", "cgroup_css", "cgroup_id":
				continue
			}
			retained = append(retained, label)
		}
		sample.Label = retained
		appendLabel := func(name, value string) {
			sample.Label = append(sample.Label, &profilev1.Label{
				Key: intern(name),
				Str: intern(value),
			})
		}
		container := containers[ref]
		if container == nil {
			appendLabel("attribution", ScopeOther)
			continue
		}
		appendLabel("attribution", ScopeContainer)
		appendLabel("container_id", container.ID)
		appendLabel("container_hostname", container.Hostname)
		appendLabel("container_host_namespace", container.LabelHostNamespace())
		appendLabel("container_type", container.Type.String())
		appendLabel("container_qos", container.Qos.String())
	}
	clearUnusedProfileStrings(profile)
	return nil
}

// rawContainerRef is only used on the capture side of the publication boundary.
func rawContainerRef(profile *profilev1.Profile, sample *profilev1.Sample) (pod.CgroupCSSRef, error) {
	if sample == nil {
		return pod.CgroupCSSRef{}, fmt.Errorf("raw IO profile has nil sample")
	}

	decoder := profileDecoder{profile: profile}
	var css, id, attribution string
	for _, label := range sample.Label {
		if label == nil {
			return pod.CgroupCSSRef{}, fmt.Errorf("raw IO sample has nil label")
		}
		name, err := decoder.text(label.Key)
		if err != nil {
			return pod.CgroupCSSRef{}, err
		}

		var target *string
		switch name {
		case "cgroup_css":
			target = &css
		case "cgroup_id":
			target = &id
		case "attribution":
			target = &attribution
		case "container_id", "container_hostname", "container_host_namespace", "container_type", "container_qos":
			return pod.CgroupCSSRef{}, fmt.Errorf("raw IO sample contains container metadata %q", name)
		default:
			continue
		}
		value, err := decoder.text(label.Str)
		if err != nil {
			return pod.CgroupCSSRef{}, err
		}
		if value == "" || (*target != "" && *target != value) {
			return pod.CgroupCSSRef{}, fmt.Errorf("raw IO sample requires one string value for %q", name)
		}
		*target = value
	}
	if attribution != ScopeOther {
		return pod.CgroupCSSRef{}, fmt.Errorf("raw IO sample must use other attribution")
	}
	address, cssErr := strconv.ParseUint(css, 10, 64)
	cgroupID, idErr := strconv.ParseUint(id, 10, 64)
	if cssErr != nil || idErr != nil {
		return pod.CgroupCSSRef{}, fmt.Errorf("raw IO sample requires a numeric cgroup identity pair")
	}
	return pod.CgroupCSSRef{CSSAddr: address, CgroupID: cgroupID}, nil
}

// Keep indices stable while removing strings referenced only by stripped labels.
func clearUnusedProfileStrings(profile *profilev1.Profile) {
	used := make([]bool, len(profile.StringTable))
	mark := func(indices ...int64) {
		for _, index := range indices {
			if uint64(index) < uint64(len(used)) {
				used[index] = true
			}
		}
	}

	mark(0, profile.DefaultSampleType, profile.DropFrames, profile.KeepFrames)
	mark(profile.Comment...)
	mark(profile.PeriodType.GetType(), profile.PeriodType.GetUnit())
	for _, sampleType := range profile.SampleType {
		mark(sampleType.GetType(), sampleType.GetUnit())
	}
	for _, sample := range profile.Sample {
		for _, label := range sample.Label {
			mark(label.GetKey(), label.GetStr(), label.GetNumUnit())
		}
	}
	for _, function := range profile.Function {
		mark(function.GetName(), function.GetSystemName(), function.GetFilename())
	}
	for _, mapping := range profile.Mapping {
		mark(mapping.GetFilename(), mapping.GetBuildId())
	}
	for i, keep := range used {
		if !keep {
			profile.StringTable[i] = ""
		}
	}
}
