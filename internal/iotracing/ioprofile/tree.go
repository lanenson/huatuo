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

// Result trees are built once from the capture's joint-valued samples.
package ioprofile

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ccfos/huatuo/internal/profiling/window"
	"github.com/ccfos/huatuo/pkg/types"
)

type stackIdentity struct {
	UserFrames   []types.ProfileFrame
	KernelFrames []types.ProfileFrame
	Labels       []types.ProfileLabel
}

type groupKey struct {
	scope       string
	containerID string
	direction   string
}

func sampleScope(containerID string, labels []types.ProfileLabel) (string, error) {
	var attribution string
	var seen bool
	for i := range labels {
		label := &labels[i]
		if label.Name != "attribution" {
			continue
		}
		if seen || label.Kind != types.ProfileLabelString {
			return "", fmt.Errorf("file io attribution requires one string label")
		}
		seen = true
		attribution = label.StringValue
	}
	if containerID != "" && attribution == ScopeContainer {
		return ScopeContainer, nil
	}
	if containerID == "" && attribution == ScopeOther {
		return attribution, nil
	}

	return "", fmt.Errorf("file io attribution %q does not match container %q", attribution, containerID)
}

func resultLabel(labels []types.ProfileLabel) (string, error) {
	var result string
	var seen bool
	for i := range labels {
		label := &labels[i]
		if label.Name != "result" {
			continue
		}
		if seen || label.Kind != types.ProfileLabelString {
			return "", fmt.Errorf("file io result requires one string label")
		}
		seen = true
		result = label.StringValue
	}
	switch result {
	case "success", "error":
		return result, nil
	default:
		return "", fmt.Errorf("unsupported file io result %q", result)
	}
}

func addResult(
	group *Group,
	identity *stackIdentity,
	stats Stats,
	result string,
) error {
	if result == "error" {
		count, err := window.AddValues(group.FailedOperations, stats.Count)
		if err != nil {
			return err
		}
		group.FailedOperations = count
		return nil
	}
	if stats.Bytes == 0 {
		// Retain successful zero-byte calls in the summary without a zero-width frame.
		return group.Root.Stats.add(stats)
	}
	return addStack(group, identity, stats)
}

func getGroup(groups map[groupKey]*Group, key groupKey) *Group {
	group := groups[key]
	if group != nil {
		return group
	}
	group = &Group{
		Scope:       key.scope,
		ContainerID: key.containerID,
		Direction:   key.direction,
		Root: &Node{
			Frame: types.ProfileFrame{Name: key.scope + " " + key.direction},
		},
	}
	groups[key] = group

	return group
}

func addStack(group *Group, identity *stackIdentity, stats Stats) error {
	if err := group.Root.Stats.add(stats); err != nil {
		return err
	}
	labelParts := make([]string, len(identity.Labels))
	for i := range identity.Labels {
		label := &identity.Labels[i]
		if label.Kind == types.ProfileLabelString {
			labelParts[i] = fmt.Sprintf("%s=%q", label.Name, label.StringValue)
		} else {
			labelParts[i] = fmt.Sprintf(
				"%s=%d %s",
				label.Name,
				label.NumberValue,
				label.NumberUnit,
			)
		}
	}
	node := group.Root
	if len(labelParts) > 0 {
		node = labelNode(node, identity.Labels, strings.Join(labelParts, " "))
		if err := node.Stats.add(stats); err != nil {
			return err
		}
	}
	if len(identity.UserFrames) == 0 {
		node = childNode(node, types.ProfileFrame{Name: "[unknown user stack]"}, false)
		if err := node.Stats.add(stats); err != nil {
			return err
		}
	}
	for kind, frames := range [][]types.ProfileFrame{identity.UserFrames, identity.KernelFrames} {
		for i := range frames {
			node = childNode(node, frames[i], kind == 1)
			if err := node.Stats.add(stats); err != nil {
				return err
			}
		}
	}

	return nil
}

func childNode(parent *Node, frame types.ProfileFrame, isKernel bool) *Node {
	for _, child := range parent.Children {
		if len(child.Labels) == 0 && child.Frame == frame && child.IsKernel == isKernel {
			return child
		}
	}
	node := &Node{
		Frame:    frame,
		IsKernel: isKernel,
	}
	parent.Children = append(parent.Children, node)

	return node
}

func labelNode(parent *Node, labels []types.ProfileLabel, name string) *Node {
	for _, child := range parent.Children {
		if slices.Equal(child.Labels, labels) {
			return child
		}
	}
	node := &Node{
		Frame:  types.ProfileFrame{Name: name},
		Labels: slices.Clone(labels),
	}
	parent.Children = append(parent.Children, node)

	return node
}

func sortNodes(root *Node) {
	sort.Slice(root.Children, func(i, j int) bool {
		a, b := root.Children[i], root.Children[j]
		if a.Frame.Name != b.Frame.Name {
			return a.Frame.Name < b.Frame.Name
		}
		if a.Frame.File != b.Frame.File {
			return a.Frame.File < b.Frame.File
		}
		if a.Frame.Line != b.Frame.Line {
			return a.Frame.Line < b.Frame.Line
		}

		return !a.IsKernel && b.IsKernel
	})
	for _, child := range root.Children {
		sortNodes(child)
	}
}
