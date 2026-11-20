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

// File IO rendering keeps measured totals separate from representative-stack
// attribution. Numeric labels and tables remain available in static exports.
package flamegraph

import (
	"context"
	"fmt"
	"html"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
)

const (
	ioProfileImageWidth   = 1280
	ioProfileFrameHeight  = 18
	ioProfileMargin       = 24
	ioProfileTextHeight   = 19
	ioProfileTableLimit   = 16
	ioProfileMinLatencyNS = 10000.0
	ioProfileMaxLatencyNS = 100000000.0
)

type ioProfileTableRow struct {
	path  string
	stats ioprofile.Stats
}

type ioProfilePanel struct {
	group     *ioprofile.Group
	depth     int
	rows      []ioProfileTableRow
	totalRows int
	height    int
}

// RenderIOProfile writes separate scope/direction panels into a single static SVG.
// The result must come from ioprofile.Decode; the caller owns output.
func RenderIOProfile(
	ctx context.Context,
	out io.Writer,
	result *ioprofile.Result,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var panels []ioProfilePanel
	height := 215
	groups := result.Groups
	for i := range groups {
		panel := ioProfilePanel{group: &groups[i]}
		panel.collect(groups[i].Root, nil, 0)
		panel.selectRows()
		panel.height = 160 + panel.depth*ioProfileFrameHeight +
			(len(panel.rows)+len(groups[i].Outcomes))*ioProfileTextHeight
		if len(groups[i].Root.Labels) != 0 {
			panel.height += ioProfileTextHeight
		}
		height += panel.height
		panels = append(panels, panel)
	}
	if len(panels) == 0 {
		height += 40
	}
	ew := &errWriter{w: out}
	ew.println(`<?xml version="1.0" standalone="no"?>`)
	ew.printf(
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n",
		ioProfileImageWidth,
		height,
		ioProfileImageWidth,
		height,
	)
	ew.printf(`<rect width="%d" height="%d" fill="#ffffff"/>`+"\n", ioProfileImageWidth, height)
	ioProfileText(
		ew,
		ioProfileMargin,
		30,
		20,
		"File IO profiles: measured bytes and mean operation latency",
	)
	ioProfileText(
		ew,
		ioProfileMargin,
		55,
		12,
		"Numeric values are measured without scaling; stacks are periodic representatives, "+
			"not exact per-function attribution.",
	)
	ioProfileText(
		ew,
		ioProfileMargin,
		74,
		12,
		"Host includes containers and other. Each panel has its own byte scale; do not add host and container totals.",
	)
	ioProfileText(
		ew,
		ioProfileMargin,
		93,
		12,
		"Green means lower mean file-operation latency, not disk health. "+
			"Width is successful returned bytes; parent frames include children.",
	)
	for i := 0; i < 200; i++ {
		latency := ioProfileMinLatencyNS * math.Pow(ioProfileMaxLatencyNS/ioProfileMinLatencyNS, float64(i)/199)
		ew.printf(
			`<rect x="%d" y="108" width="3" height="14" fill="%s"/>`+"\n",
			ioProfileMargin+i*3,
			ioProfileLatencyColor(latency),
		)
	}
	ioProfileText(
		ew,
		ioProfileMargin,
		138,
		11,
		"10 us                 100 us                  1 ms                  10 ms                 100 ms (fixed log scale)",
	)
	if result.NumericComplete {
		ioProfileText(
			ew,
			ioProfileMargin,
			163,
			12,
			"Numeric completeness: no data loss reported for covered operations.",
		)
	} else {
		ew.printf(`<rect x="%d" y="147" width="%d" height="26" fill="#fff0f0"/>`+"\n",
			ioProfileMargin, ioProfileImageWidth-2*ioProfileMargin)
		ew.printf(
			`<text x="%d" y="164" font-family="Verdana" font-size="13" font-weight="bold" fill="#a4161a">`+
				`INCOMPLETE: numeric data loss detected; totals and mean latencies describe retained operations only.</text>`+"\n",
			ioProfileMargin+6,
		)
	}
	y := 185
	if len(panels) == 0 {
		ioProfileText(
			ew,
			ioProfileMargin,
			y+20,
			14,
			"No completed operation records are available in the supplied snapshots.",
		)
	}
	for i := range panels {
		if err := ctx.Err(); err != nil {
			return err
		}
		panels[i].render(ew, y)
		y += panels[i].height
	}
	ew.println("</svg>")

	return ew.err
}

func (p *ioProfilePanel) collect(node *ioprofile.Node, path []string, depth int) {
	if depth+1 > p.depth {
		p.depth = depth + 1
	}
	name := node.Frame.Name
	if node.IsKernel {
		name += " [kernel]"
	}
	if depth > 0 {
		path = append(path, name)
	}
	if node.Self.Count > 0 {
		p.rows = append(p.rows, ioProfileTableRow{
			path:  strings.Join(path, " > "),
			stats: node.Self,
		})
	}
	for _, child := range node.Children {
		p.collect(child, path, depth+1)
	}
}

func (p *ioProfilePanel) selectRows() {
	p.totalRows = len(p.rows)
	if len(p.rows) <= ioProfileTableLimit {
		return
	}
	sort.Slice(p.rows, func(i, j int) bool { return p.rows[i].stats.Bytes > p.rows[j].stats.Bytes })
	selected := append([]ioProfileTableRow(nil), p.rows[:ioProfileTableLimit/2]...)
	remaining := p.rows[ioProfileTableLimit/2:]
	sort.Slice(remaining, func(i, j int) bool {
		return remaining[i].stats.MeanDurationNS() > remaining[j].stats.MeanDurationNS()
	})
	selected = append(selected, remaining[:ioProfileTableLimit/2]...)
	p.rows = selected
}

func (p *ioProfilePanel) render(ew *errWriter, top int) {
	group := p.group
	title := strings.ToUpper(group.Direction) + " / " + group.Scope
	if group.ContainerID != "" {
		title += " / " + group.ContainerID
	}
	ioProfileText(
		ew,
		ioProfileMargin,
		top+20,
		16,
		title,
	)

	if len(group.Root.Labels) != 0 {
		var hostname, containerType, qos string
		for _, label := range group.Root.Labels {
			switch label.Name {
			case "container_hostname":
				hostname = label.StringValue
			case "container_type":
				containerType = label.StringValue
			case "container_qos":
				qos = label.StringValue
			}
		}
		shortID := group.ContainerID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		ioProfileText(ew, ioProfileMargin, top+39, 12,
			fmt.Sprintf("Container: %s / %s / type: %s / QoS: %s", hostname, shortID, containerType, qos))
		top += ioProfileTextHeight
	}
	ioProfileText(
		ew,
		ioProfileMargin,
		top+42,
		12,
		statsText(group.Root.Stats),
	)
	ioProfileText(
		ew,
		ioProfileMargin,
		top+61,
		12,
		fmt.Sprintf("Unknown user-stack attribution: %d bytes / %d operations", group.Unknown.Bytes, group.Unknown.Count),
	)
	graphTop := top + 78
	if group.Root.Stats.Bytes > 0 {
		p.drawNode(
			ew,
			group.Root,
			0,
			0,
			graphTop,
		)
	} else {
		ioProfileText(
			ew,
			ioProfileMargin,
			graphTop+15,
			12,
			"No positive-byte successful operations; see outcome counts below.",
		)
	}
	y := graphTop + p.depth*ioProfileFrameHeight + 22
	for _, outcome := range sortedOutcomeKeys(group.Outcomes) {
		stats := group.Outcomes[outcome]
		ioProfileText(
			ew,
			ioProfileMargin,
			y,
			12,
			fmt.Sprintf(
				"%s: %d operations; accumulated duration %.3f ms",
				outcome,
				stats.Count,
				float64(stats.DurationNS)/1e6,
			),
		)
		y += ioProfileTextHeight
	}
	ioProfileText(
		ew,
		ioProfileMargin,
		y,
		12,
		fmt.Sprintf("Completed paths (%d of %d; largest byte totals and highest mean delays)", len(p.rows), p.totalRows),
	)
	y += ioProfileTextHeight
	ioProfileText(
		ew,
		ioProfileMargin,
		y,
		11,
		"Path                                                       Bytes             Count          "+
			"Mean size (B)       Mean delay (ms)",
	)
	y += ioProfileTextHeight
	for i := range p.rows {
		row := &p.rows[i]
		// Keep the full path in XML metadata while leaving numeric columns visible.
		ew.printf(`<g><title>%s</title>`+"\n", html.EscapeString(row.path))
		displayPath := []rune(row.path)
		if len(displayPath) > 75 {
			displayPath = append([]rune("..."), displayPath[len(displayPath)-72:]...)
		}
		ew.printf(
			`<text x="%d" y="%d" font-family="monospace" font-size="11">%s</text>`+"\n",
			ioProfileMargin,
			y,
			fitIOProfileText(string(displayPath), 600),
		)
		ioProfileText(
			ew,
			650,
			y,
			11,
			fmt.Sprintf("%d", row.stats.Bytes),
		)
		ioProfileText(
			ew,
			800,
			y,
			11,
			fmt.Sprintf("%d", row.stats.Count),
		)
		ioProfileText(
			ew,
			930,
			y,
			11,
			fmt.Sprintf("%.1f", row.stats.MeanSizeBytes()),
		)
		ioProfileText(
			ew,
			1095,
			y,
			11,
			fmt.Sprintf("%.3f", row.stats.MeanDurationNS()/1e6),
		)
		ew.println("</g>")
		y += ioProfileTextHeight
	}
}

func (p *ioProfilePanel) drawNode(
	ew *errWriter,
	node *ioprofile.Node,
	depth int,
	left int64,
	top int,
) {
	usable := float64(ioProfileImageWidth - 2*ioProfileMargin)
	total := float64(p.group.Root.Stats.Bytes)
	x := ioProfileMargin + float64(left)/total*usable
	width := float64(node.Stats.Bytes) / total * usable
	y := top + (p.depth-depth-1)*ioProfileFrameHeight
	name := node.Frame.Name
	if node.IsKernel {
		name += " [kernel]"
	}
	color := ioProfileLatencyColor(node.Stats.MeanDurationNS())
	if name == "[unknown user stack]" {
		color = "#b6bec7"
	}
	title := name + "; " + statsText(node.Stats)
	if node.Frame.File != "" {
		title += fmt.Sprintf("; %s:%d", node.Frame.File, node.Frame.Line)
	}
	ew.printf(
		`<g><title>%s</title><rect x="%.3f" y="%d" width="%.3f" height="%d" `+
			`fill="%s" stroke="white" stroke-width="0.5"/>`+"\n",
		html.EscapeString(title),
		x,
		y,
		width,
		ioProfileFrameHeight,
		color,
	)
	ew.printf(
		`<text x="%.3f" y="%d" font-family="Verdana" font-size="11">%s</text></g>`+"\n",
		x+3,
		y+13,
		fitIOProfileText(name, width-6),
	)
	childLeft := left
	for _, child := range node.Children {
		p.drawNode(
			ew,
			child,
			depth+1,
			childLeft,
			top,
		)
		childLeft += child.Stats.Bytes
	}
}

func fitIOProfileText(text string, width float64) string {
	characters := int(width / 6.8)
	if characters < 3 {
		return ""
	}
	runes := []rune(text)
	if len(runes) > characters {
		return html.EscapeString(string(runes[:characters-2])) + ".."
	}

	return html.EscapeString(string(runes))
}

func ioProfileLatencyColor(latencyNS float64) string {
	t := math.Log10(max(latencyNS, ioProfileMinLatencyNS)/ioProfileMinLatencyNS) /
		math.Log10(ioProfileMaxLatencyNS/ioProfileMinLatencyNS)
	t = min(t, 1)
	start, end := [3]float64{65, 171, 93}, [3]float64{254, 224, 139}
	if t > 0.5 {
		start, end = end, [3]float64{215, 48, 39}
		t = (t - 0.5) * 2
	} else {
		t *= 2
	}

	return fmt.Sprintf(
		"rgb(%d,%d,%d)",
		int(start[0]+(end[0]-start[0])*t),
		int(start[1]+(end[1]-start[1])*t),
		int(start[2]+(end[2]-start[2])*t),
	)
}

func statsText(stats ioprofile.Stats) string {
	if stats.Count == 0 {
		return fmt.Sprintf("%d bytes; 0 operations; mean size n/a; mean latency n/a", stats.Bytes)
	}

	return fmt.Sprintf(
		"%d bytes; %d operations; mean size %.1f B; mean latency %.3f ms",
		stats.Bytes,
		stats.Count,
		stats.MeanSizeBytes(),
		stats.MeanDurationNS()/1e6,
	)
}

func ioProfileText(
	ew *errWriter,
	x,
	y,
	size int,
	text string,
) {
	ew.printf(
		`<text x="%d" y="%d" font-family="Verdana" font-size="%d" fill="#233044">%s</text>`+"\n",
		x,
		y,
		size,
		html.EscapeString(text),
	)
}

func sortedOutcomeKeys(values map[string]ioprofile.Stats) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}
