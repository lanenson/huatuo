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
// attribution. Panel summaries remain visible in static exports.
package ioprofile

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"io"
	"math"
	"strings"
)

const (
	ioProfileImageWidth   = 1280
	ioProfileFrameHeight  = 18
	ioProfileMargin       = 24
	ioProfileTextHeight   = 19
	ioProfileMinLatencyNS = 10000.0
	ioProfileMaxLatencyNS = 100000000.0
)

type ioProfilePanel struct {
	group  *Group
	depth  int
	height int
}

// RenderSVG writes separate scope/direction panels into a single static SVG.
// The result must come from Decode; the caller owns output.
func RenderSVG(
	ctx context.Context,
	out io.Writer,
	result *Result,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var panels []ioProfilePanel
	y := 145
	if !result.NumericComplete {
		y = 185
	}
	height := y + 30
	groups := result.Groups
	for i := range groups {
		panel := ioProfilePanel{
			group: &groups[i],
			depth: ioProfileDepth(groups[i].Root),
		}
		panel.height = 100 + panel.depth*ioProfileFrameHeight
		if panel.group.FailedOperations != 0 {
			panel.height += ioProfileTextHeight
		}
		if len(groups[i].Root.Labels) != 0 {
			panel.height += ioProfileTextHeight
		}
		height += panel.height
		panels = append(panels, panel)
	}
	if len(panels) == 0 {
		height += 40
	}
	w := bufio.NewWriter(out)
	fmt.Fprintln(w, `<?xml version="1.0" standalone="no"?>`)
	fmt.Fprintf(w,
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`+"\n",
		ioProfileImageWidth,
		height,
		ioProfileImageWidth,
		height,
	)
	fmt.Fprintf(w, `<rect width="%d" height="%d" fill="#ffffff"/>`+"\n", ioProfileImageWidth, height)
	ioProfileText(
		w,
		ioProfileMargin,
		30,
		20,
		"File IO profiles: measured bytes and mean operation latency",
	)
	ioProfileText(
		w,
		ioProfileMargin,
		55,
		12,
		"Numeric values are measured without scaling; stacks are periodic representatives, "+
			"not exact per-function attribution.",
	)
	ioProfileText(
		w,
		ioProfileMargin,
		74,
		12,
		"Host includes containers and other. Each panel has its own byte scale; do not add host and container totals.",
	)
	ioProfileText(
		w,
		ioProfileMargin,
		93,
		12,
		"Green means lower mean file-operation latency, not disk health. "+
			"Width is successful returned bytes; parent frames include children.",
	)
	for i := 0; i < 200; i++ {
		latency := ioProfileMinLatencyNS * math.Pow(ioProfileMaxLatencyNS/ioProfileMinLatencyNS, float64(i)/199)
		fmt.Fprintf(w,
			`<rect x="%d" y="108" width="3" height="14" fill="%s"/>`+"\n",
			ioProfileMargin+i*3,
			ioProfileLatencyColor(latency),
		)
	}
	ioProfileText(
		w,
		ioProfileMargin,
		138,
		11,
		"10 us                 100 us                  1 ms                  10 ms                 100 ms (fixed log scale)",
	)
	if !result.NumericComplete {
		fmt.Fprintf(w, `<rect x="%d" y="147" width="%d" height="26" fill="#fff0f0"/>`+"\n",
			ioProfileMargin, ioProfileImageWidth-2*ioProfileMargin)
		fmt.Fprintf(w,
			`<text x="%d" y="164" font-family="Verdana" font-size="13" font-weight="bold" fill="#a4161a">`+
				`INCOMPLETE: numeric data loss detected; totals and mean latencies describe retained operations only.</text>`+"\n",
			ioProfileMargin+6,
		)
	}
	if len(panels) == 0 {
		ioProfileText(
			w,
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
		panels[i].render(w, y)
		y += panels[i].height
	}
	fmt.Fprintln(w, "</svg>")

	return w.Flush()
}

func ioProfileDepth(node *Node) int {
	var depth int
	for _, child := range node.Children {
		depth = max(depth, ioProfileDepth(child))
	}
	return depth + 1
}

func (p *ioProfilePanel) render(w *bufio.Writer, top int) {
	group := p.group
	title := strings.ToUpper(group.Direction) + " / " + group.Scope
	if group.ContainerID != "" {
		title += " / " + group.ContainerID
	}
	ioProfileText(
		w,
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
		ioProfileText(w, ioProfileMargin, top+39, 12,
			fmt.Sprintf("Container: %s / %s / type: %s / QoS: %s", hostname, shortID, containerType, qos))
		top += ioProfileTextHeight
	}
	ioProfileText(
		w,
		ioProfileMargin,
		top+42,
		12,
		statsText(group.Root.Stats),
	)
	graphTop := top + 60
	if group.Root.Stats.Bytes > 0 {
		p.drawNode(
			w,
			group.Root,
			0,
			0,
			graphTop,
		)
	} else {
		ioProfileText(
			w,
			ioProfileMargin,
			graphTop+15,
			12,
			"No bytes were read or written.",
		)
	}
	if group.FailedOperations != 0 {
		ioProfileText(
			w,
			ioProfileMargin,
			graphTop+p.depth*ioProfileFrameHeight+22,
			12,
			fmt.Sprintf("Failed operations: %d", group.FailedOperations),
		)
	}
}

func (p *ioProfilePanel) drawNode(
	w *bufio.Writer,
	node *Node,
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
	fmt.Fprintf(w,
		`<g><title>%s</title><rect x="%.3f" y="%d" width="%.3f" height="%d" `+
			`fill="%s" stroke="white" stroke-width="0.5"/>`+"\n",
		html.EscapeString(title),
		x,
		y,
		width,
		ioProfileFrameHeight,
		color,
	)
	fmt.Fprintf(w,
		`<text x="%.3f" y="%d" font-family="Verdana" font-size="11">%s</text></g>`+"\n",
		x+3,
		y+13,
		fitIOProfileText(name, width-6),
	)
	childLeft := left
	for _, child := range node.Children {
		p.drawNode(
			w,
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

func statsText(stats Stats) string {
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
	w *bufio.Writer,
	x,
	y,
	size int,
	text string,
) {
	fmt.Fprintf(w,
		`<text x="%d" y="%d" font-family="Verdana" font-size="%d" fill="#233044">%s</text>`+"\n",
		x,
		y,
		size,
		html.EscapeString(text),
	)
}
