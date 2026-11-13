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

package flamegraph

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/internal/profiling/fileio"
	"github.com/ccfos/huatuo/pkg/types"
)

func TestRenderKeepsSymbolsOutOfJavaScript(t *testing.T) {
	symbol := `');alert(1);//<script>alert(2)</script>`
	var proc processor
	proc.Process(Stack{
		Names:   []string{"root", symbol},
		Samples: 1,
	})

	var output bytes.Buffer
	if err := proc.render(&output, DefaultStyle); err != nil {
		t.Fatalf("render flame graph: %v", err)
	}

	content := output.String()
	if strings.Contains(content, `onmouseover="s('`) ||
		strings.Contains(content, "<script>alert(2)</script>") {
		t.Fatalf("SVG embeds an untrusted symbol as executable markup: %s", content)
	}

	if !strings.Contains(content, `data-title="`) ||
		!strings.Contains(content, "&lt;script&gt;alert(2)&lt;/script&gt;") {
		t.Fatalf("SVG does not preserve the escaped symbol as data: %s", content)
	}
}

func fileIOLabels(container string) []types.ProfileLabel {
	attribution := fileio.ScopeOther
	labels := []types.ProfileLabel{types.ProfileStringLabel("direction", "read"), types.ProfileStringLabel("result", "success"), types.ProfilePIDLabel(10)}
	if container != "" {
		attribution = fileio.ScopeContainer
		labels = append(labels, types.ProfileStringLabel("container_id", container), types.ProfileStringLabel("container_hostname", "worker"), types.ProfileStringLabel("container_type", "normal"), types.ProfileStringLabel("container_qos", "burstable"))
	}
	return append(labels, types.ProfileStringLabel("attribution", attribution))
}

func fileIOCapture(t *testing.T) *profilev1.Profile {
	t.Helper()
	builder := fileio.NewBuilder(1, 10000000000)
	for _, container := range []string{"container-a", ""} {
		if err := builder.Add([]types.ProfileFrame{{Name: "main"}, {Name: "read_file"}}, fileIOLabels(container), fileio.Stats{
			Bytes:      4096,
			Count:      1,
			DurationNS: 1000000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := builder.AddDiagnostic("stack_attempt", 2); err != nil {
		t.Fatal(err)
	}
	capture, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

func TestFileIOSingleCaptureKeepsValuesTogether(t *testing.T) {
	capture := fileIOCapture(t)
	result, err := fileio.Decode(capture)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.SampleType) != 4 || len(result.Groups) != 3 || result.Groups[0].Scope != fileio.ScopeHost || result.Groups[0].Root.Stats != (fileio.Stats{
		Bytes:      8192,
		Count:      2,
		DurationNS: 2000000,
	}) || result.Diagnostics["stack_attempt"] != 2 {
		t.Fatalf("joint capture lost values: %+v", result)
	}
	if result.Groups[1].Container == nil || result.Groups[1].Container.Hostname != "worker" || result.Groups[1].Container.QoS != "burstable" {
		t.Fatal("container classification was lost")
	}
	if !result.NumericComplete {
		t.Fatal("complete capture reported numeric loss")
	}
}

func TestFileIORejectsInvalidCapture(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*profilev1.Profile)
	}{
		{
			name:   "missing value type",
			mutate: func(p *profilev1.Profile) { p.SampleType = p.SampleType[:3] },
		},
		{
			name:   "missing row value",
			mutate: func(p *profilev1.Profile) { p.Sample[0].Value = p.Sample[0].Value[:3] },
		},
		{
			name:   "negative count",
			mutate: func(p *profilev1.Profile) { p.Sample[0].Value[1] = -1 },
		},
		{
			name:   "missing location",
			mutate: func(p *profilev1.Profile) { p.Sample[0].LocationId = []uint64{9999} },
		},
		{
			name:   "negative duration",
			mutate: func(p *profilev1.Profile) { p.DurationNanos = -1 },
		},
		{
			name:   "duplicate value type",
			mutate: func(p *profilev1.Profile) { p.SampleType[1] = p.SampleType[0] },
		},
		{
			name:   "missing string",
			mutate: func(p *profilev1.Profile) { p.Sample[0].Label[0].Key = 9999 },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := fileIOCapture(t)
			test.mutate(p)
			if _, err := fileio.Decode(p); err == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

func TestFileIOUnknownErrorsAndLoss(t *testing.T) {
	builder := fileio.NewBuilder(1, 1000000000)
	if err := builder.Add(nil, fileIOLabels(""), fileio.Stats{
		Bytes:      4096,
		Count:      1,
		DurationNS: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	labels := fileIOLabels("")
	for i := range labels {
		if labels[i].Name == "result" {
			labels[i].StringValue = "error"
		}
	}
	if err := builder.Add(nil, labels, fileio.Stats{
		Count:      2,
		DurationNS: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := builder.AddDiagnostic("aggregate_failure", 1); err != nil {
		t.Fatal(err)
	}
	capture, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := fileio.Decode(capture)
	if err != nil {
		t.Fatal(err)
	}
	if result.NumericComplete || result.Groups[0].Unknown.Bytes != 4096 || result.Groups[0].Outcomes["error"].Count != 2 || result.Groups[0].Root.Stats.Count != 1 {
		t.Fatalf("error/unknown/loss semantics changed: %+v", result)
	}
	var svg bytes.Buffer
	if err := RenderFileIO(t.Context(), &svg, result.Groups, result.Diagnostics); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(svg.String(), "INCOMPLETE") || !strings.Contains(svg.String(), "error: 2 operations") {
		t.Fatal("loss or outcome not visible")
	}
}

func TestFileIOCaptureRejectsOverflow(t *testing.T) {
	builder := fileio.NewBuilder(1, 1000000000)
	for i := 0; i < 2; i++ {
		if err := builder.Add(nil, fileIOLabels(""), fileio.Stats{
			Bytes:      math.MaxInt64,
			Count:      1,
			DurationNS: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	capture, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fileio.Decode(capture); err == nil {
		t.Fatal("overflowed capture accepted")
	}
}

func TestFileIOSVGEncodesBytesSelfAndMeanLatency(t *testing.T) {
	builder := fileio.NewBuilder(1, 1000000000)
	for _, sample := range []struct {
		name  string
		stats fileio.Stats
	}{
		{
			name: "parent",
			stats: fileio.Stats{
				Bytes:      20,
				Count:      1,
				DurationNS: 2000000,
			},
		},
		{
			name: "fast",
			stats: fileio.Stats{
				Bytes:      40,
				Count:      4,
				DurationNS: 40000,
			},
		},
		{
			name: "middle",
			stats: fileio.Stats{
				Bytes:      20,
				Count:      2,
				DurationNS: 2000000,
			},
		},
		{
			name: "slow",
			stats: fileio.Stats{
				Bytes:      20,
				Count:      1,
				DurationNS: 100000000,
			},
		},
	} {
		frames := []types.ProfileFrame{{Name: "parent"}}
		if sample.name != "parent" {
			frames = append(frames, types.ProfileFrame{Name: sample.name})
		}
		if err := builder.Add(frames, fileIOLabels(""), sample.stats); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := fileio.Decode(profile)
	if err != nil {
		t.Fatal(err)
	}
	groups := result.Groups
	var image bytes.Buffer
	if err := RenderFileIO(t.Context(), &image, groups, nil); err != nil {
		t.Fatal(err)
	}
	type rectangle struct {
		X     string `xml:"x,attr"`
		Width string `xml:"width,attr"`
		Fill  string `xml:"fill,attr"`
	}
	type frame struct {
		Title string    `xml:"title"`
		Rect  rectangle `xml:"rect"`
	}
	frames := make(map[string]frame)
	decoder := xml.NewDecoder(&image)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "g" {
			continue
		}
		var current frame
		if err := decoder.DecodeElement(&current, &start); err != nil {
			t.Fatal(err)
		}
		name := strings.SplitN(current.Title, ";", 2)[0]
		if _, exists := frames[name]; !exists {
			frames[name] = current
		}
	}
	number := func(t *testing.T, value string) float64 {
		t.Helper()
		result, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	parent := frames["parent"]
	width := number(t, parent.Rect.Width)
	if width <= 0 {
		t.Fatal("parent has no byte width")
	}
	childWidth := 0.0
	parentX := number(t, parent.Rect.X)
	for _, test := range []struct {
		name  string
		ratio float64
		left  float64
		color string
	}{
		{
			name:  "fast",
			ratio: 0.4,
			color: "rgb(65,171,93)",
		},
		{
			name:  "middle",
			ratio: 0.2,
			left:  0.4,
			color: "rgb(254,224,139)",
		},
		{
			name:  "slow",
			ratio: 0.2,
			left:  0.6,
			color: "rgb(215,48,39)",
		},
	} {
		current := frames[test.name]
		actualWidth := number(t, current.Rect.Width)
		childWidth += actualWidth
		t.Run(test.name, func(t *testing.T) {
			nextX := parentX + width*test.left
			if math.Abs(actualWidth-width*test.ratio) > 0.002 || math.Abs(number(t, current.Rect.X)-nextX) > 0.002 {
				t.Fatalf("frame width/position = %+v, want ratio %g at x=%g", current.Rect, test.ratio, nextX)
			}
			if current.Rect.Fill != test.color {
				t.Fatalf("mean-latency color = %q, want %q", current.Rect.Fill, test.color)
			}
		})
	}
	if math.Abs(width-childWidth-width*0.2) > 0.002 {
		t.Fatal("parent self bytes did not leave 20 percent blank space")
	}
}
