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

// The existing disk trigger owns both captures. A bounded, optional handoff
// appends an IO graph to the original report without a second detector or store.
package autotracing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	internalconfig "github.com/ccfos/huatuo/internal/config"
	"github.com/ccfos/huatuo/internal/executil"
	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/internal/profiling/fileio"
	"github.com/ccfos/huatuo/internal/profiling/formatter/flamegraph"
	"github.com/ccfos/huatuo/internal/timeutil"
	"github.com/ccfos/huatuo/internal/toolstream"
	"github.com/ccfos/huatuo/pkg/profiling"
	"github.com/ccfos/huatuo/pkg/types"
)

const maxIOProfileBytes = 64 << 20

var pendingIOProfiles sync.Map

type ioProfileSummary struct {
	Scope       string                    `json:"scope"`
	ContainerID string                    `json:"container_id,omitempty"`
	Container   *types.ProfilingContainer `json:"container,omitempty"`
	Direction   string                    `json:"direction"`
	Stats       fileio.Stats              `json:"stats"`
	Unknown     fileio.Stats              `json:"unknown"`
	Outcomes    map[string]fileio.Stats   `json:"outcomes,omitempty"`
}

type ioProfileReport struct {
	StartedTimestamp timeutil.Timestamp `json:"started_timestamp"`
	DurationNS       int64              `json:"duration_ns"`
	Groups           []ioProfileSummary `json:"groups"`
	Diagnostics      map[string]uint64  `json:"diagnostics"`
	NumericComplete  bool               `json:"numeric_complete"`
	FlamegraphSVG    string             `json:"flamegraph_svg"`
}

type pendingIOProfile struct {
	ready  chan struct{}
	once   sync.Once
	cancel context.CancelFunc
	report *ioProfileReport
	err    error
}

func newPendingIOProfile(cancel context.CancelFunc) *pendingIOProfile {
	return &pendingIOProfile{
		ready:  make(chan struct{}),
		cancel: cancel,
	}
}

func (p *pendingIOProfile) complete(report *ioProfileReport, err error) bool {
	accepted := false
	p.once.Do(func() {
		p.report, p.err = report, err
		accepted = true
		close(p.ready)
	})
	return accepted
}

func (p *pendingIOProfile) wait(ctx context.Context) (*ioProfileReport, error) {
	if p == nil {
		return nil, nil
	}
	timer := time.NewTimer(iotracingSnapshotTimeout)
	defer timer.Stop()
	select {
	case <-p.ready:
	case <-ctx.Done():
		p.complete(nil, context.Cause(ctx))
		p.cancel()
	case <-timer.C:
		p.complete(nil, errors.New("IO graph was not ready within the snapshot handoff budget"))
		p.cancel()
	}
	<-p.ready
	return p.report, p.err
}

type ioProfileSVGBuffer struct{ bytes.Buffer }

func (b *ioProfileSVGBuffer) Write(data []byte) (int, error) {
	if len(data) > maxIOProfileBytes-b.Len() {
		return 0, errors.New("IO flamegraph exceeds its output budget")
	}
	return b.Buffer.Write(data)
}

func init() {
	toolstream.RegisterDefault[types.ProfilingWindow](profiling.IOCaptureServiceName, handleIOProfileCapture)
}

func handleIOProfileCapture(ctx context.Context, request *toolstream.Request[types.ProfilingWindow]) error {
	value, exists := pendingIOProfiles.LoadAndDelete(request.TaskID)
	if !exists {
		return errors.New("IO profile has no pending disk trigger")
	}
	pending := value.(*pendingIOProfile)
	report, err := decodeIOProfileCapture(ctx, request.Data)
	if !pending.complete(report, err) {
		return errors.New("IO profile trigger no longer accepts a capture")
	}
	return err
}

func decodeIOProfileCapture(ctx context.Context, window *types.ProfilingWindow) (*ioProfileReport, error) {
	if window == nil || window.Profile == nil || window.ProfileType != fileio.ProfileType || window.ContainerID != "" || len(window.DroppedSamples) != 0 {
		return nil, errors.New("IO event requires one complete capture")
	}
	if proto.Size(window.Profile) > maxIOProfileBytes {
		return nil, errors.New("IO capture exceeds its output budget")
	}
	data, err := fileio.Decode(window.Profile)
	if err != nil {
		return nil, err
	}
	var svg ioProfileSVGBuffer
	if err := flamegraph.RenderFileIO(ctx, &svg, data.Groups, data.Diagnostics); err != nil {
		return nil, err
	}
	report := &ioProfileReport{
		StartedTimestamp: timeutil.Timestamp{Time: time.Unix(0, window.Profile.TimeNanos).UTC()},
		DurationNS:       window.Profile.DurationNanos,
		Diagnostics:      data.Diagnostics,
		NumericComplete:  data.NumericComplete,
		FlamegraphSVG:    svg.String(),
		Groups:           make([]ioProfileSummary, 0, len(data.Groups)),
	}
	for i := range data.Groups {
		group := &data.Groups[i]
		report.Groups = append(report.Groups, ioProfileSummary{
			Scope:       group.Scope,
			ContainerID: group.ContainerID,
			Container:   group.Container,
			Direction:   group.Direction,
			Stats:       group.Root.Stats,
			Unknown:     group.Unknown,
			Outcomes:    group.Outcomes,
		})
	}
	return report, nil
}

func runIOProfileCommand(parent context.Context, taskID string, durationSeconds uint64, spec *profiling.Spec) error {
	if durationSeconds == 0 || durationSeconds > uint64(maxProfileDurationSeconds) {
		return errors.New("IO profile duration exceeds its supported range")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(durationSeconds)*time.Second+profileCompletionGracePeriod)
	defer cancel()
	manager := pod.ManagerConfig()
	args := []string{
		"--type", "io", "--language", "c", "--duration", strconv.FormatUint(durationSeconds, 10),
		"--io-stack-mode", string(spec.Mode), "--output-format", "autotracing", "--output-path", toolstream.DefaultSockPath, "--task-id", taskID,
		"--kubelet-read-only-port", strconv.FormatUint(uint64(manager.PodReadOnlyPort), 10),
		"--kubelet-authorized-port", strconv.FormatUint(uint64(manager.PodAuthorizedPort), 10),
		"--kubelet-client-cert-path", manager.PodClientCertPath, "--docker-api-version", manager.DockerAPIVersion,
	}
	if spec.Mode == profiling.ModeIOTime {
		args = append(args, "--io-stack-interval", strconv.FormatUint(spec.IOSampleIntervalUS, 10)+"us")
	} else {
		args = append(args, "--io-stack-every", strconv.FormatUint(spec.IOSampleEvery, 10))
	}
	result, err := executil.Run(ctx, executil.Spec{
		Path:           filepath.Join(internalconfig.CoreBinDir, "profiler"),
		Args:           args,
		MaxStdoutBytes: 4 << 10,
		MaxStderrBytes: 4 << 10,
	})
	if err != nil {
		return fmt.Errorf("run triggered IO profile: %w; stderr: %s", err, result.Stderr)
	}
	return nil
}
