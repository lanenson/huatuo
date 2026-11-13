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

package handlers

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/ccfos/huatuo/apis/v1"
	serverapi "github.com/ccfos/huatuo/apis/v1/server"
	profilinghandler "github.com/ccfos/huatuo/cmd/huatuo-apiserver/handlers/profiling"
	"github.com/ccfos/huatuo/internal/httpserver/response"
	"github.com/ccfos/huatuo/internal/job"
	"github.com/ccfos/huatuo/internal/profiling/fileio"
	"github.com/ccfos/huatuo/pkg/observation"
	profilingdomain "github.com/ccfos/huatuo/pkg/profiling"
	tracingdomain "github.com/ccfos/huatuo/pkg/tracing"
	"github.com/ccfos/huatuo/pkg/types"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"
)

func TestGetReadiness(t *testing.T) {
	response, err := (&APIHandler{}).GetReadiness(
		t.Context(),
		serverapi.GetReadinessRequestObject{},
	)
	if err != nil {
		t.Fatalf("GetReadiness() error = %v", err)
	}
	if _, ok := response.(serverapi.GetReadiness204Response); !ok {
		t.Fatalf("GetReadiness() response = %T, want GetReadiness204Response", response)
	}
}

func TestCreateProfilingJobRejectsExplicitZeroIOSampling(t *testing.T) {
	zero, interval := uint64(0), uint64(1000)
	for _, test := range []struct {
		name     string
		interval *uint64
		every    *uint64
	}{
		{
			name:     "zero interval",
			interval: &zero,
		},
		{
			name:  "zero every",
			every: &zero,
		},
		{
			name:     "zero does not hide second parameter",
			interval: &interval,
			every:    &zero,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := (&APIHandler{}).CreateProfilingJob(t.Context(), serverapi.CreateProfilingJobRequestObject{
				Body: &serverapi.CreateProfilingJobJSONRequestBody{
					Type:               serverapi.ProfilingTypeIO,
					Language:           serverapi.ProfilingLanguageGo,
					Mode:               serverapi.ProfilingModeIOTime,
					IOSampleIntervalUS: test.interval,
					IOSampleEvery:      test.every,
				},
			})
			if err == nil || !strings.Contains(err.Error(), "must be positive") {
				t.Fatalf("CreateProfilingJob() error = %v", err)
			}
		})
	}
}

func TestMapProfilingJobPreservesIOSampling(t *testing.T) {
	for _, mode := range []profilingdomain.Mode{profilingdomain.ModeIOTime, profilingdomain.ModeIOCount} {
		t.Run(string(mode), func(t *testing.T) {
			spec := &profilingdomain.Spec{
				Type:     profilingdomain.TypeIO,
				Language: profilingdomain.LanguageGo,
				Mode:     mode,
			}
			if mode == profilingdomain.ModeIOTime {
				spec.IOSampleIntervalUS = 1000
			} else {
				spec.IOSampleEvery = 100
			}
			got := mapProfilingJob(&job.Job{
				ID:   "io-job",
				Kind: job.KindProfiling,
				Spec: job.Spec{Profiling: spec},
			})
			if got.Type != serverapi.ProfilingTypeIO || string(got.Mode) != string(mode) {
				t.Fatalf("lost IO type or mode: %+v", got)
			}
			if mode == profilingdomain.ModeIOTime {
				if got.IOSampleIntervalUS == nil || *got.IOSampleIntervalUS != 1000 || got.IOSampleEvery != nil {
					t.Fatalf("lost IO time setting: %+v", got)
				}
			} else if got.IOSampleEvery == nil || *got.IOSampleEvery != 100 || got.IOSampleIntervalUS != nil {
				t.Fatalf("lost IO count setting: %+v", got)
			}
		})
	}
}

func TestStartRejectsMissingAuthUsers(t *testing.T) {
	_, err := Start(&ServerOptions{JobManager: &job.Manager{}})
	if err == nil || !strings.Contains(err.Error(), "at least one auth user is required") {
		t.Fatalf("Start() error = %v, want missing auth user error", err)
	}
}

func TestMapCommonJobMapsTerminalFailure(t *testing.T) {
	base := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	input := &job.Job{
		ID:        "job-1",
		Hostname:  "node-1",
		Duration:  time.Minute,
		Scope:     observation.ScopeHost,
		Status:    job.StatusTerminal,
		CreatedAt: base,
		UpdatedAt: base.Add(time.Second),
		EndedAt:   base.Add(time.Minute),
		Terminal: &job.TerminalResult{
			Outcome: job.OutcomeFailed,
			Reason:  job.FailureReasonOperationLost,
			Message: "Node no longer has the Operation",
		},
	}

	got := mapCommonJob(input)
	if got.Status != serverapi.JobStatusTerminal || got.Terminal == nil {
		t.Fatalf("mapCommonJob() = %+v", got)
	}
	if got.Terminal.Outcome != serverapi.JobOutcomeFailed || got.Terminal.Reason == nil ||
		*got.Terminal.Reason != string(job.FailureReasonOperationLost) {
		t.Fatalf("terminal = %+v", got.Terminal)
	}
	if got.EndedAt == nil || !got.EndedAt.Equal(input.EndedAt) {
		t.Fatalf("ended_at = %v", got.EndedAt)
	}
}

func TestMapTracingJobUsesIndependentDomainState(t *testing.T) {
	input := &job.Job{
		ID:       "job-1",
		Kind:     job.KindTracing,
		Hostname: "node-1",
		Duration: time.Minute,
		Scope:    observation.ScopeHost,
		Status:   job.StatusTerminal,
		Terminal: &job.TerminalResult{Outcome: job.OutcomeUnknown},
		Spec: job.Spec{Tracing: &tracingdomain.Spec{
			Type: tracingdomain.TypeNetworkingDrop,
		}},
	}
	got := mapTracingJob(input)
	if got.Status != serverapi.JobStatusTerminal || got.Terminal == nil ||
		got.Terminal.Outcome != serverapi.JobOutcomeUnknown {
		t.Fatalf("mapTracingJob() = %+v", got)
	}
}

func TestServerAPIErrorMapsStableResultErrors(t *testing.T) {
	tests := []struct {
		err      error
		wantCode apiv1.ErrorCode
	}{
		{err: profilinghandler.ErrResultNotReady, wantCode: serverapi.ErrorCodeResultNotReady},
		{err: profilinghandler.ErrResultNotFound, wantCode: serverapi.ErrorCodeResultNotFound},
		{err: profilinghandler.ErrResultUnavailable, wantCode: serverapi.ErrorCodeResultUnavailable},
		{err: errRawProfileResponseTooLarge, wantCode: serverapi.ErrorCodeResultTooLarge},
		{
			err:      profilinghandler.ErrResultTooLarge,
			wantCode: serverapi.ErrorCodeResultTooLarge,
		},
		{err: job.ErrQuotaExceeded, wantCode: serverapi.ErrorCodeQuotaExceeded},
		{err: job.ErrNotFound, wantCode: serverapi.ErrorCodeJobNotFound},
		{err: job.ErrJobNotSupervised, wantCode: apiv1.ErrorCodeServiceUnavailable},
	}
	for _, tt := range tests {
		mapped := serverAPIError(tt.err)
		var apiErr *response.APIError
		if !errors.As(mapped, &apiErr) || apiErr.Code != tt.wantCode {
			t.Fatalf("serverAPIError(%v) = %v, want code %q", tt.err, mapped, tt.wantCode)
		}
	}
}

func TestRawProfilesRejectsOversizedEncodedPage(t *testing.T) {
	_, err := rawProfiles([]*profilinghandler.RawProfile{{
		Profile: &profilev1.Profile{StringTable: []string{"profile payload"}},
	}}, 1)
	if !errors.Is(err, errRawProfileResponseTooLarge) {
		t.Fatalf("rawProfiles() error = %v, want ErrResponseTooLarge", err)
	}
}

func TestFileIOResponseMappingPreservesFields(t *testing.T) {
	stats := fileio.Stats{
		Bytes:      1<<53 + 1,
		Count:      1,
		DurationNS: math.MaxInt64,
	}
	source := fileio.Group{
		Scope:       fileio.ScopeContainer,
		Direction:   fileio.DirectionWrite,
		ContainerID: "container-id",
		Container: &types.ProfilingContainer{
			ID:            "container-id",
			Hostname:      "container-host",
			HostNamespace: "namespace",
			Type:          "docker",
			QoS:           "burstable",
		},
		Root: &fileio.Node{
			Frame: types.ProfileFrame{
				Name: "root",
				File: "source.c",
				Line: 123,
			},
			IsKernel: true,
			Stats:    stats,
			Self:     stats,
			Labels: []types.ProfileLabel{
				{
					Name:        "string",
					Kind:        types.ProfileLabelString,
					StringValue: "value",
				},
				{
					Name:        "number",
					Kind:        types.ProfileLabelNumber,
					NumberValue: math.MaxInt64,
					NumberUnit:  "bytes",
				},
			},
			Children: []*fileio.Node{{
				Frame: types.ProfileFrame{Name: "child"},
				Stats: stats,
				Self:  stats,
			}},
		},
		Unknown:        stats,
		DroppedSamples: map[string]uint64{"collection": math.MaxUint64},
		Outcomes:       map[string]fileio.Stats{"error": stats},
	}
	encoded, err := json.Marshal(fileIOGroup(&source))
	if err != nil {
		t.Fatal(err)
	}
	var restored fileio.Group
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source, restored) {
		t.Fatalf("IO response mapping changed fields: want %+v, got %+v", source, restored)
	}
}

func TestIOOversizedResultGivesApplicableGuidance(t *testing.T) {
	err := serverAPIError(profilinghandler.ErrResultTooLarge)
	if strings.Contains(err.Error(), "reduce limit") || !strings.Contains(err.Error(), "raw profiles") {
		t.Fatalf("IO size error has inapplicable guidance: %v", err)
	}
	rawErr := serverAPIError(errRawProfileResponseTooLarge)
	if !strings.Contains(rawErr.Error(), "reduce limit") {
		t.Fatalf("raw result lost pagination guidance: %v", rawErr)
	}
}
