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

package profiling

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSpecValidateAcceptsEveryCapabilityMode(t *testing.T) {
	t.Parallel()

	for _, capability := range Capabilities() {
		for _, mode := range capability.Modes {
			spec := Spec{
				Type:     capability.Type,
				Language: capability.Language,
				Mode:     mode,
			}
			if mode == ModeIOTime {
				spec.IOSampleIntervalUS = 1000
			} else if mode == ModeIOCount {
				spec.IOSampleEvery = 100
			}
			require.NoError(t, spec.Validate(), "%q/%q/%q", spec.Type, spec.Language, spec.Mode)

			if capability.SupportsBinaryMatch {
				spec.BinaryMatchPath = "/usr/bin/service"
				require.NoError(t, spec.Validate(), "%q/%q/%q", spec.Type, spec.Language, spec.Mode)
			}
		}
	}
}

func TestSpecValidateIOSampling(t *testing.T) {
	for _, test := range []struct {
		name      string
		typ       Type
		mode      Mode
		interval  uint64
		every     uint64
		wantError bool
	}{
		{
			name:     "time",
			typ:      TypeIO,
			mode:     ModeIOTime,
			interval: 1000,
		},
		{
			name:  "count",
			typ:   TypeIO,
			mode:  ModeIOCount,
			every: 100,
		},
		{
			name:      "time requires interval",
			typ:       TypeIO,
			mode:      ModeIOTime,
			wantError: true,
		},
		{
			name:      "count requires every",
			typ:       TypeIO,
			mode:      ModeIOCount,
			wantError: true,
		},
		{
			name:      "time rejects every",
			typ:       TypeIO,
			mode:      ModeIOTime,
			interval:  1000,
			every:     1,
			wantError: true,
		},
		{
			name:      "count rejects interval",
			typ:       TypeIO,
			mode:      ModeIOCount,
			interval:  1,
			every:     100,
			wantError: true,
		},
		{
			name:      "CPU rejects interval",
			typ:       TypeCPU,
			mode:      ModeOnCPU,
			interval:  1,
			wantError: true,
		},
		{
			name:      "CPU rejects every",
			typ:       TypeCPU,
			mode:      ModeOnCPU,
			every:     1,
			wantError: true,
		},
		{
			name:      "CPU rejects IO mode",
			typ:       TypeCPU,
			mode:      ModeIOCount,
			every:     1,
			wantError: true,
		},
		{
			name:      "interval overflow",
			typ:       TypeIO,
			mode:      ModeIOTime,
			interval:  uint64(math.MaxInt64/int64(time.Microsecond)) + 1,
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := Spec{
				Type:               test.typ,
				Language:           LanguageGo,
				Mode:               test.mode,
				IOSampleIntervalUS: test.interval,
				IOSampleEvery:      test.every,
			}
			if test.wantError {
				require.Error(t, spec.Validate())
			} else {
				require.NoError(t, spec.Validate())
			}
		})
	}
}

func TestSpecValidateRejectsInvalidCombination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		spec    Spec
		wantErr string
	}{
		{
			name:    "unknown type",
			spec:    Spec{Type: "lock", Language: LanguageGo, Mode: ModeOnCPU},
			wantErr: `unsupported profiling type "lock"`,
		},
		{
			name:    "unknown language",
			spec:    Spec{Type: TypeCPU, Language: "rust", Mode: ModeOnCPU},
			wantErr: `unsupported language "rust"`,
		},
		{
			name:    "unknown mode",
			spec:    Spec{Type: TypeCPU, Language: LanguageGo, Mode: "wall_clock"},
			wantErr: `unsupported profiling mode "wall_clock"`,
		},
		{
			name:    "unsupported type",
			spec:    Spec{Type: TypeMemory, Language: LanguagePython, Mode: ModeObjectAlloc},
			wantErr: `profiling type "memory" is not supported for language "python"`,
		},
		{
			name:    "CPU with memory mode",
			spec:    Spec{Type: TypeCPU, Language: LanguageGo, Mode: ModeObjectAlloc},
			wantErr: `profiling mode "object_alloc" is not supported for type "cpu" and language "go"`,
		},
		{
			name:    "Java with off CPU mode",
			spec:    Spec{Type: TypeCPU, Language: LanguageJava, Mode: ModeOffCPU},
			wantErr: `profiling mode "offcpu" is not supported for type "cpu" and language "java"`,
		},
		{
			name: "memory with binary match",
			spec: Spec{
				Type:            TypeMemory,
				Language:        LanguageJava,
				Mode:            ModeObjectAlloc,
				BinaryMatchPath: "/usr/bin/service",
			},
			wantErr: `binary match path is not supported for type "memory" and language "java"`,
		},
		{
			name: "native CPU with binary match",
			spec: Spec{
				Type:            TypeCPU,
				Language:        LanguageGo,
				Mode:            ModeOnCPU,
				BinaryMatchPath: "/usr/bin/service",
			},
			wantErr: `binary match path is not supported for type "cpu" and language "go"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.EqualError(t, tt.spec.Validate(), tt.wantErr)
		})
	}
}
