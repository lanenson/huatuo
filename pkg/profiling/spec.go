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
	"fmt"
	"math"
	"slices"
	"time"
)

// Spec contains stable profiling service parameters.
type Spec struct {
	Type               Type     `json:"type"`
	Language           Language `json:"language"`
	Mode               Mode     `json:"mode"`
	BinaryMatchPath    string   `json:"binary_match_path,omitempty"`
	IOSampleIntervalUS uint64   `json:"io_sample_interval_us,omitempty"`
	IOSampleEvery      uint64   `json:"io_sample_every,omitempty"`
}

// Validate checks the profiling parameter combination against static capabilities.
func (s *Spec) Validate() error {
	if _, err := ParseType(string(s.Type)); err != nil {
		return err
	}
	if _, err := ParseLanguage(string(s.Language)); err != nil {
		return err
	}
	if _, err := ParseMode(string(s.Mode)); err != nil {
		return err
	}

	capability, ok := capabilityFor(s.Language, s.Type)
	if !ok {
		return fmt.Errorf(
			"profiling type %q is not supported for language %q",
			s.Type,
			s.Language,
		)
	}
	if !slices.Contains(capability.Modes, s.Mode) {
		return fmt.Errorf(
			"profiling mode %q is not supported for type %q and language %q",
			s.Mode,
			s.Type,
			s.Language,
		)
	}
	if s.BinaryMatchPath != "" && !capability.SupportsBinaryMatch {
		return fmt.Errorf(
			"binary match path is not supported for type %q and language %q",
			s.Type,
			s.Language,
		)
	}

	return s.validateIOSampling()
}

func (s *Spec) validateIOSampling() error {
	if s.Type != TypeIO {
		if s.IOSampleIntervalUS != 0 || s.IOSampleEvery != 0 {
			return fmt.Errorf("IO sampling parameters require profiling type io")
		}
		return nil
	}

	switch s.Mode {
	case ModeIOTime:
		if s.IOSampleIntervalUS == 0 || s.IOSampleIntervalUS > uint64(math.MaxInt64/int64(time.Microsecond)) {
			return fmt.Errorf(
				"io_sample_interval_us must be between 1 and %d for mode time",
				math.MaxInt64/int64(time.Microsecond),
			)
		}
		if s.IOSampleEvery != 0 {
			return fmt.Errorf("io_sample_every is not allowed for mode time")
		}
	case ModeIOCount:
		if s.IOSampleEvery == 0 {
			return fmt.Errorf("io_sample_every must be positive for mode count")
		}
		if s.IOSampleIntervalUS != 0 {
			return fmt.Errorf("io_sample_interval_us is not allowed for mode count")
		}
	}

	return nil
}
