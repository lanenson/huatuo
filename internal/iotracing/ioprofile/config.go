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

// Profile configuration is owned by iotracing. Optional failures leave
// legacy diagnostics available.
package ioprofile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/bpf/abi"
	"github.com/ccfos/huatuo/internal/timeutil"
)

type SamplingMode string

const (
	ModeTime  SamplingMode = "io_time"
	ModeCount SamplingMode = "io_count"
)

type Config struct {
	PID           int
	CSSAddr       uint64
	CgroupID      uint64
	Duration      time.Duration
	Mode          SamplingMode
	Interval      time.Duration
	Every         uint64
	PIDStartTicks uint64
}

func (c Config) Validate() error {
	if c.Duration <= 0 {
		return errors.New("IO profile duration must be positive")
	}
	if c.PID < 0 || uint64(c.PID) > math.MaxUint32 {
		return errors.New("IO profile PID must fit uint32")
	}
	switch c.Mode {
	case ModeTime:
		if c.Interval <= 0 || c.Every != 0 {
			return errors.New("io_time requires a positive interval and zero operation count")
		}
	case ModeCount:
		if c.Every == 0 || c.Interval != 0 {
			return errors.New("io_count requires a positive operation count and zero interval")
		}
	default:
		return fmt.Errorf("unsupported IO stack sampling mode %q", c.Mode)
	}

	return nil
}

func (c Config) BPFConstants() map[string]any {
	mode := uint32(abi.IotracingProfileSamplingTime)
	if c.Mode == ModeCount {
		mode = uint32(abi.IotracingProfileSamplingCount)
	}

	return map[string]any{
		"io_profile_sampling_mode":     mode,
		"io_profile_self_pid":          uint32(os.Getpid()),
		"io_profile_interval_ns":       uint64(c.Interval),
		"io_profile_duration_ns":       uint64(c.Duration),
		"io_profile_every":             c.Every,
		"io_profile_filter_pid":        uint32(c.PID),
		"io_profile_filter_start_tick": c.PIDStartTicks,
		"io_profile_filter_css_addr":   c.CSSAddr,
		"io_profile_filter_cgroup_id":  c.CgroupID,
	}
}

// Arm installs a future capture window and waits for it to start. The start
// time is for reporting, while the deadline is in host CLOCK_MONOTONIC nanoseconds.
func Arm(object bpf.BPF, duration time.Duration) (started time.Time, deadlineNS uint64, err error) {
	nowNS, err := timeutil.MonotonicNowNS()
	if err != nil {
		return time.Time{}, 0, err
	}

	// Leave time to install the control map before BPF admits any calls.
	const armingLead = 20 * time.Millisecond
	if duration <= 0 || int64(duration) > math.MaxInt64-int64(nowNS)-int64(armingLead) {
		return time.Time{}, 0, errors.New("IO profile deadline exceeds the monotonic clock range")
	}

	startNS := nowNS + uint64(armingLead)
	endNS := startNS + uint64(duration)
	started, err = timeutil.KtimeToTime(startNS)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("convert IO profile start time: %w", err)
	}

	var key [4]byte
	value := binary.LittleEndian.AppendUint64(nil, endNS)
	if err := object.WriteMapItems(object.MapIDByName("io_profile_control"), []bpf.MapItem{{
		Key:   key[:],
		Value: value,
	}}); err != nil {
		return time.Time{}, 0, fmt.Errorf("arm IO profile: %w", err)
	}

	nowNS, err = timeutil.MonotonicNowNS()
	if err != nil {
		return time.Time{}, 0, err
	}
	if nowNS >= startNS {
		return time.Time{}, 0, errors.New("IO profile window started before arming completed")
	}

	time.Sleep(time.Duration(startNS - nowNS))
	return started, endNS, nil
}
