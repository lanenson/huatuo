// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Standalone profile labels use process UTS hostnames, without initializing
// container discovery or changing the original report's hostname lookups.
package ioprofile

import (
	"context"
	"strconv"
	"time"

	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/internal/process"
	"github.com/ccfos/huatuo/internal/procfs"
)

// ProcessStartTicks returns the process birth time in /proc's clock ticks.
func ProcessStartTicks(pid int) (uint64, error) {
	proc, err := procfs.NewProc(pid)
	if err != nil {
		return 0, err
	}
	stat, err := proc.Stat()
	return stat.Starttime, err
}

// Match iotracing's standalone metadata: one UTS hostname lookup per process.
// A hostname is descriptive metadata, not a container identity.
func ResolveHostnames(ctx context.Context, profile *profilev1.Profile) error {
	if err := AttributeContainers(profile, nil); err != nil {
		return err
	}

	type identity struct {
		pid     uint32
		startNS uint64
	}
	hostnames := make(map[identity]int64)
	hostnameKey := int64(len(profile.StringTable))
	profile.StringTable = append(profile.StringTable, "container_hostname")
	for _, sample := range profile.Sample {
		if err := ctx.Err(); err != nil {
			return err
		}

		var target identity
		for _, label := range sample.Label {
			switch profile.StringTable[label.Key] {
			case "pid":
				value, _ := strconv.ParseUint(profile.StringTable[label.Str], 10, 32)
				target.pid = uint32(value)
			case "process_start_ns":
				target.startNS, _ = strconv.ParseUint(profile.StringTable[label.Str], 10, 64)
			}
		}

		if target.pid == 0 || target.startNS == 0 {
			continue
		}

		hostnameID, known := hostnames[target]
		if !known {
			hostname := hostnameForProcess(int(target.pid), target.startNS)
			if hostname != "" {
				hostnameID = int64(len(profile.StringTable))
				profile.StringTable = append(profile.StringTable, hostname)
			}
			hostnames[target] = hostnameID
		}

		if hostnameID != 0 {
			sample.Label = append(sample.Label, &profilev1.Label{
				Key: hostnameKey,
				Str: hostnameID,
			})
		}
	}

	return nil
}

func hostnameForProcess(pid int, startNS uint64) string {
	// The kernel exports process start times in 100 Hz ticks.
	want := startNS / uint64(10*time.Millisecond)
	if ticks, err := ProcessStartTicks(pid); err != nil || ticks != want {
		return ""
	}
	hostname, err := process.Hostname(pid)
	if err != nil {
		return ""
	}
	// The target may have exited while the UTS namespace was being opened.
	if ticks, err := ProcessStartTicks(pid); err != nil || ticks != want {
		return ""
	}
	return hostname
}
