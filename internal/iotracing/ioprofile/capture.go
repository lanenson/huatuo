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

// Frozen profile maps retain bytes, operations and duration together. Symbol
// lookup runs after legacy diagnostic rates and hostnames have been fixed.
package ioprofile

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/bpf/abi"
	"github.com/ccfos/huatuo/internal/profiling/bpfmap"
	"github.com/ccfos/huatuo/internal/symbol"
	"github.com/ccfos/huatuo/pkg/types"
)

type captureReader struct {
	config         Config
	bpf            bpf.BPF
	stackMapID     uint32
	processes      map[abi.IotracingProfileProcessKey]bool
	processSymbols map[abi.IotracingProfileProcessKey]*symbol.UsymResolver
}

// ReadCapture reads frozen profile maps after their owner has detached probes.
// It does not own the BPF object or alter the original diagnostic counters.
func ReadCapture(ctx context.Context, object bpf.BPF, cfg Config, started time.Time) (*types.ProfilingWindow, error) {
	p := &captureReader{
		config:     cfg,
		bpf:        object,
		stackMapID: object.MapIDByName("stack_map_a"),
	}
	p.processes = make(map[abi.IotracingProfileProcessKey]bool)
	p.processSymbols = make(map[abi.IotracingProfileProcessKey]*symbol.UsymResolver)
	builder := NewBuilder(started.UnixNano(), p.config.Duration.Nanoseconds())
	items, err := p.bpf.DumpMapByName("io_counts")
	if err != nil {
		return nil, fmt.Errorf("read file IO capture: %w", err)
	}

	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, context.Cause(ctx)
		}

		var key abi.IotracingProfileKey
		if _, err := binary.Decode(item.Key, binary.NativeEndian, &key); err != nil {
			return nil, err
		}

		value, err := sumIOPerCPU(item.Value)
		if err != nil {
			return nil, err
		}

		if value.Count == 0 {
			continue
		}

		if err := p.appendIORecord(builder, &key, &value); err != nil {
			return nil, err
		}
	}

	if err := p.appendOverflow(ctx, builder); err != nil {
		return nil, err
	}

	dropped, err := p.readDropped()
	if err != nil {
		return nil, err
	}

	profile, err := builder.Profile(ctx)
	if err != nil {
		return nil, err
	}

	return &types.ProfilingWindow{
		ProfileType:    ProfileType,
		Profile:        profile,
		DroppedSamples: dropped,
	}, nil
}

func (p *captureReader) appendIORecord(
	builder *Builder,
	key *abi.IotracingProfileKey,
	value *abi.IotracingProfileValue,
) error {
	direction := DirectionRead
	if key.Group.Direction == uint32(abi.IotracingProfileWrite) {
		direction = DirectionWrite
	} else if key.Group.Direction != uint32(abi.IotracingProfileRead) {
		return fmt.Errorf("invalid file IO direction %d", key.Group.Direction)
	}

	result, err := ioResultName(key.Result)
	if err != nil {
		return err
	}

	labels := []types.ProfileLabel{
		types.ProfileStringLabel("direction", direction),
		types.ProfileStringLabel("result", result),
		types.ProfileStringLabel("io_stack_mode", string(p.config.Mode)),
		types.ProfileStringLabel("cgroup_css", fmt.Sprint(key.Group.CSS)),
		types.ProfileStringLabel("cgroup_id", fmt.Sprint(key.Group.CgroupID)),
		types.ProfileStringLabel("attribution", ScopeOther),
	}
	if key.Group.TGID != 0 {
		labels = append(labels,
			types.ProfilePIDLabel(key.Group.TGID),
			types.ProfileStringLabel("comm", commString(key.Comm)),
			types.ProfileStringLabel("process_start_ns", fmt.Sprint(key.Group.ProcessStartNS)))
	}
	if p.config.Mode == ModeTime {
		labels = append(labels, types.ProfileStringLabel("io_stack_interval_ns", fmt.Sprint(p.config.Interval.Nanoseconds())))
	} else {
		labels = append(labels, types.ProfileStringLabel("io_stack_every", fmt.Sprint(p.config.Every)))
	}

	frames, err := p.resolveIOFrames(key)
	if err != nil && !errors.Is(err, bpfmap.ErrStackNotFound) {
		return err
	}

	return builder.Add(frames, labels, Stats{
		Bytes:      int64(value.Bytes),
		Count:      int64(value.Count),
		DurationNS: int64(value.DurationSumNS),
	})
}

func sumIOPerCPU(raw []byte) (abi.IotracingProfileValue, error) {
	var total abi.IotracingProfileValue
	size := binary.Size(total)
	stride := (size + 7) &^ 7
	if len(raw)%stride != 0 {
		return total, fmt.Errorf("invalid file IO per-CPU value size %d", len(raw))
	}

	for offset := 0; offset < len(raw); offset += stride {
		var value abi.IotracingProfileValue
		if _, err := binary.Decode(raw[offset:offset+size], binary.NativeEndian, &value); err != nil {
			return total, err
		}

		if value.Bytes > math.MaxInt64-total.Bytes || value.Count > math.MaxInt64-total.Count ||
			value.DurationSumNS > math.MaxInt64-total.DurationSumNS {
			return total, errors.New("file IO counters exceed int64 capacity")
		}

		total.Bytes += value.Bytes
		total.Count += value.Count
		total.DurationSumNS += value.DurationSumNS
	}

	return total, nil
}

func (p *captureReader) resolveIOFrames(key *abi.IotracingProfileKey) ([]types.ProfileFrame, error) {
	if key.UserStack < 0 {
		return nil, nil
	}

	identity := abi.IotracingProfileProcessKey{
		ProcessStartNS: key.Group.ProcessStartNS,
		TGID:           key.Group.TGID,
	}
	isCurrent, ok := p.processes[identity]
	if !ok {
		proc, err := procfs.NewProc(int(identity.TGID))
		if err == nil {
			stat, statErr := proc.Stat()
			// /proc uses Linux USER_HZ, also used by procfs on supported architectures.
			isCurrent = statErr == nil && stat.Starttime == identity.ProcessStartNS/uint64(time.Second/100)
		}
		p.processes[identity] = isCurrent
	}

	if isCurrent {
		resolver := p.processSymbols[identity]
		if resolver == nil {
			resolver = symbol.NewUsymResolver()
			p.processSymbols[identity] = resolver
		}

		trace, err := bpfmap.ReadStackTrace(p.bpf, p.stackMapID, uint32(key.UserStack))
		if err != nil {
			return nil, err
		}

		names := resolver.UsymStackStrsReversed(key.Group.TGID, trace[:], len(trace))
		frames := make([]types.ProfileFrame, len(names))
		for i, name := range names {
			if name == "" || name == "unknown" || strings.HasPrefix(name, "unknown ") || strings.HasPrefix(name, "[unknown]/") {
				name = fmt.Sprintf("0x%x", trace[len(names)-1-i])
			}
			frames[i] = types.ProfileFrame{Name: name}
		}

		return frames, nil
	}

	trace, err := bpfmap.ReadStackTrace(p.bpf, p.stackMapID, uint32(key.UserStack))
	if err != nil {
		return nil, err
	}

	frames := []types.ProfileFrame{}
	for _, address := range &trace {
		if address == 0 {
			break
		}
		frames = append(frames, types.ProfileFrame{Name: fmt.Sprintf("0x%x", address)})
	}

	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}

	return frames, nil
}

func ioResultName(result uint32) (string, error) {
	switch result {
	case uint32(abi.IotracingProfileSuccess):
		return "success", nil
	case uint32(abi.IotracingProfileEof):
		return "eof", nil
	case uint32(abi.IotracingProfileZeroLength):
		return "zero_length", nil
	case uint32(abi.IotracingProfileZeroResult):
		return "zero_result", nil
	case uint32(abi.IotracingProfileError):
		return "error", nil
	default:
		return "", fmt.Errorf("invalid file IO result %d", result)
	}
}

func (p *captureReader) appendOverflow(ctx context.Context, builder *Builder) error {
	items, err := p.bpf.DumpMapByName("io_overflow")
	if err != nil {
		return fmt.Errorf("read file IO overflow counters: %w", err)
	}

	resultMax := uint32(abi.IotracingProfileResultMax)
	for i := range items {
		if err := ctx.Err(); err != nil {
			return context.Cause(ctx)
		}
		item := &items[i]
		if len(item.Key) != 4 {
			return errors.New("invalid file IO overflow key size")
		}
		bucket := binary.NativeEndian.Uint32(item.Key)
		if bucket >= uint32(abi.IotracingProfileDirectionMax)*resultMax {
			return fmt.Errorf("invalid file IO overflow bucket %d", bucket)
		}
		value, err := sumIOPerCPU(item.Value)
		if err != nil {
			return err
		}
		if value.Count == 0 {
			continue
		}
		// Only a container-filtered capture can attribute the whole bucket.
		key := abi.IotracingProfileKey{
			Group: abi.IotracingProfileGroupKey{
				CSS:       p.config.CSSAddr,
				CgroupID:  p.config.CgroupID,
				Direction: bucket / resultMax,
			},
			UserStack: -1,
			Result:    bucket % resultMax,
		}
		if err := p.appendIORecord(builder, &key, &value); err != nil {
			return err
		}
	}

	return nil
}

func (p *captureReader) readDropped() (map[string]uint64, error) {
	items, err := p.bpf.DumpMapByName("io_dropped")
	if err != nil {
		return nil, fmt.Errorf("read file IO collection losses: %w", err)
	}
	if len(items) != 1 || len(items[0].Key) != 4 || binary.NativeEndian.Uint32(items[0].Key) != 0 ||
		len(items[0].Value) == 0 || len(items[0].Value)%8 != 0 {
		return nil, errors.New("invalid file IO collection loss counters")
	}
	var count uint64
	for raw := items[0].Value; len(raw) > 0; raw = raw[8:] {
		value := binary.NativeEndian.Uint64(raw)
		if value > math.MaxUint64-count {
			return nil, errors.New("file IO collection loss counter overflow")
		}
		count += value
	}
	if count == 0 {
		return nil, nil
	}

	return map[string]uint64{types.DropReasonCollection: count}, nil
}

func commString(comm [bpf.TaskCommLen]byte) string {
	length := bytes.IndexByte(comm[:], 0)
	if length == -1 {
		length = len(comm)
	}

	return string(comm[:length])
}
