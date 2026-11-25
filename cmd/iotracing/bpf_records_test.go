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

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"capnproto.org/go/capnp/v3"
	profilev1 "github.com/grafana/pyroscope/api/gen/proto/go/google/v1"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/bpf/abi"
	"github.com/ccfos/huatuo/internal/iotracing/ioprofile"
	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/internal/timeutil"
	"github.com/ccfos/huatuo/internal/toolstream"
	"github.com/ccfos/huatuo/internal/toolstream/transport"
	"github.com/ccfos/huatuo/pkg/types"

	"github.com/stretchr/testify/assert"
)

func TestBPFFilesystemIOLayout(t *testing.T) {
	t.Parallel()

	var record bpfFilesystemIO

	assert.Equal(t, uintptr(376), unsafe.Sizeof(record))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(record.TGID))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(record.PathInitialized))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(record.DevID))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(record.FsWriteBytes))
	assert.Equal(t, uintptr(64), unsafe.Offsetof(record.Latency))
	assert.Equal(t, uintptr(104), unsafe.Offsetof(record.Comm))
	assert.Equal(t, uintptr(120), unsafe.Offsetof(record.PathSegs))
}

func TestBPFFilesystemIOPathName(t *testing.T) {
	t.Parallel()

	t.Run("missing path", func(t *testing.T) {
		record := bpfFilesystemIO{Ino: 1}

		assert.Empty(t, record.PathName())
	})

	t.Run("captured path", func(t *testing.T) {
		record := bpfFilesystemIO{Ino: 1}
		copy(record.PathSegs[0][:], "io")
		copy(record.PathSegs[1][:], "huatuo-iotracing.test")
		copy(record.PathSegs[2][:], "/")

		assert.Equal(t, "/huatuo-iotracing.test/io", record.PathName())
	})
}

func TestReportAfterCollectionCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := toolstream.NewClient(&toolstream.ClientOptions{
		SockPath:    path,
		ServiceName: "iotracing",
		Version:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	traceErr := errors.New("collection failed after snapshot")
	if err := writeToolstreamReport(ctx, client, &types.IOTracingSnapshot{}, traceErr); !errors.Is(err, traceErr) || errors.Is(err, toolstream.ErrOutputCanceled) {
		t.Fatalf("report = %v, want collection error only", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	decoder := capnp.NewDecoder(peer)
	message, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	message.Release()
	for _, wantEnd := range []bool{false, true} {
		message, err := decoder.Decode()
		if err != nil {
			t.Fatal(err)
		}
		root, err := transport.ReadRootMessage(message)
		if err != nil {
			message.Release()
			t.Fatal(err)
		}
		chunk, err := root.Chunk()
		if err != nil {
			message.Release()
			t.Fatal(err)
		}
		gotEnd := chunk.End()
		message.Release()
		if gotEnd != wantEnd {
			t.Fatalf("End = %v, want %v", gotEnd, wantEnd)
		}
	}
}

func TestReportDeadlineUnblocksWrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "s")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := toolstream.NewClient(&toolstream.ClientOptions{
		SockPath:    path,
		ServiceName: "iotracing",
		Version:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	done := make(chan error, 1)
	go func() {
		done <- writeToolstreamReport(t.Context(), client, &types.IOTracingSnapshot{
			StallStacks: []types.IOScheduleEvent{{Comm: strings.Repeat("x", 1<<20)}},
		}, nil)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, toolstream.ErrOutputTimeout) || errors.Is(err, toolstream.ErrOutputCanceled) {
			t.Fatalf("report = %v, want timeout", err)
		}
	case <-time.After(toolstream.DefaultSendTimeout + time.Second):
		_ = client.Close()
		<-done
		t.Fatal("report finalization did not return after the send timeout")
	}
}

var _ bpf.PerfEventReader = (*reportTestReader)(nil)

type reportTestReader struct {
	bpf.PerfEventReader
	readErr       error
	hasRead       bool
	hasSampleLoss bool
}

func (r *reportTestReader) ReadInto(data any) error {
	if r.hasSampleLoss {
		r.hasSampleLoss = false
		return bpf.ErrPerfEventSamplesLost
	}
	if r.hasRead {
		return r.readErr
	}

	r.hasRead = true
	event := data.(*bpfScheduleDelay)
	event.TGID = 1
	event.TID = 2
	event.CPU = 3
	event.DurationNS = 2500
	copy(event.Comm[:], "init")
	return nil
}

type reportTestBPF struct {
	bpf.BPF
	t        *testing.T
	rows     []bpf.MapItem
	detached bool
}

func (b *reportTestBPF) Detach() error {
	b.detached = true
	return nil
}

func (b *reportTestBPF) DumpMapByName(name string) ([]bpf.MapItem, error) {
	b.t.Helper()
	if !b.detached || name != bpfSourceMapName {
		b.t.Fatalf("map dump before detach or unexpected map: %s", name)
	}
	return b.rows, nil
}

type failingReportOutput struct{ err error }

func (w failingReportOutput) Write([]byte) (int, error) { return 0, w.err }

func TestCollectReportWritesPartialOutput(t *testing.T) {
	readerErr := errors.New("reader failed")
	outputErr := errors.New("output failed")
	for _, test := range []struct {
		name          string
		beforeRead    bool
		hasSampleLoss bool
		readErr       error
		wantStalls    int
		wantReason    string
	}{
		{name: "error before first event", beforeRead: true, readErr: readerErr, wantReason: types.IOTracingFailureReader},
		{name: "error after event", readErr: readerErr, wantStalls: 1, wantReason: types.IOTracingFailureReader},
		{name: "normal cancellation", readErr: types.ErrExitByCancelCtx, wantStalls: 1},
		{name: "sample loss", hasSampleLoss: true, readErr: types.ErrExitByCancelCtx, wantStalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var row bytes.Buffer
			record := bpfFilesystemIO{
				TGID: 1, FsReadBytes: 8192, FsWriteBytes: 16384,
				BlockReadBytes: 2048, BlockWriteBytes: 4096,
			}
			if err := binary.Write(&row, binary.LittleEndian, &record); err != nil {
				t.Fatal(err)
			}
			object := &reportTestBPF{t: t, rows: []bpf.MapItem{{Value: row.Bytes()}}}
			const sampled = 250 * time.Millisecond
			started := time.Now().Add(-sampled)
			report, traceErr := collectReport(
				object,
				&reportTestReader{
					hasRead: test.beforeRead, hasSampleLoss: test.hasSampleLoss, readErr: test.readErr,
				},
				ioConfig{durationSecond: 10, maxProcess: 1, maxFilesPerProcess: 1, maxStack: 2},
				started,
			)
			elapsed := time.Since(started)
			var output bytes.Buffer
			err := writeReport(&jsonWriter{w: &output}, report, traceErr)
			if test.wantReason != "" {
				if !errors.Is(err, readerErr) {
					t.Fatalf("output error = %v, want reader failure", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
				t.Fatalf("decode actual output fields: %v", err)
			}
			if _, hasReason := fields["failure_reason"]; hasReason != (test.wantReason != "") {
				t.Fatalf("optional failure marker: %s", output.Bytes())
			}
			var got types.IOTracingSnapshot
			if err := json.Unmarshal(output.Bytes(), &got); err != nil {
				t.Fatalf("decode actual output: %v", err)
			}
			if got.FailureReason != test.wantReason || len(got.StallStacks) != test.wantStalls {
				t.Fatalf("partial report = %+v", got)
			}
			if test.wantStalls != 0 {
				stall := got.StallStacks[0]
				if stall.PID != 1 || stall.Comm != "init" || stall.ScheduleLatencyUS != 2 ||
					stall.TID != 2 || stall.CPU != 3 {
					t.Fatalf("reported stall = %+v", stall)
				}
			}
			if len(got.Processes) != 1 || len(got.Processes[0].TotalFiles) != 1 {
				t.Fatalf("completed process IO lost: %+v", got.Processes)
			}
			process := got.Processes[0]
			file := process.TotalFiles[0]
			for _, rate := range []struct {
				bytes, process, file uint64
			}{
				{bytes: record.FsReadBytes, process: process.TotalFsReadBps, file: file.FsReadBps},
				{bytes: record.FsWriteBytes, process: process.TotalFsWriteBps, file: file.FsWriteBps},
				{bytes: record.BlockReadBytes, process: process.TotalDiskReadBps, file: file.DiskReadBps},
				{bytes: record.BlockWriteBytes, process: process.TotalDiskWriteBps, file: file.DiskWriteBps},
			} {
				minimum := uint64(float64(rate.bytes) / elapsed.Seconds())
				maximum := uint64(float64(rate.bytes) / sampled.Seconds())
				if rate.process != rate.file || rate.process < minimum || rate.process > maximum {
					t.Fatalf("partial rate = %+v, want [%d, %d] B/s", rate, minimum, maximum)
				}
			}
			err = writeReport(&jsonWriter{w: failingReportOutput{outputErr}}, report, traceErr)
			if !errors.Is(err, outputErr) || (traceErr != nil && !errors.Is(err, readerErr)) {
				t.Fatalf("combined output/reader error = %v", err)
			}
		})
	}
}

// Signal cancellation reaches the same perf-reader boundary as production.
// The legacy dump waits until the capture timer fires after collection stops.
type combinedStopTestReader struct {
	bpf.PerfEventReader
	ctx         context.Context
	stop        func()
	returnAfter <-chan struct{}
	readErr     error
}

func (r *combinedStopTestReader) ReadInto(any) error {
	if r.readErr != nil {
		return r.readErr
	}
	if r.stop != nil {
		r.stop()
	}
	select {
	case <-r.ctx.Done():
		if r.returnAfter != nil {
			select {
			case <-r.returnAfter:
			case <-time.After(3 * time.Second):
				return errors.New("capture deadline did not release the perf reader")
			}
		}
		return types.ErrExitByCancelCtx
	case <-time.After(3 * time.Second):
		return errors.New("capture context did not stop the perf reader")
	}
}

type combinedStopTestBPF struct {
	*reportTestBPF
	profile      ioProfileSnapshotBPF
	timerDone    <-chan struct{}
	profileReads int
}

func (b *combinedStopTestBPF) MapIDByName(name string) uint32 {
	return b.profile.MapIDByName(name)
}

func (b *combinedStopTestBPF) DumpMapByName(name string) ([]bpf.MapItem, error) {
	if name == bpfSourceMapName {
		select {
		case <-b.timerDone:
		case <-time.After(3 * time.Second):
			b.t.Fatal("capture timer did not fire while the legacy dump was blocked")
		}
		return b.reportTestBPF.DumpMapByName(name)
	}
	if name == "io_counts" {
		b.profileReads++
	}
	return b.profile.DumpMapByName(name)
}

func TestCombinedProfileUsesKernelDeadline(t *testing.T) {
	readerErr := errors.New("diagnostic reader failed before the capture deadline")
	for _, test := range []struct {
		name                 string
		signalBeforeDeadline bool
		signalAfterDeadline  bool
		stackMapDrops        []uint64
		delayReader          bool
		readErr              error
	}{
		{
			name:                 "signal before deadline with a delayed legacy dump",
			signalBeforeDeadline: true,
		},
		{
			name:                 "signal before deadline with a reader delayed until cutoff",
			signalBeforeDeadline: true,
			delayReader:          true,
		},
		{
			name:                "signal after kernel deadline before the timer runs",
			signalAfterDeadline: true,
		},
		{
			name: "natural deadline",
		},
		{
			name:                "stack map rejections preserve diagnostics and IO totals",
			signalAfterDeadline: true,
			stackMapDrops:       []uint64{2, 3},
		},
		{
			name:    "reader failure before timer expires during legacy dump",
			readErr: readerErr,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			signals := make(chan os.Signal, 1)
			timeout := make(chan struct{})
			captureCtx, cancel := traceContext(t.Context(), signals, timeout)
			defer cancel(nil)
			reader := &combinedStopTestReader{
				ctx:     captureCtx,
				readErr: test.readErr,
			}
			if test.signalBeforeDeadline || test.signalAfterDeadline {
				reader.stop = func() { signals <- syscall.SIGINT }
			}
			if test.delayReader {
				reader.returnAfter = timeout
			}

			var row bytes.Buffer
			if err := binary.Write(&row, binary.LittleEndian, bpfFilesystemIO{
				TGID:           math.MaxUint32,
				FsReadBytes:    4096,
				BlockReadBytes: 4096,
			}); err != nil {
				t.Fatal(err)
			}
			value, err := binary.Append(nil, binary.NativeEndian, abi.IotracingProfileValue{
				Bytes:         4096,
				Count:         1,
				DurationSumNS: 1000,
			})
			if err != nil {
				t.Fatal(err)
			}
			object := &combinedStopTestBPF{
				reportTestBPF: &reportTestBPF{
					t:    t,
					rows: []bpf.MapItem{{Value: row.Bytes()}},
				},
				profile: ioProfileSnapshotBPF{
					stackMapDrops: test.stackMapDrops,
					items: []bpf.MapItem{{
						Key: ioProfileTestKey(t, abi.IotracingProfileKey{
							Group: abi.IotracingProfileGroupKey{
								TGID:      math.MaxUint32,
								Direction: uint32(abi.IotracingProfileRead),
							},
							UserStack: -1,
							Result:    uint32(abi.IotracingProfileSuccess),
						}),
						Value: value,
					}},
				},
				timerDone: timeout,
			}
			const duration = time.Second
			started := time.Now()
			nowNS, err := timeutil.MonotonicNowNS()
			if err != nil {
				t.Fatal(err)
			}
			deadlineNS := nowNS + uint64(duration)
			if test.signalAfterDeadline {
				deadlineNS = nowNS
				object.timerDone = captureCtx.Done()
			} else {
				timer := time.AfterFunc(duration, func() { close(timeout) })
				defer timer.Stop()
			}
			report, err := collectTraceReport(
				captureCtx,
				object,
				reader,
				ioConfig{
					durationSecond:     1,
					maxProcess:         1,
					maxFilesPerProcess: 1,
				},
				&ioProfileOptions{
					config: ioprofile.Config{
						Duration: duration,
						Mode:     ioprofile.ModeCount,
						Every:    100,
					},
				},
				started,
				started,
				deadlineNS,
			)
			wantFailure := ""
			if test.readErr != nil {
				wantFailure = types.IOTracingFailureReader
				if !errors.Is(err, test.readErr) {
					t.Fatalf("diagnostic error = %v, want %v", err, test.readErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if report == nil || report.FailureReason != wantFailure || len(report.Processes) != 1 ||
				report.Processes[0].TotalFsReadBps == 0 || !object.detached {
				t.Fatalf("legacy partial report changed: %+v", report)
			}
			if test.signalBeforeDeadline || test.readErr != nil {
				if report.IOProfile != nil || report.IOProfileError == "" || object.profileReads != 0 {
					t.Fatalf("early stop published a profile after legacy processing: %+v", report)
				}
				return
			}
			if report.IOProfile == nil || object.profileReads != 1 {
				t.Fatalf("complete profile lost after deadline: %+v", report)
			}
			if len(test.stackMapDrops) == 0 {
				if report.IOProfileError != "" {
					t.Fatalf("unexpected IO profile error: %q", report.IOProfileError)
				}
				return
			}
			if !strings.Contains(report.IOProfileError, "stack map rejected 5 samples") ||
				!strings.Contains(report.IOProfileError, "unknown user stacks") {
				t.Fatalf("missing stack map error: %q", report.IOProfileError)
			}
			data, err := ioprofile.Decode(report.IOProfile.Profile, report.IOProfile.DroppedSamples)
			if err != nil {
				t.Fatal(err)
			}
			want := ioprofile.Stats{Bytes: 4096, Count: 1, DurationNS: 1000}
			if !data.NumericComplete || data.Groups[0].Root.Stats != want {
				t.Fatalf("stack map rejection lost measurements: %+v", data)
			}
		})
	}
}

// Map snapshots exercise the same binary decoding boundary as a detached BPF
// object, without initializing kernel or container-discovery resources.
type ioProfileSnapshotBPF struct {
	bpf.BPF
	items         []bpf.MapItem
	overflow      []bpf.MapItem
	dropped       uint64
	stackMapDrops []uint64
}

func (b *ioProfileSnapshotBPF) MapIDByName(string) uint32 { return 1 }

func (b *ioProfileSnapshotBPF) DumpMapByName(name string) ([]bpf.MapItem, error) {
	switch name {
	case "io_counts":
		return b.items, nil
	case "io_overflow":
		return b.overflow, nil
	case "io_dropped":
		items := []bpf.MapItem{{
			Key:   make([]byte, 4),
			Value: binary.NativeEndian.AppendUint64(nil, b.dropped),
		}}
		if len(b.stackMapDrops) > 0 {
			value := make([]byte, 0, len(b.stackMapDrops)*8)
			for _, count := range b.stackMapDrops {
				value = binary.NativeEndian.AppendUint64(value, count)
			}
			items = append(items, bpf.MapItem{
				Key:   binary.NativeEndian.AppendUint32(nil, uint32(abi.IotracingProfileDropStackMap)),
				Value: value,
			})
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unexpected fixture map %q", name)
	}
}

func ioProfileTestKey(t *testing.T, key abi.IotracingProfileKey) []byte {
	t.Helper()
	value, err := binary.Append(nil, binary.NativeEndian, key)
	if err != nil {
		t.Fatal(err)
	}

	return value
}

func TestIOProfilePerCPUCounterReduction(t *testing.T) {
	var raw []byte
	for _, value := range []abi.IotracingProfileValue{
		{
			Bytes:         4096,
			Count:         1,
			DurationSumNS: 200,
		},
		{},
		{
			Bytes:         17,
			Count:         1,
			DurationSumNS: 300,
		},
	} {
		var err error
		raw, err = binary.Append(raw, binary.NativeEndian, value)
		if err != nil {
			t.Fatal(err)
		}
	}

	key := ioProfileTestKey(t, abi.IotracingProfileKey{
		Group: abi.IotracingProfileGroupKey{
			TGID:      10,
			Direction: uint32(abi.IotracingProfileRead),
		},
		UserStack: -1,
		Result:    uint32(abi.IotracingProfileSuccess),
	})
	cfg := ioprofile.Config{
		Duration: time.Second,
		Mode:     ioprofile.ModeCount,
		Every:    100,
	}

	for _, test := range []struct {
		name      string
		raw       []byte
		wantError bool
	}{
		{
			name: "complete",
			raw:  raw,
		},
		{
			name:      "truncated",
			raw:       raw[:len(raw)-1],
			wantError: true,
		},
		{
			name:      "overflow",
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.raw
			if test.name == "overflow" {
				var err error
				data, err = binary.Append(nil, binary.NativeEndian, abi.IotracingProfileValue{Count: math.MaxUint64})
				if err != nil {
					t.Fatal(err)
				}
			}

			window, _, err := ioprofile.ReadCapture(
				t.Context(),
				&ioProfileSnapshotBPF{
					dropped: 1,
					items: []bpf.MapItem{{
						Key:   key,
						Value: data,
					}},
				},
				cfg,
				time.Unix(0, 1),
			)
			if test.wantError {
				if err == nil {
					t.Fatal("invalid per-CPU counters accepted")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			result, err := ioprofile.Decode(window.Profile, window.DroppedSamples)
			if err != nil {
				t.Fatal(err)
			}

			want := ioprofile.Stats{
				Bytes:      4113,
				Count:      2,
				DurationNS: 500,
			}
			if len(result.Groups) != 2 || result.Groups[0].Root.Stats != want || result.NumericComplete ||
				result.DroppedSamples[types.DropReasonCollection] != 1 {
				t.Fatalf("result=%+v; want totals %+v and one lost measurement", result, want)
			}
		})
	}
}

func TestIOProfileOverflowPreservesMeasuredValues(t *testing.T) {
	const (
		css = 17
		id  = 42
	)
	key := abi.IotracingProfileKey{
		Group: abi.IotracingProfileGroupKey{
			TGID:     10,
			CSS:      css,
			CgroupID: id,
		},
		UserStack: -1,
	}
	zeroKey := key
	zeroKey.Result = uint32(abi.IotracingProfileZeroBytes)
	var raw []byte
	for _, value := range []abi.IotracingProfileValue{
		{Bytes: 17, Count: 1, DurationSumNS: 200},
		{Bytes: 4096, Count: 1, DurationSumNS: 300},
		{Count: 1, DurationSumNS: 500},
		{Count: 1, DurationSumNS: 80000},
	} {
		var err error
		raw, err = binary.Append(raw, binary.NativeEndian, value)
		if err != nil {
			t.Fatal(err)
		}
	}
	size := binary.Size(abi.IotracingProfileValue{})
	fixture := &ioProfileSnapshotBPF{
		items: []bpf.MapItem{
			{
				Key:   ioProfileTestKey(t, key),
				Value: raw[:size],
			},
			{
				Key:   ioProfileTestKey(t, zeroKey),
				Value: raw[size*3:],
			},
		},
		overflow: []bpf.MapItem{
			{
				Key:   binary.NativeEndian.AppendUint32(nil, uint32(abi.IotracingProfileSuccess)),
				Value: raw[:size*2],
			},
			{
				Key:   binary.NativeEndian.AppendUint32(nil, uint32(abi.IotracingProfileError)),
				Value: raw[size*2 : size*3],
			},
			{
				Key:   binary.NativeEndian.AppendUint32(nil, uint32(abi.IotracingProfileZeroBytes)),
				Value: raw[size*3:],
			},
		},
	}
	capture, _, err := ioprofile.ReadCapture(
		t.Context(),
		fixture,
		ioprofile.Config{
			Duration: time.Second,
			Mode:     ioprofile.ModeCount,
			Every:    100,
		},
		time.Unix(0, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ioprofile.AttributeContainers(capture.Profile, map[pod.CgroupCSSRef]*pod.Container{
		{CSSAddr: css, CgroupID: id}: {
			ID:     "a",
			Labels: map[string]any{"HostNamespace": "service"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := ioprofile.Decode(capture.Profile, capture.DroppedSamples)
	if err != nil {
		t.Fatal(err)
	}
	total := ioprofile.Stats{Bytes: 4130, Count: 5, DurationNS: 160700}
	if len(result.Groups) != 3 || !result.NumericComplete {
		t.Fatalf("unexpected IO profile structure: %+v", result)
	}
	host, container, other := &result.Groups[0], &result.Groups[1], &result.Groups[2]
	if host.Scope != ioprofile.ScopeHost || host.Root.Stats != total || host.FailedOperations != 1 {
		t.Fatalf("overflow altered host totals: %+v", host)
	}
	containerTotal := ioprofile.Stats{Bytes: 17, Count: 2, DurationNS: 80200}
	if container.Scope != ioprofile.ScopeContainer || container.Root.Stats != containerTotal || container.FailedOperations != 0 {
		t.Fatalf("container received unattributed overflow: %+v", container)
	}
	overflowTotal := ioprofile.Stats{Bytes: 4113, Count: 3, DurationNS: 80500}
	if other.Scope != ioprofile.ScopeOther || other.Root.Stats != overflowTotal || other.FailedOperations != 1 {
		t.Fatalf("unattributed overflow was lost: %+v", other)
	}

	for _, check := range []struct {
		group *ioprofile.Group
		want  ioprofile.Stats
	}{
		{group: container, want: ioprofile.Stats{Bytes: 17, Count: 1, DurationNS: 200}},
		{group: other, want: ioprofile.Stats{Bytes: 4113, Count: 2, DurationNS: 500}},
	} {
		labels := check.group.Root.Children
		if len(labels) != 1 || len(labels[0].Children) != 1 {
			t.Fatalf("scope %s: missing unknown-stack branch", check.group.Scope)
		}
		unknown := labels[0].Children[0]
		if unknown.Frame.Name != "[unknown user stack]" || unknown.Stats != check.want {
			t.Fatalf("scope %s: unknown stack has %+v, want %+v", check.group.Scope, unknown.Stats, check.want)
		}
	}
}

func TestIOProfileUsesEndOfCaptureContainerMetadata(t *testing.T) {
	container := &pod.Container{
		ID:       "container-a",
		Hostname: "worker",
		Type:     pod.ContainerTypeNormal,
		Labels:   map[string]any{"HostNamespace": "service"},
	}
	if err := json.Unmarshal([]byte(`"burstable"`), &container.Qos); err != nil {
		t.Fatal(err)
	}
	fixture := &ioProfileSnapshotBPF{}
	key := abi.IotracingProfileKey{
		Group: abi.IotracingProfileGroupKey{
			TGID:      10,
			CSS:       17,
			Direction: uint32(abi.IotracingProfileRead),
		},
		UserStack: -1,
		Result:    uint32(abi.IotracingProfileSuccess),
	}
	value := abi.IotracingProfileValue{
		Bytes:         4096,
		Count:         1,
		DurationSumNS: 1000,
	}
	for _, cgroupID := range []uint64{42, 43} {
		key.Group.CgroupID = cgroupID
		raw, err := binary.Append(nil, binary.NativeEndian, value)
		if err != nil {
			t.Fatal(err)
		}
		fixture.items = append(fixture.items, bpf.MapItem{
			Key:   ioProfileTestKey(t, key),
			Value: raw,
		})
	}

	window, _, err := ioprofile.ReadCapture(
		t.Context(),
		fixture,
		ioprofile.Config{
			Duration: time.Second,
			Mode:     ioprofile.ModeCount,
			Every:    100,
		},
		time.Unix(0, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := window.Profile

	// The collector emits identities and totals before any container lookup.
	before, err := ioprofile.Decode(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Groups) != 2 || before.Groups[0].Root.Stats.Bytes != 8192 ||
		before.Groups[1].Scope != ioprofile.ScopeOther {
		t.Fatalf("raw capture lost IO: %+v", before.Groups)
	}
	rawProfile := profile.CloneVT()
	if err := ioprofile.AttributeContainers(profile, map[pod.CgroupCSSRef]*pod.Container{
		{
			CSSAddr:  17,
			CgroupID: 42,
		}: container,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := ioprofile.Decode(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 3 || result.Groups[0].Scope != ioprofile.ScopeHost ||
		result.Groups[0].Root.Stats.Bytes != 8192 || result.Groups[1].ContainerID != container.ID ||
		result.Groups[1].Root.Stats.Bytes != 4096 || result.Groups[2].Scope != ioprofile.ScopeOther ||
		result.Groups[2].Root.Stats.Bytes != 4096 {
		t.Fatalf("host/container attribution changed: %+v", result.Groups)
	}
	labels := result.Groups[1].Root.Labels
	for _, label := range []types.ProfileLabel{
		types.ProfileStringLabel("container_hostname", "worker"),
		types.ProfileStringLabel("container_host_namespace", "service"),
		types.ProfileStringLabel("container_type", "normal"),
		types.ProfileStringLabel("container_qos", "burstable"),
	} {
		if !slices.Contains(labels, label) {
			t.Fatalf("container profile label %s was lost: %+v", label.Name, labels)
		}
	}

	if slices.Contains(profile.StringTable, "cgroup_css") || slices.Contains(profile.StringTable, "17") ||
		profile.StringTable[profile.DefaultSampleType] != "bytes" {
		t.Fatal("published pprof retained a CSS pointer or lost its default sample type")
	}

	container.Hostname = ""
	container.Labels["HostNamespace"] = ""
	profile = rawProfile.CloneVT()
	if err := ioprofile.AttributeContainers(profile, map[pod.CgroupCSSRef]*pod.Container{
		{
			CSSAddr:  17,
			CgroupID: 42,
		}: container,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ioprofile.Decode(profile, nil); err != nil {
		t.Fatalf("empty metadata must remain a string label: %v", err)
	}

	// A container absent from the final view remains fully counted in other.
	profile = rawProfile.CloneVT()
	if err := ioprofile.AttributeContainers(profile, nil); err != nil {
		t.Fatal(err)
	}
	missing, err := ioprofile.Decode(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing.Groups) != 2 || missing.Groups[0].Root.Stats != before.Groups[0].Root.Stats ||
		missing.Groups[1].Scope != ioprofile.ScopeOther || missing.Groups[1].Root.Stats != before.Groups[1].Root.Stats {
		t.Fatalf("missing container changed measured IO: %+v", missing.Groups)
	}
}

type delayedArmBPF struct {
	bpf.BPF
}

func (delayedArmBPF) MapIDByName(string) uint32 { return 1 }

func (delayedArmBPF) WriteMapItems(uint32, []bpf.MapItem) error {
	time.Sleep(50 * time.Millisecond)
	return nil
}

func TestIOProfileArmRejectsMissedStart(t *testing.T) {
	for _, duration := range []time.Duration{time.Nanosecond, time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			_, _, err := ioprofile.Arm(delayedArmBPF{}, duration)
			if err == nil || !strings.Contains(err.Error(), "started before arming completed") {
				t.Fatalf("Arm() error = %v, want missed start", err)
			}
		})
	}
}

func TestIOProfileRejectsPreclassifiedCapture(t *testing.T) {
	builder := ioprofile.NewBuilder(1, int64(time.Second))
	if err := builder.Add(nil, []types.ProfileLabel{
		types.ProfileStringLabel("direction", "read"),
		types.ProfileStringLabel("attribution", "container"),
		types.ProfileStringLabel("container_id", "container-a"),
		types.ProfileStringLabel("result", "success"),
	}, ioprofile.Stats{Bytes: 1, Count: 1}); err != nil {
		t.Fatal(err)
	}
	profile, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := ioprofile.ResolveContainers(profile); err == nil {
		t.Fatal("accepted preclassified IO sample without a raw cgroup identity")
	}
}

func TestIOProfileRejectsInvalidRawCgroupLabel(t *testing.T) {
	builder := ioprofile.NewBuilder(1, int64(time.Second))
	if err := builder.Add(nil, []types.ProfileLabel{
		types.ProfileStringLabel("direction", "read"),
		types.ProfileStringLabel("attribution", "other"),
		types.ProfileStringLabel("cgroup_css", "17"),
		types.ProfileStringLabel("cgroup_id", "42"),
		types.ProfileStringLabel("result", "success"),
	}, ioprofile.Stats{Bytes: 1, Count: 1}); err != nil {
		t.Fatal(err)
	}
	profile, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range profile.Sample[0].Label {
		if profile.StringTable[label.Key] == "cgroup_css" {
			label.Str = int64(len(profile.StringTable))
			break
		}
	}
	if err := ioprofile.ResolveContainers(profile); err == nil {
		t.Fatal("accepted a cgroup label pointing outside the string table")
	}
}

func TestIOProfileHostnameSkipsReusedPID(t *testing.T) {
	pid := os.Getpid()
	ticks, err := ioprofile.ProcessStartTicks(pid)
	if err != nil {
		t.Fatal(err)
	}
	staleStart := (ticks + 1) * uint64(10*time.Millisecond)
	builder := ioprofile.NewBuilder(1, int64(time.Second))
	if err := builder.Add(nil, []types.ProfileLabel{
		types.ProfilePIDLabel(uint32(pid)),
		types.ProfileStringLabel("process_start_ns", fmt.Sprint(staleStart)),
		types.ProfileStringLabel("direction", "read"),
		types.ProfileStringLabel("attribution", "other"),
		types.ProfileStringLabel("cgroup_css", "0"),
		types.ProfileStringLabel("cgroup_id", "0"),
		types.ProfileStringLabel("result", "success"),
	}, ioprofile.Stats{Bytes: 1, Count: 1}); err != nil {
		t.Fatal(err)
	}
	profile, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := ioprofile.ResolveHostnames(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
	for _, label := range profile.Sample[0].Label {
		if profile.StringTable[label.Key] == "container_hostname" {
			t.Fatal("used the hostname of a later process")
		}
	}
}

func ioProfileLabels(container string) []types.ProfileLabel {
	attribution := ioprofile.ScopeOther
	labels := []types.ProfileLabel{types.ProfileStringLabel("direction", "read"), types.ProfileStringLabel("result", "success"), types.ProfilePIDLabel(10)}
	if container != "" {
		attribution = ioprofile.ScopeContainer
		labels = append(labels, types.ProfileStringLabel("container_id", container), types.ProfileStringLabel("container_hostname", "worker"), types.ProfileStringLabel("container_type", "normal"), types.ProfileStringLabel("container_qos", "burstable"))
	}
	return append(labels, types.ProfileStringLabel("attribution", attribution))
}

func ioProfileCapture(t *testing.T) *profilev1.Profile {
	t.Helper()
	builder := ioprofile.NewBuilder(1, 10000000000)
	for _, container := range []string{"container-a", ""} {
		if err := builder.Add([]types.ProfileFrame{{Name: "main"}, {Name: "read_file"}}, ioProfileLabels(container), ioprofile.Stats{
			Bytes:      4096,
			Count:      1,
			DurationNS: 1000000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	capture, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return capture
}

func TestIOProfileSingleCaptureKeepsValuesTogether(t *testing.T) {
	capture := ioProfileCapture(t)
	result, err := ioprofile.Decode(capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.SampleType) != 3 || len(result.Groups) != 3 || result.Groups[0].Scope != ioprofile.ScopeHost || result.Groups[0].Root.Stats != (ioprofile.Stats{
		Bytes:      8192,
		Count:      2,
		DurationNS: 2000000,
	}) {
		t.Fatalf("joint capture lost values: %+v", result)
	}
	for _, index := range []int{0, 1} {
		found := false
		for _, node := range result.Groups[index].Root.Children {
			var hostname, containerType, qos string
			for _, label := range node.Labels {
				switch label.Name {
				case "container_hostname":
					hostname = label.StringValue
				case "container_type":
					containerType = label.StringValue
				case "container_qos":
					qos = label.StringValue
				}
			}
			found = found || (hostname == "worker" && containerType == "normal" && qos == "burstable")
		}
		if !found {
			t.Fatalf("scope %s lost container profile labels", result.Groups[index].Scope)
		}
	}
	var svg bytes.Buffer
	if err := ioprofile.RenderSVG(t.Context(), &svg, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(svg.String(), "container_hostname=&#34;worker&#34;") ||
		!strings.Contains(svg.String(), "container_qos=&#34;burstable&#34;") ||
		!strings.Contains(svg.String(), "Container: worker / container-a / type: normal / QoS: burstable") {
		t.Fatal("SVG lost container profile labels")
	}
	if !result.NumericComplete || strings.Contains(svg.String(), "Numeric completeness") {
		t.Fatal("complete capture should not print a numeric completeness message")
	}
}

func TestIOProfileRejectsInvalidCapture(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*profilev1.Profile)
	}{
		{
			name:   "missing value type",
			mutate: func(p *profilev1.Profile) { p.SampleType = p.SampleType[:2] },
		},
		{
			name:   "missing row value",
			mutate: func(p *profilev1.Profile) { p.Sample[0].Value = p.Sample[0].Value[:2] },
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
			p := ioProfileCapture(t)
			test.mutate(p)
			if _, err := ioprofile.Decode(p, nil); err == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

func TestIOProfileUnknownErrorsAndLoss(t *testing.T) {
	builder := ioprofile.NewBuilder(1, 1000000000)
	if err := builder.Add(nil, ioProfileLabels(""), ioprofile.Stats{
		Bytes:      4096,
		Count:      1,
		DurationNS: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	labels := ioProfileLabels("container-errors")
	for i := range labels {
		if labels[i].Name == "result" {
			labels[i].StringValue = "error"
		}
	}
	if err := builder.Add(nil, labels, ioprofile.Stats{
		Count:      2,
		DurationNS: 5000,
	}); err != nil {
		t.Fatal(err)
	}
	for i := range labels {
		if labels[i].Name == "result" {
			labels[i].StringValue = "success"
		}
	}
	if err := builder.Add(nil, labels, ioprofile.Stats{Count: 1, DurationNS: 5}); err != nil {
		t.Fatal(err)
	}
	capture, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := ioprofile.Decode(capture, map[string]uint64{types.DropReasonCollection: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.NumericComplete || result.Groups[0].Root.Stats != (ioprofile.Stats{Bytes: 4096, Count: 2, DurationNS: 1005}) ||
		result.Groups[0].FailedOperations != 2 {
		t.Fatalf("error/unknown/loss semantics changed: %+v", result)
	}
	container := &result.Groups[1]
	if container.ContainerID != "container-errors" || len(container.Root.Children) != 0 ||
		len(container.Root.Labels) == 0 || container.Root.Stats != (ioprofile.Stats{Count: 1, DurationNS: 5}) ||
		container.FailedOperations != 2 {
		t.Fatalf("zero-byte container lost metadata or outcomes: %+v", container)
	}

	var svg bytes.Buffer
	if err := ioprofile.RenderSVG(t.Context(), &svg, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(svg.String(), "INCOMPLETE") || !strings.Contains(svg.String(), "Failed operations: 2") ||
		!strings.Contains(svg.String(), "[unknown user stack]") || strings.Contains(svg.String(), "Unknown user-stack attribution:") ||
		!strings.Contains(svg.String(), "Container: worker") || !strings.Contains(svg.String(), "type: normal / QoS: burstable") {
		t.Fatal("loss or outcome not visible")
	}
}

func TestIOProfileCaptureRejectsOverflow(t *testing.T) {
	builder := ioprofile.NewBuilder(1, 1000000000)
	for i := 0; i < 2; i++ {
		if err := builder.Add(nil, ioProfileLabels(""), ioprofile.Stats{
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
	if _, err := ioprofile.Decode(capture, nil); err == nil {
		t.Fatal("overflowed capture accepted")
	}
}

func TestIOProfileSVGEncodesBytesSelfAndMeanLatency(t *testing.T) {
	builder := ioprofile.NewBuilder(1, 1000000000)
	for _, sample := range []struct {
		name  string
		stats ioprofile.Stats
	}{
		{
			name: "parent",
			stats: ioprofile.Stats{
				Bytes:      20,
				Count:      1,
				DurationNS: 2000000,
			},
		},
		{
			name: "fast",
			stats: ioprofile.Stats{
				Bytes:      40,
				Count:      4,
				DurationNS: 40000,
			},
		},
		{
			name: "middle",
			stats: ioprofile.Stats{
				Bytes:      20,
				Count:      2,
				DurationNS: 2000000,
			},
		},
		{
			name: "slow",
			stats: ioprofile.Stats{
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
		if err := builder.Add(frames, ioProfileLabels(""), sample.stats); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := builder.Profile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := ioprofile.Decode(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	var image bytes.Buffer
	if err := ioprofile.RenderSVG(t.Context(), &image, result); err != nil {
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
