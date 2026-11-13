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

// IO is a bounded capture rather than a scalar stream. Publishing one native
// pprof vector keeps measured values together and leaves common profilers alone.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/ccfos/huatuo/internal/profiling/fileio"
	output "github.com/ccfos/huatuo/internal/profiling/formatter"
	"github.com/ccfos/huatuo/internal/profiling/formatter/flamegraph"
	"github.com/ccfos/huatuo/internal/profiling/formatter/remotestore"
	"github.com/ccfos/huatuo/internal/profiling/profile"
	"github.com/ccfos/huatuo/internal/randomid"
)

func RunIO(ctx context.Context, config *Config, destination output.Config, taskID string) error {
	cfg := *config
	cfg.PIDs = slices.Clone(config.PIDs)
	capture := &ioNativeProfiler{config: cfg}
	data, err := capture.capture(ctx)
	if err != nil {
		return err
	}
	outputCtx, cancel := context.WithTimeout(ctx, profile.FinalizationTimeout)
	defer cancel()
	if err := outputCtx.Err(); err != nil {
		return err
	}
	destination.ToolName = "profiler"
	destination.TaskID = randomid.NewIfEmpty(taskID)
	if destination.Format == output.FormatAutotracing {
		return remotestore.HandOffSnapshot(outputCtx, destination, data)
	}
	if destination.Format == output.FormatRemoteStore {
		return remotestore.WriteSnapshot(outputCtx, destination, data)
	}
	local, err := output.NewLocalDestination(destination)
	if err != nil {
		return err
	}
	switch destination.Format {
	case output.FormatJSON:
		return local.WriteAndClose(func(writer io.Writer) error { return json.NewEncoder(writer).Encode(data) })
	case output.FormatSVG, output.FormatFlameGraph:
		decoded, err := fileio.Decode(data.Profile)
		if err != nil {
			return err
		}
		return local.WriteAndClose(func(writer io.Writer) error {
			return flamegraph.RenderFileIO(outputCtx, writer, decoded.Groups, decoded.Diagnostics)
		})
	default:
		return fmt.Errorf("unsupported one-shot IO output %q", destination.Format)
	}
}
