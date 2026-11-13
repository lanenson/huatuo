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

package remotestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	output "github.com/ccfos/huatuo/internal/profiling/formatter"
	"github.com/ccfos/huatuo/internal/toolstream"
	"github.com/ccfos/huatuo/pkg/profiling"
	"github.com/ccfos/huatuo/pkg/types"
)

type formatter struct {
	client *toolstream.Client
}

func (*formatter) Name() output.OutputFormat { return output.FormatRemoteStore }

func (f *formatter) Add(ctx context.Context, window *types.AggregationWindow) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return f.client.Send(ctx, window, toolstream.SendOptions{})
}

func (f *formatter) Complete(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return f.client.Send(ctx, nil, toolstream.SendOptions{
		End:    true,
		Commit: true,
	})
}

// NewFormatter connects remote output.
func newClient(cfg output.Config, version, service string) (*toolstream.Client, error) {
	if err := output.ValidateDestination(cfg.Destination); err != nil {
		return nil, err
	}

	path := cfg.Destination
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect remote profiling destination %q: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("remote profiling destination %q must be a Unix socket", path)
	}

	client, err := toolstream.NewClient(&toolstream.ClientOptions{
		SockPath:    path,
		ServiceName: service,
		ToolName:    cfg.ToolName,
		TaskID:      cfg.TaskID,
		Version:     version,
		SendTimeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("connect remote profiling destination %q: %w", path, err)
	}

	return client, nil
}

func (f *formatter) Close() error { return f.client.Close() }

// NewFormatter connects the established scalar window stream.
func NewFormatter(cfg output.Config) (output.Formatter, error) {
	client, err := newClient(cfg, "3", profiling.StoreServiceName)
	if err != nil {
		return nil, err
	}
	return &formatter{client: client}, nil
}

// WriteSnapshot publishes an already complete pprof result through the existing
// legacy envelope. Values remain joint and require one storage write.
func WriteSnapshot(ctx context.Context, cfg output.Config, data *types.ProfilingWindow) (returnErr error) {
	client, err := newClient(cfg, "1", profiling.StoreServiceName)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, client.Close()) }()
	return client.Send(ctx, data, toolstream.SendOptions{
		End:    true,
		Commit: true,
	})
}

// HandOffSnapshot acknowledges receipt by the pending event, not an independent
// durable profile. The parent iotracing result owns the eventual storage write.
func HandOffSnapshot(ctx context.Context, cfg output.Config, data *types.ProfilingWindow) (returnErr error) {
	client, err := newClient(cfg, "1", profiling.IOCaptureServiceName)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, client.Close()) }()
	return client.Send(ctx, data, toolstream.SendOptions{
		End:    true,
		Commit: true,
	})
}
