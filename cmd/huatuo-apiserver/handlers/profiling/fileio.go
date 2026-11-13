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

// Published IO tasks contain one joint-valued capture. Container attribution is
// carried by sample labels, so task queries do not use the legacy scope filter.
package profiling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/ccfos/huatuo/internal/httpserver/auth"
	"github.com/ccfos/huatuo/internal/job"
	"github.com/ccfos/huatuo/internal/profiling/fileio"
	"github.com/ccfos/huatuo/internal/profiling/formatter/flamegraph"
	profilingdomain "github.com/ccfos/huatuo/pkg/profiling"
)

// MaxResultResponseBytes is the shared raw-profile and IO response budget.
const MaxResultResponseBytes = 64 << 20

// ErrResultTooLarge indicates a complete capture exceeds the output budget.
var ErrResultTooLarge = errors.New("profiling result response is too large")

// FileIOResult is shared by local, automatic and API rendering.
type FileIOResult = fileio.Result

// FileIO returns the one published capture owned by an authorized task.
func (s *Service) FileIO(ctx context.Context, principal auth.Principal, requestID string) (*FileIOResult, error) {
	currentJob, err := s.requirePublishedJob(ctx, principal, requestID)
	if err != nil {
		return nil, err
	}
	if currentJob.Spec.Profiling == nil || currentJob.Spec.Profiling.Type != profilingdomain.TypeIO {
		return nil, fmt.Errorf("%w: file io results require an io profiling task", job.ErrInvalidQuery)
	}
	documents, err := s.profileStore.ListByTracerID(ctx, requestID, 2, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: query file io task %q: %w", ErrResultStoreUnavailable, requestID, err)
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("%w: file io task %q has no capture", ErrResultNotFound, requestID)
	}
	if len(documents) != 1 {
		return nil, fmt.Errorf("%w: one file io task requires exactly one capture", ErrResultUnavailable)
	}
	document := documents[0]
	if document == nil || document.TracerID != requestID || document.Hostname == "" ||
		document.ProfileData == nil || document.ProfileData.Profile == nil || document.ProfileData.ProfileType != fileio.ProfileType {
		return nil, fmt.Errorf("%w: file io capture does not match its task", ErrResultUnavailable)
	}
	if proto.Size(document.ProfileData.Profile) > MaxResultResponseBytes {
		return nil, ErrResultTooLarge
	}
	result, err := fileio.Decode(document.ProfileData.Profile)
	if err != nil {
		return nil, fmt.Errorf("%w: decode file io capture: %w", ErrResultUnavailable, err)
	}
	if err := checkFileIOResponseSize(ctx, result, MaxResultResponseBytes); err != nil {
		return nil, err
	}

	return result, nil
}

// FileIOSVG uses the same authorized result and the local static renderer.
func (s *Service) FileIOSVG(ctx context.Context, principal auth.Principal, requestID string) ([]byte, error) {
	result, err := s.FileIO(ctx, principal, requestID)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := resultLimitWriter{
		ctx:       ctx,
		writer:    &output,
		remaining: MaxResultResponseBytes,
	}
	if err := flamegraph.RenderFileIO(
		ctx,
		&writer,
		result.Groups,
		result.Diagnostics,
	); err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

func checkFileIOResponseSize(ctx context.Context, result *FileIOResult, limit int) error {
	writer := resultLimitWriter{
		ctx:       ctx,
		writer:    io.Discard,
		remaining: limit,
	}
	envelope := struct {
		Data *FileIOResult `json:"data"`
	}{Data: result}
	if err := json.NewEncoder(&writer).Encode(envelope); err != nil {
		return fmt.Errorf("encode file io response: %w", err)
	}

	return nil
}

type resultLimitWriter struct {
	ctx       context.Context
	writer    io.Writer
	remaining int
}

func (w *resultLimitWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) > w.remaining {
		return 0, ErrResultTooLarge
	}
	written, err := w.writer.Write(data)
	w.remaining -= written

	return written, err
}
