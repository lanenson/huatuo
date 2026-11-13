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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"

	apiv1 "github.com/ccfos/huatuo/apis/v1"
)

func TestOpenAPIJSON(t *testing.T) {
	t.Parallel()

	first := OpenAPIJSON()
	if len(first) == 0 {
		t.Fatal("OpenAPIJSON() returned an empty document")
	}
	first[0] = 0
	if OpenAPIJSON()[0] == 0 {
		t.Fatal("OpenAPIJSON() returned mutable package state")
	}

	loader := openapi3.NewLoader()
	document, err := loader.LoadFromData(OpenAPIJSON())
	if err != nil {
		t.Fatalf("LoadFromData(OpenAPIJSON()) error = %v", err)
	}
	if err := document.Validate(t.Context()); err != nil {
		t.Errorf("Validate(OpenAPIJSON()) error = %v", err)
	}
}

func TestGeneratedContractsCompile(t *testing.T) {
	t.Parallel()

	if _, err := NewClient("http://127.0.0.1:8080"); err != nil {
		t.Errorf("NewClient() error = %v, want nil", err)
	}
	var _ StrictServerInterface = (*unimplementedStrictServer)(nil)
}

func TestCapabilitiesRouteIsNotCapturedAsRequestID(t *testing.T) {
	t.Parallel()

	handler := &routingStrictServer{}
	router := gin.New()
	RegisterHandlers(router, NewStrictHandler(handler, nil))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/profiling/capabilities", http.NoBody)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Errorf("GET /v1/profiling/capabilities status = %d, want 200", recorder.Code)
	}
	if !handler.capabilitiesCalled {
		t.Error("GET /v1/profiling/capabilities did not call GetProfilingCapabilities")
	}
	if handler.jobCalled {
		t.Error("GET /v1/profiling/capabilities was captured as request_id")
	}
}

func TestFileIOResultRouteContracts(t *testing.T) {
	document, err := openapi3.NewLoader().LoadFromData(OpenAPIJSON())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		path        string
		operation   string
		contentType string
		body        string
	}{
		{
			name:        "JSON",
			path:        "/v1/profiling/{request_id}/io",
			operation:   "getFileIOProfile",
			contentType: "application/json",
			body:        `"groups":[]`,
		},
		{
			name:        "SVG",
			path:        "/v1/profiling/{request_id}/io/flamegraph",
			operation:   "getFileIOFlamegraph",
			contentType: "image/svg+xml",
			body:        `<svg xmlns="http://www.w3.org/2000/svg"/>`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := document.Paths.Value(test.path)
			if path == nil || path.Get == nil || path.Get.OperationID != test.operation {
				t.Fatalf("missing GET contract for %s", test.path)
			}
			security := path.Get.Security
			if security == nil || len(*security) != 1 {
				t.Fatalf("GET %s has no BearerAuth requirement", test.path)
			}
			if _, ok := (*security)[0]["BearerAuth"]; !ok {
				t.Fatalf("GET %s does not use BearerAuth", test.path)
			}
			handler := &fileIOResultServer{}
			router := gin.New()
			RegisterHandlers(router, NewStrictHandler(handler, nil))
			requestPath := strings.Replace(test.path, "{request_id}", "io-job", 1)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, requestPath, http.NoBody))
			if recorder.Code != http.StatusOK || handler.requestID != "io-job" ||
				!strings.HasPrefix(recorder.Header().Get("Content-Type"), test.contentType) ||
				!strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf(
					"GET %s: status=%d type=%q requestID=%q body=%s",
					requestPath,
					recorder.Code,
					recorder.Header().Get("Content-Type"),
					handler.requestID,
					recorder.Body.String(),
				)
			}
		})
	}
}

type fileIOResultServer struct {
	StrictServerInterface
	requestID string
}

func (s *fileIOResultServer) GetFileIOProfile(
	_ context.Context,
	request GetFileIOProfileRequestObject,
) (GetFileIOProfileResponseObject, error) {
	s.requestID = request.RequestID
	return GetFileIOProfile200JSONResponse(FileIOProfileResponse{
		Data: FileIOResult{
			Groups:          []FileIOGroup{},
			Diagnostics:     map[string]uint64{},
			NumericComplete: true,
		},
	}), nil
}

func (s *fileIOResultServer) GetFileIOFlamegraph(
	_ context.Context,
	request GetFileIOFlamegraphRequestObject,
) (GetFileIOFlamegraphResponseObject, error) {
	s.requestID = request.RequestID
	data := []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)
	return GetFileIOFlamegraph200ImageSvgXMLResponse{
		Body:          bytes.NewReader(data),
		ContentLength: int64(len(data)),
	}, nil
}

func TestServerHTTPStatusForErrorCode(t *testing.T) {
	t.Parallel()

	status, ok := HTTPStatusForErrorCode(ErrorCodeJobNotFound)
	if status != http.StatusNotFound || !ok {
		t.Errorf("HTTPStatusForErrorCode(job_not_found) = (%d, %t), want (404, true)", status, ok)
	}
	status, ok = HTTPStatusForErrorCode(apiv1.ErrorCodeUnauthenticated)
	if status != http.StatusUnauthorized || !ok {
		t.Errorf("HTTPStatusForErrorCode(unauthenticated) = (%d, %t), want (401, true)", status, ok)
	}
}

func TestRemovedServerRoutesAreNotRegistered(t *testing.T) {
	t.Parallel()

	router := gin.New()
	RegisterHandlers(router, NewStrictHandler(&unimplementedStrictServer{}, nil))
	for _, path := range []string{
		"/healthz",
		"/v1/profiles",
		"/v1/profiles/job-1",
		"/v1/traces",
		"/v1/traces/job-1",
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, recorder.Code)
		}
	}
}

type unimplementedStrictServer struct{}

var errNotImplemented = errors.New("test handler is not implemented")

func (*unimplementedStrictServer) GetReadiness(
	context.Context,
	GetReadinessRequestObject,
) (GetReadinessResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetOpenAPI(
	context.Context,
	GetOpenAPIRequestObject,
) (GetOpenAPIResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) ListProfilingJobs(
	context.Context,
	ListProfilingJobsRequestObject,
) (ListProfilingJobsResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) CreateProfilingJob(
	context.Context,
	CreateProfilingJobRequestObject,
) (CreateProfilingJobResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetProfilingCapabilities(
	context.Context,
	GetProfilingCapabilitiesRequestObject,
) (GetProfilingCapabilitiesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) SelectMergeStacktraces(
	context.Context,
	SelectMergeStacktracesRequestObject,
) (SelectMergeStacktracesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetProfileTypes(
	context.Context,
	GetProfileTypesRequestObject,
) (GetProfileTypesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetProfileLabelNames(
	context.Context,
	GetProfileLabelNamesRequestObject,
) (GetProfileLabelNamesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetProfileLabelValues(
	context.Context,
	GetProfileLabelValuesRequestObject,
) (GetProfileLabelValuesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetProfilingJob(
	context.Context,
	GetProfilingJobRequestObject,
) (GetProfilingJobResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetRawProfiles(
	context.Context,
	GetRawProfilesRequestObject,
) (GetRawProfilesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetFileIOProfile(
	context.Context,
	GetFileIOProfileRequestObject,
) (GetFileIOProfileResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetFileIOFlamegraph(
	context.Context,
	GetFileIOFlamegraphRequestObject,
) (GetFileIOFlamegraphResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) StopProfilingJob(
	context.Context,
	StopProfilingJobRequestObject,
) (StopProfilingJobResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) ListTracingJobs(
	context.Context,
	ListTracingJobsRequestObject,
) (ListTracingJobsResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) CreateTracingJob(
	context.Context,
	CreateTracingJobRequestObject,
) (CreateTracingJobResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetTracingCapabilities(
	context.Context,
	GetTracingCapabilitiesRequestObject,
) (GetTracingCapabilitiesResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) GetTracingJob(
	context.Context,
	GetTracingJobRequestObject,
) (GetTracingJobResponseObject, error) {
	return nil, errNotImplemented
}

func (*unimplementedStrictServer) StopTracingJob(
	context.Context,
	StopTracingJobRequestObject,
) (StopTracingJobResponseObject, error) {
	return nil, errNotImplemented
}

type routingStrictServer struct {
	StrictServerInterface
	capabilitiesCalled bool
	jobCalled          bool
}

func (s *routingStrictServer) GetProfilingCapabilities(
	context.Context,
	GetProfilingCapabilitiesRequestObject,
) (GetProfilingCapabilitiesResponseObject, error) {
	s.capabilitiesCalled = true
	return GetProfilingCapabilities200JSONResponse{
		Data: ProfilingCapabilities{Items: []ProfilingCapability{}},
	}, nil
}

func (s *routingStrictServer) GetProfilingJob(
	context.Context,
	GetProfilingJobRequestObject,
) (GetProfilingJobResponseObject, error) {
	s.jobCalled = true
	return GetProfilingJob200JSONResponse{}, nil
}

func TestFileIOClientPreservesIntegerCounters(t *testing.T) {
	for _, value := range []uint64{0, 1<<53 - 1, 1 << 53, 1<<53 + 1, math.MaxInt64} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			stats := fmt.Sprintf(`{"bytes":%d,"count":%d,"duration_ns":%d}`, value, value, value)
			body := fmt.Sprintf(`{"data":{"groups":[{"scope":"host","direction":"read",`+
				`"root":{"frame":{"name":"all"},"stats":%s,"self":%s,`+
				`"children":[{"frame":{"name":"read"},"stats":%s,"self":%s}]},`+
				`"unknown":%s,"outcomes":{"error":%s},"dropped_samples":{"collection":%d}}],`+
				`"diagnostics":{"completed":%d},"numeric_complete":false}}`,
				stats, stats, stats, stats, stats, stats, uint64(math.MaxUint64), uint64(math.MaxUint64))
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Content-Type", "application/json")
			_, _ = recorder.WriteString(body)
			response := recorder.Result()
			defer response.Body.Close()
			parsed, err := ParseGetFileIOProfileResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(parsed.JSON200)
			if err != nil {
				t.Fatal(err)
			}
			decode := func(raw []byte) any {
				t.Helper()
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				var result any
				if err := decoder.Decode(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			if !reflect.DeepEqual(decode([]byte(body)), decode(encoded)) {
				t.Fatalf("client changed IO counters: want %s, got %s", body, encoded)
			}
		})
	}
}

func TestResultReferenceContract(t *testing.T) {
	document, err := openapi3.NewLoader().LoadFromData(OpenAPIJSON())
	if err != nil {
		t.Fatal(err)
	}
	result := document.Components.Schemas["Job"].Value.Properties["result_url"].Value
	if result.Format != "uri-reference" {
		t.Fatalf("result_url format = %q, want uri-reference", result.Format)
	}
}
