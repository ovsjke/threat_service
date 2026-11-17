package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/scanning"
)

func logRecords(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []map[string]any
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func TestRequestAndFailureLogs(t *testing.T) {
	for _, tc := range []struct {
		name, path     string
		engine         engine
		status         int
		message, level string
	}{
		{name: "success", path: "/scans", status: 200, message: "scan completed", level: "INFO"},
		{name: "engine failure", path: "/scans", engine: engine{fail: errors.New("clamd connection refused")}, status: 502, message: "scan failed", level: "ERROR"},
		{name: "timeout", path: "/scans", engine: engine{block: true}, status: 504, message: "scan failed", level: "WARN"},
		{name: "readiness", path: "/ready", engine: engine{fail: errors.New("clamd connection refused")}, status: 503, message: "ClamAV is not ready", level: "WARN"},
		{name: "not found", path: "/missing", status: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			h := testHandler(tc.engine)
			h.Timeout = 20 * time.Millisecond
			h.Log = slog.New(slog.NewJSONHandler(&logs, nil))
			body, contentType := upload(t, "file", "abc")
			method := http.MethodPost
			if tc.path == "/ready" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, tc.path+"?token=private-query", body)
			req.Header.Set("Content-Type", contentType)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Fatalf("status %d", response.Code)
			}
			requests, events := 0, 0
			for _, record := range logRecords(t, logs.Bytes()) {
				if record["msg"] == "HTTP request" {
					requests++
					if record["method"] != method || record["path"] != tc.path || record["status"] != float64(tc.status) || record["duration_ms"] == nil {
						t.Fatalf("request log: %+v", record)
					}
				}
				if tc.message != "" && record["msg"] == tc.message {
					events++
					if record["level"] != tc.level {
						t.Fatalf("level: %+v", record)
					}
					if tc.status >= 500 && record["error"] == nil {
						t.Fatalf("cause missing: %+v", record)
					}
					if tc.name == "success" && (record["md5"] != "900150983cd24fb0d6963f7d28e17f72" || record["verdict"] != "clean") {
						t.Fatalf("scan log: %+v", record)
					}
				}
			}
			if requests != 1 || (tc.message != "" && events != 1) {
				t.Fatalf("request/event count = %d/%d: %s", requests, events, logs.String())
			}
			if strings.Contains(logs.String(), "private-query") || strings.Contains(logs.String(), "untrusted.bin") {
				t.Fatalf("request metadata leaked: %s", logs.String())
			}
		})
	}
}

type failedCatalog struct{}

func (failedCatalog) Get(context.Context, string) (*scanning.Threat, error) {
	return nil, scanning.ErrCatalogUnavailable
}
func (failedCatalog) Create(context.Context, scanning.Threat) (*scanning.Threat, error) {
	return nil, errors.New("unexpected create")
}

func TestCatalogFailureLoggedWithSuccessfulResponse(t *testing.T) {
	var logs bytes.Buffer
	h := testHandler(engine{})
	h.Service = scanning.NewWithCatalog(engine{}, failedCatalog{}, 3, 1)
	h.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	body, contentType := upload(t, "file", "abc")
	req := httptest.NewRequest(http.MethodPost, "/scans", body)
	req.Header.Set("Content-Type", contentType)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("%d: %s", response.Code, response.Body.String())
	}
	var result scanning.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Verdict != "clean" || result.CatalogStatus != "unavailable" {
		t.Fatalf("result: %+v", result)
	}
	warnings := 0
	for _, record := range logRecords(t, logs.Bytes()) {
		if record["msg"] == "threat catalog failed" {
			warnings++
			if record["level"] != "WARN" || record["catalog_status"] != "unavailable" || record["error"] != scanning.ErrCatalogUnavailable.Error() || record["md5"] != result.MD5 {
				t.Fatalf("catalog log: %+v", record)
			}
		}
	}
	if warnings != 1 {
		t.Fatalf("catalog warning missing: %s", logs.String())
	}
}
