package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"github.com/ovsjke/threat_service/scanner/internal/scanning"
)

type engine struct {
	fail    error
	verdict string
	block   bool
}

func (e engine) Scan(ctx context.Context, r io.Reader) (clamav.Result, error) {
	if e.block {
		<-ctx.Done()
		return clamav.Result{}, ctx.Err()
	}
	_, err := io.Copy(io.Discard, r)
	if err != nil {
		return clamav.Result{}, &clamav.UploadError{Err: err}
	}
	if e.fail != nil {
		return clamav.Result{}, e.fail
	}
	verdict := e.verdict
	if verdict == "" {
		verdict = "clean"
	}
	signature := ""
	if verdict == "infected" {
		signature = "Test.Signature"
	}
	return clamav.Result{Verdict: verdict, Signature: signature}, nil
}
func (e engine) Ping(context.Context) error { return e.fail }
func testHandler(e engine) *Handler {
	return &Handler{Service: scanning.New(e, 3, 1), MaxFileBytes: 3, Timeout: time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}
func upload(t *testing.T, field, data string) (*bytes.Buffer, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if field != "" {
		p, err := w.CreateFormFile(field, "untrusted.bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(p, data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &b, w.FormDataContentType()
}
func TestScanHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, field, data string
		e                 engine
		status            int
		code              string
	}{
		{name: "clean", field: "file", data: "abc", status: 200},
		{name: "infected", field: "file", data: "abc", e: engine{verdict: "infected"}, status: 200},
		{name: "empty", field: "file", status: 400, code: "empty_file"},
		{name: "missing", status: 400, code: "missing_file"},
		{name: "wrong field", field: "other", data: "abc", status: 400, code: "missing_file"},
		{name: "too large", field: "file", data: "abcd", status: 413, code: "file_too_large"},
		{name: "engine failed", field: "file", data: "abc", e: engine{fail: errors.New("failed")}, status: 502, code: "engine_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := upload(t, tc.field, tc.data)
			r := httptest.NewRequest("POST", "/scans", body)
			r.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			testHandler(tc.e).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatal("not JSON")
			}
			if tc.status == 200 {
				var result scanning.Result
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Size != 3 || result.MD5 != "900150983cd24fb0d6963f7d28e17f72" || len(result.SHA256) != 64 || result.DurationMS < 0 {
					t.Fatalf("%+v", result)
				}
				if tc.name == "infected" && (result.Verdict != "infected" || result.Signature == "") {
					t.Fatalf("%+v", result)
				}
			} else {
				var result struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Error.Code != tc.code {
					t.Fatalf("%s: %v", w.Body.String(), err)
				}
			}
		})
	}
}
func TestBadMultipartAndBodyLimit(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		contentType   string
		status        int
		unknownLength bool
	}{
		{"wrong type", "abc", "text/plain", 400, false},
		{"bad boundary", "abc", "multipart/form-data; boundary=missing", 400, false},
		{"body known", strings.Repeat("x", int(MultipartOverhead)+100), "multipart/form-data; boundary=x", 413, false},
		{"malformed streamed", strings.Repeat("x", int(MultipartOverhead)+100), "multipart/form-data; boundary=x", 400, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/scans", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			if tc.unknownLength {
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			testHandler(engine{}).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
		})
	}
}
func TestTruncatedAndExtraParts(t *testing.T) {
	b, ct := upload(t, "file", "abc")
	var extra bytes.Buffer
	mw := multipart.NewWriter(&extra)
	for i := 0; i < 2; i++ {
		p, err := mw.CreateFormFile("file", "a")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(p, "abc")
	}
	_ = mw.Close()
	for _, tc := range []struct {
		data, contentType string
		status            int
	}{
		{strings.Split(b.String(), "abc")[0] + "abc", ct, 400},
		{extra.String(), mw.FormDataContentType(), 400},
		{b.String() + strings.Repeat("x", int(MultipartOverhead)+100), ct, 413},
	} {
		r := httptest.NewRequest("POST", "/scans", strings.NewReader(tc.data))
		r.ContentLength = -1
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		testHandler(engine{}).ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
	}
}
func TestCanceledAndTimeout(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		b, ct := upload(t, "file", "abc")
		r := httptest.NewRequest("POST", "/scans", b)
		r.Header.Set("Content-Type", ct)
		h := testHandler(engine{block: true})
		h.Timeout = 10 * time.Millisecond
		want := 504
		if canceled {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
			want = 408
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%d: %s", w.Code, w.Body.String())
		}
	}
}
func TestRoutes(t *testing.T) {
	h := testHandler(engine{fail: errors.New("unavailable")})
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/health", 200}, {"GET", "/ready", 503}, {"GET", "/scans/id", 404}, {"GET", "/scans", 405}, {"POST", "/health", 405}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}

// A real HTTP connection verifies that a slow upload is interrupted, even while
// the scanner is blocked in a body read rather than in a clamd network call.
func TestSlowUploadDeadline(t *testing.T) {
	h := testHandler(engine{})
	h.Timeout = 40 * time.Millisecond
	server := httptest.NewServer(h)
	defer server.Close()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, err := http.NewRequest("POST", server.URL+"/scans", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "multipart/form-data; boundary=slow")
	go func() {
		_, _ = io.WriteString(writer, "--slow\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\na")
	}()
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 504 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("%d: %s", response.StatusCode, body)
	}
}
