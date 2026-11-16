//go:build integration

package tests

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Run against a real HTTP scanner connected to real clamd, never a fake engine.
func TestRealClamAV(t *testing.T) {
	base := os.Getenv("SCANNER_TEST_URL")
	if base == "" {
		base = "http://127.0.0.1:8082"
	}
	base = strings.TrimRight(base, "/")
	client := &http.Client{Timeout: 90 * time.Second}
	ready, err := client.Get(base + "/ready")
	if err != nil {
		t.Fatalf("start scanner and ClamAV first: %v", err)
	}
	ready.Body.Close()
	if ready.StatusCode != 200 {
		t.Fatalf("ClamAV not ready: %d", ready.StatusCode)
	}
	for _, tc := range []struct{ name, data, verdict string }{
		{"clean", "hello scanner\n", "clean"},
		{"eicar", `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`, "infected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			p, err := mw.CreateFormFile("file", tc.name+".txt")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(p, tc.data)
			_ = mw.Close()
			response, err := client.Post(base+"/scans", mw.FormDataContentType(), &body)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("%d: %s", response.StatusCode, raw)
			}
			var result struct {
				MD5        string `json:"md5"`
				SHA256     string `json:"sha256"`
				Size       int64  `json:"size"`
				Verdict    string `json:"verdict"`
				Signature  string `json:"signature"`
				DurationMS int64  `json:"duration_ms"`
			}
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			m, s := md5.Sum([]byte(tc.data)), sha256.Sum256([]byte(tc.data))
			if result.MD5 != hex.EncodeToString(m[:]) || result.SHA256 != hex.EncodeToString(s[:]) || result.Size != int64(len(tc.data)) || result.Verdict != tc.verdict || result.DurationMS < 0 {
				t.Fatalf("unexpected result: %s", raw)
			}
			if (tc.verdict == "infected") != (result.Signature != "") {
				t.Fatalf("signature: %s", raw)
			}
			t.Logf("%s", raw)
		})
	}
}
