//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type threatResponse struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	DetectedAt  time.Time `json:"detected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func request(t *testing.T, client *http.Client, method, url string, body any, wantStatus int) []byte {
	t.Helper()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: got status %d, want %d, body: %s", method, url, resp.StatusCode, wantStatus, data)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("got Content-Type %q, want application/json", resp.Header.Get("Content-Type"))
	}

	return data
}

func decodeThreat(t *testing.T, data []byte) threatResponse {
	t.Helper()

	var threat threatResponse
	if err := json.Unmarshal(data, &threat); err != nil {
		t.Fatalf("failed to decode threat: %v", err)
	}
	return threat
}

func assertThreat(t *testing.T, threat threatResponse, md5, name, description, severity string) {
	t.Helper()

	if threat.MD5 != md5 {
		t.Errorf("got MD5 %q, want %q", threat.MD5, md5)
	}
	if threat.Name != name {
		t.Errorf("got name %q, want %q", threat.Name, name)
	}
	if threat.Description != description {
		t.Errorf("got description %q, want %q", threat.Description, description)
	}
	if threat.Severity != severity {
		t.Errorf("got severity %q, want %q", threat.Severity, severity)
	}
	if threat.DetectedAt.IsZero() || threat.UpdatedAt.IsZero() {
		t.Error("expected non-zero timestamps")
	}
}

func TestThreatLifecycle(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	if baseURL == "" {
		t.Fatal("E2E_BASE_URL is not set")
	}

	client := &http.Client{Timeout: 5 * time.Second}

	var rawMD5 [16]byte
	if _, err := rand.Read(rawMD5[:]); err != nil {
		t.Fatal(err)
	}
	md5 := hex.EncodeToString(rawMD5[:])

	created := decodeThreat(t, request(t, client,
		http.MethodPost, baseURL+"/info",
		map[string]string{
			"md5":         md5,
			"name":        "Test.Trojan",
			"description": "Test threat",
			"severity":    "high",
		},
		http.StatusCreated,
	))
	assertThreat(t, created, md5, "Test.Trojan", "Test threat", "high")

	found := decodeThreat(t, request(t, client,
		http.MethodGet, baseURL+"/info/"+md5, nil, http.StatusOK,
	))
	assertThreat(t, found, md5, "Test.Trojan", "Test threat", "high")

	request(t, client,
		http.MethodPost, baseURL+"/info",
		map[string]string{
			"md5":      md5,
			"name":     "Test.Trojan",
			"severity": "high",
		},
		http.StatusConflict,
	)

	updated := decodeThreat(t, request(t, client,
		http.MethodPut, baseURL+"/info/"+md5,
		map[string]string{
			"name":        "Test.Updated",
			"description": "Updated threat",
			"severity":    "critical",
		},
		http.StatusOK,
	))
	assertThreat(t, updated, md5, "Test.Updated", "Updated threat", "critical")
	if !updated.DetectedAt.Equal(created.DetectedAt) {
		t.Error("detected_at changed after update")
	}

	found = decodeThreat(t, request(t, client,
		http.MethodGet, baseURL+"/info/"+md5, nil, http.StatusOK,
	))
	assertThreat(t, found, md5, "Test.Updated", "Updated threat", "critical")
	if !found.DetectedAt.Equal(created.DetectedAt) {
		t.Error("detected_at changed after update")
	}
	if !found.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Error("updated_at from GET differs from PUT response")
	}
}
func TestMinimalPut(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	if baseURL == "" {
		t.Fatal("E2E_BASE_URL is not set")
	}

	client := &http.Client{Timeout: 5 * time.Second}

	var rawMD5 [16]byte
	if _, err := rand.Read(rawMD5[:]); err != nil {
		t.Fatal(err)
	}

	md5 := hex.EncodeToString(rawMD5[:])
	url := baseURL + "/info/" + md5

	created := decodeThreat(t, request(t, client,
		http.MethodPost, baseURL+"/info",
		map[string]string{
			"md5":         md5,
			"name":        "Original.Threat",
			"description": "Original description",
			"severity":    "high",
		},
		http.StatusCreated,
	))

	updated := decodeThreat(t, request(t, client,
		http.MethodPut, url,
		map[string]string{
			"name": "Updated.Threat",
		},
		http.StatusOK,
	))

	assertThreat(t, updated, md5, "Updated.Threat", "", "low")

	if !updated.DetectedAt.Equal(created.DetectedAt) {
		t.Error("detected_at changed after update")
	}

	found := decodeThreat(t, request(t, client,
		http.MethodGet, url, nil, http.StatusOK,
	))

	assertThreat(t, found, md5, "Updated.Threat", "", "low")

	if !found.DetectedAt.Equal(created.DetectedAt) {
		t.Error("detected_at changed after update")
	}
	if !found.UpdatedAt.Equal(updated.UpdatedAt) {
		t.Error("updated_at from GET differs from PUT response")
	}
}
