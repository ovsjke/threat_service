//go:build integration

package tests

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/scanning"
	"github.com/ovsjke/threat_service/scanner/internal/threatclient"
)

func uploadCatalogFile(t *testing.T, data string) scanning.Result {
	t.Helper()
	base := os.Getenv("SCANNER_TEST_URL")
	if base == "" {
		base = "http://127.0.0.1:8082"
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "catalog-test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(part, data); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Post(strings.TrimRight(base, "/")+"/scans", writer.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("HTTP %d: %s", response.StatusCode, raw)
	}
	var result scanning.Result
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	hash := md5.Sum([]byte(data))
	if result.MD5 != hex.EncodeToString(hash[:]) || result.Verdict != "clean" {
		t.Fatalf("unexpected scan: %s", raw)
	}
	t.Logf("HTTP 200: %s", raw)
	return result
}

// Requires real Scanner, ClamAV, Threat API and PostgreSQL. Creates one uniquely
// identified test record, retaining existing database contents.
func TestRealThreatCatalog(t *testing.T) {
	target := os.Getenv("THREAT_TEST_GRPC_ADDR")
	if target == "" {
		t.Skip("set THREAT_TEST_GRPC_ADDR to run full catalog E2E")
	}
	client, err := threatclient.New(target)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	data := fmt.Sprintf("clean catalog integration fixture %d\n", time.Now().UnixNano())
	result := uploadCatalogFile(t, data)
	if result.CatalogStatus != "not_found" || result.Threat != nil || result.CatalogError != "" {
		t.Fatalf("missing: %+v", result)
	}
	want := scanning.Threat{MD5: result.MD5, Name: "Scanner E2E clean fixture", Description: "Harmless test record", Severity: "low"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	created, err := client.Create(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	result = uploadCatalogFile(t, data)
	if result.CatalogStatus != "found" || !reflect.DeepEqual(result.Threat, created) || result.CatalogError != "" {
		t.Fatalf("found: %+v, threat: %+v", result, result.Threat)
	}
}

func TestRealCatalogUnavailable(t *testing.T) {
	if os.Getenv("SCANNER_EXPECT_CATALOG_UNAVAILABLE") != "1" {
		t.Skip("explicitly stop Threat API and set SCANNER_EXPECT_CATALOG_UNAVAILABLE=1")
	}
	result := uploadCatalogFile(t, "clean catalog outage fixture\n")
	if result.CatalogStatus != "unavailable" || result.CatalogError == "" || result.Threat != nil {
		t.Fatalf("outage: %+v", result)
	}
}
