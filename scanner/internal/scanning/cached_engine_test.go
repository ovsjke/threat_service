package scanning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"github.com/redis/go-redis/v9"
)

type countingClamAV struct {
	calls int
}

func (c *countingClamAV) Ping(ctx context.Context) error {
	return nil
}

func (c *countingClamAV) Scan(
	ctx context.Context,
	source io.Reader,
) (clamav.Result, error) {
	c.calls++

	return clamav.Result{
		Verdict: "clean",
	}, nil
}

type fakeVersionSource struct {
	version string
}

func (v *fakeVersionSource) Version(
	ctx context.Context,
) (string, error) {
	return v.version, nil
}

func TestCachedEngineVersionInvalidation(t *testing.T) {
	ctx := context.Background()

	// Поднимаем изолированный Redis.
	server := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: server.Addr(),
	})
	defer client.Close()

	engine := &countingClamAV{}

	versioner := &fakeVersionSource{
		version: "ClamAV-1.4.6-db-28188",
	}

	logger := slog.New(
		slog.NewTextHandler(io.Discard, nil),
	)

	cached := NewCachedEngine(
		engine,
		versioner,
		client,
		time.Hour,
		100*time.Millisecond,
		100*time.Millisecond,
		"v1",
		logger,
	)

	data := []byte("safe test file")

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	scan := func(wantCalls int) {
		t.Helper()

		result, err := cached.ScanHashed(ctx, data, hash)
		if err != nil {
			t.Fatal(err)
		}

		if result.Verdict != "clean" {
			t.Fatalf("unexpected verdict: %s", result.Verdict)
		}

		if engine.calls != wantCalls {
			t.Fatalf(
				"ClamAV calls: got %d, want %d",
				engine.calls,
				wantCalls,
			)
		}
	}

	scan(1)

	scan(1)

	versioner.version = "ClamAV-1.4.6-db-28189"

	scan(2)

	scan(2)
}
