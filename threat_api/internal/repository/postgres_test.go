//go:build integration

package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ovsjke/threat_service/threat_api/internal/entity"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	databaseURL := os.Getenv("TEST_DB_URL")
	if databaseURL == "" {
		t.Fatal("TEST_DB_URL is not set")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ConnConfig.Database != "threats_test" {
		t.Fatal("integration tests must use threats_test database")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	return pool
}

func testMD5(t *testing.T) string {
	t.Helper()

	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(data)
}

func cleanupThreat(t *testing.T, pool *pgxpool.Pool, md5 string) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := pool.Exec(ctx, "DELETE FROM threats WHERE md5 = $1", md5); err != nil {
			t.Errorf("failed to delete test threat: %v", err)
		}
	})
}

func seedThreat(t *testing.T, pool *pgxpool.Pool) *entity.Threat {
	t.Helper()

	md5 := testMD5(t)
	cleanupThreat(t, pool, md5)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var threat entity.Threat
	err := pool.QueryRow(ctx, `
        INSERT INTO threats (md5, name, description, severity, detected_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 hour')
        RETURNING md5, name, description, severity, detected_at, updated_at
    `, md5, "Original.Trojan", "Original description", entity.SeverityLow).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.Severity,
		&threat.DetectedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		t.Fatal(err)
	}

	return &threat
}

func TestPostgresStorage_Create(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresStorage(pool)

	t.Run("creates threat", func(t *testing.T) {
		md5 := testMD5(t)
		cleanupThreat(t, pool, md5)

		input := &entity.Threat{
			MD5:         md5,
			Name:        "Test.Trojan",
			Description: "Test description",
			Severity:    entity.SeverityHigh,
		}

		got, err := repo.Create(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("expected threat, got nil")
		}

		if got.MD5 != input.MD5 || got.Name != input.Name || got.Description != input.Description || got.Severity != input.Severity {
			t.Errorf("got threat %+v, want %+v", got, input)
		}
		if got.DetectedAt.IsZero() || got.UpdatedAt.IsZero() {
			t.Error("expected timestamps from database")
		}
		var name string
		var severity entity.Severity
		err = pool.QueryRow(context.Background(), "SELECT name, severity FROM threats WHERE md5 = $1", md5).Scan(&name, &severity)
		if err != nil {
			t.Fatal(err)
		}
		if name != input.Name || severity != input.Severity {
			t.Errorf("database got name %q, severity %q", name, severity)
		}
	})

	t.Run("duplicate MD5", func(t *testing.T) {
		existing := seedThreat(t, pool)

		got, err := repo.Create(context.Background(), &entity.Threat{
			MD5:         existing.MD5,
			Name:        "Duplicate.Trojan",
			Description: "Duplicate description",
			Severity:    entity.SeverityHigh,
		})

		if !errors.Is(err, entity.ErrThreatAlreadyExists) {
			t.Fatalf("got error %v, want ErrThreatAlreadyExists", err)
		}
		if got != nil {
			t.Errorf("expected nil threat, got %+v", got)
		}
	})
}

func TestPostgresStorage_GetByMD5(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresStorage(pool)

	t.Run("threat found", func(t *testing.T) {
		expected := seedThreat(t, pool)

		got, err := repo.GetByMD5(context.Background(), expected.MD5)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("expected threat, got nil")
		}

		if got.MD5 != expected.MD5 || got.Name != expected.Name || got.Description != expected.Description || got.Severity != expected.Severity {
			t.Errorf("got threat %+v, want %+v", got, expected)
		}
		if !got.DetectedAt.Equal(expected.DetectedAt) || !got.UpdatedAt.Equal(expected.UpdatedAt) {
			t.Errorf("got timestamps %v and %v, want %v and %v", got.DetectedAt, got.UpdatedAt, expected.DetectedAt, expected.UpdatedAt)
		}
	})

	t.Run("threat not found", func(t *testing.T) {
		got, err := repo.GetByMD5(context.Background(), testMD5(t))
		if !errors.Is(err, entity.ErrThreatNotFound) {
			t.Fatalf("got error %v, want ErrThreatNotFound", err)
		}
		if got != nil {
			t.Errorf("expected nil threat, got %+v", got)
		}
	})
}
func TestPostgresStorage_Update(t *testing.T) {
	pool := testPool(t)
	repo := NewPostgresStorage(pool)

	t.Run("updates threat", func(t *testing.T) {
		original := seedThreat(t, pool)

		input := &entity.Threat{
			MD5:         original.MD5,
			Name:        "Updated.Trojan",
			Description: "Updated description",
			Severity:    entity.SeverityCritical,
		}

		got, err := repo.Update(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatal("expected threat, got nil")
		}

		if got.MD5 != input.MD5 || got.Name != input.Name || got.Description != input.Description || got.Severity != input.Severity {
			t.Errorf("got threat %+v, want %+v", got, input)
		}
		if !got.DetectedAt.Equal(original.DetectedAt) {
			t.Errorf("detected_at changed: got %v, want %v", got.DetectedAt, original.DetectedAt)
		}
		if !got.UpdatedAt.After(original.UpdatedAt) {
			t.Errorf("updated_at was not refreshed: got %v, previous %v", got.UpdatedAt, original.UpdatedAt)
		}

		var name string
		var severity entity.Severity
		err = pool.QueryRow(context.Background(), "SELECT name, severity FROM threats WHERE md5 = $1", input.MD5).Scan(&name, &severity)
		if err != nil {
			t.Fatal(err)
		}
		if name != input.Name || severity != input.Severity {
			t.Errorf("database got name %q, severity %q", name, severity)
		}
	})

	t.Run("threat not found", func(t *testing.T) {
		got, err := repo.Update(context.Background(), &entity.Threat{
			MD5:      testMD5(t),
			Name:     "Missing.Trojan",
			Severity: entity.SeverityLow,
		})
		if !errors.Is(err, entity.ErrThreatNotFound) {
			t.Fatalf("got error %v, want ErrThreatNotFound", err)
		}
		if got != nil {
			t.Errorf("expected nil threat, got %+v", got)
		}
	})
}
