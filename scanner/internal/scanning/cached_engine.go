package scanning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"github.com/redis/go-redis/v9"
)

type VersionSource interface {
	Version(ctx context.Context) (string, error)
}

type cachedVerdict struct {
	Verdict   string `json:"verdict"`
	Signature string `json:"signature"`
}

type CachedEngine struct {
	base           Engine
	versioner      VersionSource
	cache          *redis.Client
	ttl            time.Duration
	redisTimeout   time.Duration
	versionTimeout time.Duration
	policy         string
	logger         *slog.Logger
}

func NewCachedEngine(
	base Engine,
	versioner VersionSource,
	cache *redis.Client,
	ttl time.Duration,
	redisTimeout time.Duration,
	versionTimeout time.Duration,
	policy string,
	logger *slog.Logger,
) *CachedEngine {
	return &CachedEngine{
		base:           base,
		versioner:      versioner,
		cache:          cache,
		ttl:            ttl,
		redisTimeout:   redisTimeout,
		versionTimeout: versionTimeout,
		policy:         policy,
		logger:         logger,
	}
}

func (e *CachedEngine) Ping(ctx context.Context) error {
	return e.base.Ping(ctx)
}

func (e *CachedEngine) Scan(
	ctx context.Context,
	source io.Reader,
) (clamav.Result, error) {
	return e.scanClamAV(ctx, source)
}

func (e *CachedEngine) scanClamAV(
	ctx context.Context,
	source io.Reader,
) (clamav.Result, error) {
	start := time.Now()

	result, err := e.base.Scan(ctx, source)

	clamavDuration.Observe(time.Since(start).Seconds())

	if err != nil {
		clamavScans.WithLabelValues("error").Inc()
	} else {
		clamavScans.WithLabelValues("success").Inc()
	}

	return result, err
}

func scannerTTLWithJitter(ttl time.Duration) time.Duration {
	jitterRange := ttl / 10
	if jitterRange <= 0 {
		return ttl
	}

	jitter := time.Duration(
		rand.Int64N(int64(jitterRange) + 1),
	)
	return ttl - jitter
}

func validVerdict(v cachedVerdict) bool {
	switch v.Verdict {
	case "clean":
		return v.Signature == ""
	case "infected":
		return v.Signature != ""
	default:
		return false
	}
}

func (e *CachedEngine) cacheKey(
	version string,
	fileSHA256 string,
) string {
	fingerprint := sha256.Sum256(
		[]byte(e.policy + "\x00" + version),
	)

	return "scan:clamav:v1:" +
		hex.EncodeToString(fingerprint[:]) +
		":" + fileSHA256
}

func (e *CachedEngine) ScanHashed(
	ctx context.Context,
	data []byte,
	fileSHA256 string,
) (clamav.Result, error) {
	if e.cache == nil {
		return e.scanClamAV(ctx, bytes.NewReader(data))
	}
	versionCtx, cancel := context.WithTimeout(
		ctx,
		e.versionTimeout,
	)

	version, err := e.versioner.Version(versionCtx)
	cancel()

	if err != nil || version == "" {
		cacheLookups.WithLabelValues("bypass").Inc()

		e.logger.Warn(
			"ClamAV version unavailable, bypassing cache",
			"error", err,
		)

		// Без проверенной версии запрещаем cache hit.
		return e.scanClamAV(ctx, bytes.NewReader(data))
	}

	key := e.cacheKey(version, fileSHA256)
	getCtx, cancel := context.WithTimeout(
		ctx,
		e.redisTimeout,
	)

	payload, err := e.cache.Get(getCtx, key).Bytes()
	cancel()

	switch {
	case err == nil:
		var saved cachedVerdict

		if json.Unmarshal(payload, &saved) == nil &&
			validVerdict(saved) {
			if err := ctx.Err(); err != nil {
				return clamav.Result{}, err
			}

			cacheLookups.WithLabelValues("hit").Inc()

			return clamav.Result{
				Verdict:   saved.Verdict,
				Signature: saved.Signature,
			}, nil
		}

		cacheLookups.WithLabelValues("error").Inc()
		e.logger.Warn("Invalid cached verdict", "key", key)

	case errors.Is(err, redis.Nil):
		cacheLookups.WithLabelValues("miss").Inc()

	default:
		cacheLookups.WithLabelValues("error").Inc()
		e.logger.Warn("Redis GET failed", "error", err)
	}
	if err := ctx.Err(); err != nil {
		return clamav.Result{}, err
	}

	result, err := e.scanClamAV(
		ctx,
		bytes.NewReader(data),
	)

	if err != nil {
		return result, err
	}

	saved := cachedVerdict{
		Verdict:   result.Verdict,
		Signature: result.Signature,
	}

	if !validVerdict(saved) {
		return clamav.Result{},
			errors.New("invalid ClamAV verdict")
	}

	if err := ctx.Err(); err != nil {
		return clamav.Result{}, err
	}
	payload, err = json.Marshal(saved)
	if err != nil {
		return result, nil
	}

	setCtx, cancel := context.WithTimeout(
		ctx,
		e.redisTimeout,
	)

	err = e.cache.Set(
		setCtx,
		key,
		payload,
		scannerTTLWithJitter(e.ttl),
	).Err()

	cancel()

	if err != nil {
		cacheSetErrors.Inc()
		e.logger.Warn("Redis SET failed", "error", err)
	}

	return result, nil
}
