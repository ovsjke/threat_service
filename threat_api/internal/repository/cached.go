package repository

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/ovsjke/threat_service/threat_api/internal/entity"
	"github.com/ovsjke/threat_service/threat_api/internal/metrics"
	"github.com/redis/go-redis/v9"
)

type ThreatStore interface {
	GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error)
	Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
	Update(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
}

type CachedThreatStorage struct {
	base   ThreatStore
	cache  *redis.Client
	ttl    time.Duration
	logger *slog.Logger
}

func NewCachedThreatStorage(
	base ThreatStore,
	cache *redis.Client,
	ttl time.Duration,
	logger *slog.Logger,
) *CachedThreatStorage {
	return &CachedThreatStorage{
		base:   base,
		cache:  cache,
		ttl:    ttl,
		logger: logger,
	}
}

func cacheKey(md5 string) string {
	return "threat:v1:" + strings.ToLower(md5)
}

func ttlWithJitter(ttl time.Duration) time.Duration {
	jitterRange := ttl / 10
	if jitterRange <= 0 {
		return ttl
	}

	jitter := time.Duration(rand.Int64N(int64(jitterRange) + 1))
	return ttl - jitter
}

func (s *CachedThreatStorage) GetByMD5(
	ctx context.Context,
	md5 string,
) (*entity.Threat, error) {
	key := cacheKey(md5)

	cacheCtx, cancel := context.WithTimeout(
		ctx, 80*time.Millisecond,
	)
	data, err := s.cache.Get(cacheCtx, key).Bytes()
	cancel()

	switch {
	case err == nil:
		var threat entity.Threat

		if jsonErr := json.Unmarshal(data, &threat); jsonErr == nil &&
			strings.EqualFold(threat.MD5, md5) {

			metrics.ThreatCacheLookups.WithLabelValues("hit").Inc()
			return &threat, nil
		}

		metrics.ThreatCacheLookups.WithLabelValues("error").Inc()
		s.logger.Warn("invalid cached threat", "key", key)

	case errors.Is(err, redis.Nil):
		metrics.ThreatCacheLookups.WithLabelValues("miss").Inc()

	default:
		metrics.ThreatCacheLookups.WithLabelValues("error").Inc()
		s.logger.Warn("Redis GET failed", "error", err)
	}

	threat, err := s.base.GetByMD5(ctx, md5)
	if err != nil {
		return nil, err
	}

	data, err = json.Marshal(threat)
	if err != nil {
		s.logger.Warn("cache serialization failed", "error", err)
		return threat, nil
	}

	setCtx, cancel := context.WithTimeout(
		ctx, 80*time.Millisecond,
	)

	err = s.cache.Set(
		setCtx,
		key,
		data,
		ttlWithJitter(s.ttl),
	).Err()

	cancel()

	if err != nil {
		metrics.ThreatCacheSetErrors.Inc()
		s.logger.Warn("Redis SET failed", "error", err)
	}

	return threat, nil
}

func (s *CachedThreatStorage) Create(
	ctx context.Context,
	threat *entity.Threat,
) (*entity.Threat, error) {
	created, err := s.base.Create(ctx, threat)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx, created.MD5)
	return created, nil
}

func (s *CachedThreatStorage) Update(
	ctx context.Context,
	threat *entity.Threat,
) (*entity.Threat, error) {
	updated, err := s.base.Update(ctx, threat)
	if err != nil {
		return nil, err
	}

	s.invalidate(ctx, updated.MD5)
	return updated, nil
}

func (s *CachedThreatStorage) invalidate(
	ctx context.Context,
	md5 string,
) {
	cacheCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		150*time.Millisecond,
	)
	defer cancel()

	if err := s.cache.Del(
		cacheCtx,
		cacheKey(md5),
	).Err(); err != nil {
		metrics.ThreatCacheInvalidationErrors.Inc()
		s.logger.Warn(
			"Redis cache invalidation failed",
			"md5", md5,
			"error", err,
		)
	}
}
