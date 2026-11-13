package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"threat_api/internal/entity"
)

type PostgresStorage struct {
	pool *pgxpool.Pool
}

func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

func (s *PostgresStorage) GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error) {
	var Threat entity.Threat
	const query = `SELECT md5, name, description, severity, detected_at, updated_at 
					FROM threats WHERE md5 = $1`
	row := s.pool.QueryRow(ctx, query, md5)
	err := row.Scan(&Threat.MD5, &Threat.Name, &Threat.Description, &Threat.Severity, &Threat.DetectedAt, &Threat.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("threat not found: %w", entity.ErrThreatNotFound)
		}
		return nil, err
	}
	return &Threat, nil
}

func (s *PostgresStorage) Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	var Threat entity.Threat
	var pgErr *pgconn.PgError
	const query = `INSERT INTO threats (md5, name, description, severity) VALUES ($1, $2, $3, $4) 
					RETURNING md5, name, description, severity, detected_at, updated_at`
	row := s.pool.QueryRow(ctx, query, threat.MD5, threat.Name, threat.Description, threat.Severity)
	err := row.Scan(&Threat.MD5, &Threat.Name, &Threat.Description, &Threat.Severity, &Threat.DetectedAt, &Threat.UpdatedAt)
	if err != nil {
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, entity.ErrThreatAlreadyExists
		}
		return nil, fmt.Errorf("failed to create threat: %w", err)
	}
	return &Threat, nil
}

func (s *PostgresStorage) Update(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	var Threat entity.Threat
	const query = `UPDATE threats SET name = $1, description = $2, severity = $3, updated_at = NOW() WHERE md5 = $4 
					RETURNING md5, name, description, severity, detected_at, updated_at`
	row := s.pool.QueryRow(ctx, query, threat.Name, threat.Description, threat.Severity, threat.MD5)
	err := row.Scan(&Threat.MD5, &Threat.Name, &Threat.Description, &Threat.Severity, &Threat.DetectedAt, &Threat.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, entity.ErrThreatNotFound
		}
		return nil, fmt.Errorf("failed to update threat: %w", err)
	}
	return &Threat, nil
}
