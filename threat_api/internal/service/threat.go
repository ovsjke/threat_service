package service

import (
	"context"
	"threat_api/internal/entity"
	"strings"
)

type ThreatRepository interface {
	GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error)

	Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)

	Update(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
}

type ThreatService struct {
	repo ThreatRepository
}

func NewThreatService(repo ThreatRepository) *ThreatService {
	return &ThreatService{repo: repo}
}
func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error) {
	if !IsValidMD5(md5) {
		return nil, entity.ErrInvalidMD5
	}
	md5 = strings.ToLower(md5)
	return s.repo.GetByMD5(ctx, md5)
}

func (s *ThreatService) Update(ctx context.Context, req *entity.Threat) (*entity.Threat, error) {
	req.MD5 = strings.ToLower(req.MD5)
	if !IsValidMD5(req.MD5) {
		return nil, entity.ErrInvalidMD5
	}
	if err := ValidateName(req.Name); err != nil {
		return nil, err
	}
	if req.Severity != "" && !ValidateSeverity(req.Severity) {
		return nil, entity.ErrInvalidSeverity
	}
	if req.Severity == "" {
		req.Severity = entity.SeverityLow
	}
	threat, err := s.repo.Update(ctx, req)
	if err != nil {
		return nil, err
	}
	return threat, nil
}

func (s *ThreatService) Create(ctx context.Context, req *entity.Threat) (*entity.Threat, error) {
	req.MD5 = strings.ToLower(req.MD5)
	if !IsValidMD5(req.MD5) {
		return nil, entity.ErrInvalidMD5
	}
	if err := ValidateName(req.Name); err != nil {
		return nil, err
	}
	if req.Severity != "" && !ValidateSeverity(req.Severity) {
		return nil, entity.ErrInvalidSeverity
	}
	if req.Severity == "" {
		req.Severity = entity.SeverityLow
	}
	threat, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return threat, nil
}
