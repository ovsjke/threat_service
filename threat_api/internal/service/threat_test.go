package service

import (
	"context"
	"errors"
	"fmt"
	"threat_api/internal/entity"
	"strings"
	"testing"
)

type mockRepository struct {
	getByMD5Fn func(ctx context.Context, md5 string) (*entity.Threat, error)
	createFn   func(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
	updateFn   func(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
}

func (m *mockRepository) GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error) {
	return m.getByMD5Fn(ctx, md5)
}

func (m *mockRepository) Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	return m.createFn(ctx, threat)
}

func (m *mockRepository) Update(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	return m.updateFn(ctx, threat)
}

func TestThreatService_GetByMD5(t *testing.T) {
	validMD5 := "d41d8cd98f00b204e9800998ecf8427e"

	tests := []struct {
		name         string
		inputMD5     string
		repoErr      error
		wantErr      error
		wantMD5      string
		wantRepoCall bool
	}{
		{
			name:         "valid MD5",
			inputMD5:     validMD5,
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name:         "uppercase MD5",
			inputMD5:     strings.ToUpper(validMD5),
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name:         "invalid MD5",
			inputMD5:     "invalid",
			wantErr:      entity.ErrInvalidMD5,
			wantRepoCall: false,
		},
		{
			name:         "threat not found",
			inputMD5:     validMD5,
			wantMD5:      validMD5,
			repoErr:      entity.ErrThreatNotFound,
			wantErr:      entity.ErrThreatNotFound,
			wantRepoCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			repo := &mockRepository{
				getByMD5Fn: func(
					ctx context.Context,
					md5 string,
				) (*entity.Threat, error) {
					called = true

					if md5 != tt.wantMD5 {
						t.Errorf("repository got MD5 %q, want %q", md5, tt.wantMD5)
					}

					if tt.repoErr != nil {
						return nil, tt.repoErr
					}

					return &entity.Threat{
						MD5:  md5,
						Name: "Test.Trojan"}, nil
				},
			}

			service := NewThreatService(repo)

			got, err := service.GetByMD5(
				context.Background(),
				tt.inputMD5,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf(
					"got error %v, want %v",
					err,
					tt.wantErr,
				)
			}

			if called != tt.wantRepoCall {
				t.Errorf(
					"repository called = %v, want %v",
					called,
					tt.wantRepoCall,
				)
			}

			if tt.wantErr == nil {
				if got == nil {
					t.Fatal("expected threat, got nil")
				}

				if got.MD5 != tt.wantMD5 {
					t.Errorf("got MD5 %q, want %q", got.MD5, tt.wantMD5)
				}
			} else if got != nil {
				t.Errorf("expected nil threat, got %+v", got)
			}
		})
	}
}

func TestThreatService_Create(t *testing.T) {
	existsMd5 := "d41d8cd98f00b204e9800998ecf8427e"
	tests := []struct {
		name         string
		inputThreat  *entity.Threat
		repoErr      error
		wantErr      error
		wantRepoCall bool
	}{{
		name: "valid threat",
		inputThreat: &entity.Threat{
			MD5:         existsMd5,
			Name:        "Test.Trojan",
			Description: "A test trojan threat",
			Severity:    entity.SeverityHigh,
		},
		wantRepoCall: true,
	}, {
		name: "invalid MD5",
		inputThreat: &entity.Threat{
			MD5:         "invalid",
			Name:        "Test.Trojan",
			Description: "A test trojan threat",
			Severity:    entity.SeverityHigh,
		},
		wantErr:      entity.ErrInvalidMD5,
		wantRepoCall: false,
	},
		{
			name: "invalid name",
			inputThreat: &entity.Threat{
				MD5:         existsMd5,
				Name:        "",
				Description: "A test trojan threat",
				Severity:    entity.SeverityHigh,
			},
			wantErr:      entity.ErrInvalidName,
			wantRepoCall: false,
		}, {
			name: "invalid severity",
			inputThreat: &entity.Threat{
				MD5:         existsMd5,
				Name:        "Test.Trojan",
				Description: "A test trojan threat",
				Severity:    "InvalidSeverity",
			},
			wantErr:      entity.ErrInvalidSeverity,
			wantRepoCall: false,
		},
		{
			name: "MD5 already exists",
			inputThreat: &entity.Threat{
				MD5:         existsMd5,
				Name:        "Test.Trojan",
				Description: "A test trojan threat",
				Severity:    entity.SeverityHigh,
			},
			repoErr:      entity.ErrThreatAlreadyExists,
			wantErr:      entity.ErrThreatAlreadyExists,
			wantRepoCall: true,
		},
		{
			name: "empty severity defaults to default",
			inputThreat: &entity.Threat{
				MD5:         existsMd5,
				Name:        "Test.Trojan",
				Description: "A test trojan threat",
				Severity:    "",
			},
			wantRepoCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			repo := &mockRepository{
				createFn: func(
					ctx context.Context,
					threat *entity.Threat,
				) (*entity.Threat, error) {
					called = true

					if tt.repoErr != nil {
						return nil, tt.repoErr
					}
					if threat.Severity == "" {
						return nil, fmt.Errorf("severity cannot be empty in repository")
					}
					return threat, nil
				},
			}

			service := NewThreatService(repo)

			got, err := service.Create(
				context.Background(),
				tt.inputThreat,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			if called != tt.wantRepoCall {
				t.Errorf("repository called = %v, want %v", called, tt.wantRepoCall)
			}

			if tt.wantErr == nil {
				if got == nil {
					t.Fatal("expected threat, got nil")
				}
			}
		})
	}
}

func TestThreatService_Update(t *testing.T) {
	validMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	repoError := errors.New("database unavailable")

	tests := []struct {
		name         string
		inputThreat  *entity.Threat
		repoErr      error
		wantErr      error
		wantMD5      string
		wantRepoCall bool
	}{
		{
			name: "valid threat",
			inputThreat: &entity.Threat{
				MD5:         validMD5,
				Name:        "Test.Updated",
				Description: "Updated test threat",
				Severity:    entity.SeverityHigh,
			},
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name: "uppercase MD5",
			inputThreat: &entity.Threat{
				MD5:      strings.ToUpper(validMD5),
				Name:     "Test.Updated",
				Severity: entity.SeverityHigh,
			},
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name: "invalid MD5",
			inputThreat: &entity.Threat{
				MD5:      "invalid",
				Name:     "Test.Updated",
				Severity: entity.SeverityHigh,
			},
			wantErr:      entity.ErrInvalidMD5,
			wantRepoCall: false,
		},
		{
			name: "invalid name",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     "",
				Severity: entity.SeverityHigh,
			},
			wantErr:      entity.ErrInvalidName,
			wantRepoCall: false,
		},
		{
			name: "name too long",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     strings.Repeat("a", 256),
				Severity: entity.SeverityHigh,
			},
			wantErr:      entity.ErrNameTooLong,
			wantRepoCall: false,
		},
		{
			name: "invalid severity",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     "Test.Updated",
				Severity: "invalid",
			},
			wantErr:      entity.ErrInvalidSeverity,
			wantRepoCall: false,
		},
		{
			name: "threat not found",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     "Test.Updated",
				Severity: entity.SeverityHigh,
			},
			repoErr:      entity.ErrThreatNotFound,
			wantErr:      entity.ErrThreatNotFound,
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name: "repository error",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     "Test.Updated",
				Severity: entity.SeverityHigh,
			},
			repoErr:      repoError,
			wantErr:      repoError,
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
		{
			name: "empty severity",
			inputThreat: &entity.Threat{
				MD5:      validMD5,
				Name:     "Test.Updated",
				Severity: "",
			},
			wantMD5:      validMD5,
			wantRepoCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			repo := &mockRepository{
				updateFn: func(
					ctx context.Context,
					threat *entity.Threat,
				) (*entity.Threat, error) {
					called = true

					if threat.MD5 != tt.wantMD5 {
						t.Errorf("repository got MD5 %q, want %q", threat.MD5, tt.wantMD5)
					}

					if tt.repoErr != nil {
						return nil, tt.repoErr
					}

					return threat, nil
				},
			}

			service := NewThreatService(repo)

			wantSeverity := tt.inputThreat.Severity
			if wantSeverity == "" {
				wantSeverity = entity.SeverityLow
			}

			got, err := service.Update(
				context.Background(),
				tt.inputThreat,
			)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}

			if called != tt.wantRepoCall {
				t.Errorf("repository called = %v, want %v", called, tt.wantRepoCall)
			}

			if tt.wantErr == nil {
				if got == nil {
					t.Fatal("expected threat, got nil")
				}

				if got.MD5 != tt.wantMD5 {
					t.Errorf("got MD5 %q, want %q", got.MD5, tt.wantMD5)
				}

				if got.Name != tt.inputThreat.Name {
					t.Errorf("got name %q, want %q", got.Name, tt.inputThreat.Name)
				}

				if got.Severity != wantSeverity {
					t.Errorf("got severity %q, want %q", got.Severity, wantSeverity)
				}
			} else if got != nil {
				t.Errorf("expected nil threat, got %+v", got)
			}
		})
	}
}
