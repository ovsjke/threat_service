package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"threat_api/internal/entity"
)

type mockThreatService struct {
	createFn   func(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
	getByMD5Fn func(ctx context.Context, md5 string) (*entity.Threat, error)
	updateFn   func(ctx context.Context, threat *entity.Threat) (*entity.Threat, error)
}

func (m *mockThreatService) Create(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	return m.createFn(ctx, threat)
}

func (m *mockThreatService) GetByMD5(ctx context.Context, md5 string) (*entity.Threat, error) {
	return m.getByMD5Fn(ctx, md5)
}

func (m *mockThreatService) Update(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
	return m.updateFn(ctx, threat)
}

func TestThreatHandler_Create(t *testing.T) {
	validMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	repoError := errors.New("database connection failed")

	validBody := `{
		"md5":"d41d8cd98f00b204e9800998ecf8427e",
		"name":"Test.Trojan",
		"description":"Test threat",
		"severity":"high"
	}`

	tests := []struct {
		name            string
		body            string
		serviceErr      error
		wantStatus      int
		wantServiceCall bool
		wantMessage     string
	}{
		{
			name:            "valid threat",
			body:            validBody,
			wantStatus:      http.StatusCreated,
			wantServiceCall: true,
		},
		{
			name:            "invalid MD5",
			body:            validBody,
			serviceErr:      entity.ErrInvalidMD5,
			wantStatus:      http.StatusBadRequest,
			wantServiceCall: true,
			wantMessage:     "Invalid MD5 format",
		},
		{
			name:            "invalid name",
			body:            validBody,
			serviceErr:      entity.ErrInvalidName,
			wantStatus:      http.StatusBadRequest,
			wantServiceCall: true,
			wantMessage:     "Invalid name",
		},
		{
			name:            "threat already exists",
			body:            validBody,
			serviceErr:      entity.ErrThreatAlreadyExists,
			wantStatus:      http.StatusConflict,
			wantServiceCall: true,
			wantMessage:     "Threat already exists",
		},
		{
			name:            "internal server error",
			body:            validBody,
			serviceErr:      repoError,
			wantStatus:      http.StatusInternalServerError,
			wantServiceCall: true,
			wantMessage:     "Internal server error",
		},
		{
			name:            "invalid JSON",
			body:            `{"md5":`,
			wantStatus:      http.StatusBadRequest,
			wantServiceCall: false,
			wantMessage:     "Invalid JSON body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			service := &mockThreatService{
				createFn: func(
					ctx context.Context,
					threat *entity.Threat,
				) (*entity.Threat, error) {
					called = true

					if threat.MD5 != validMD5 {
						t.Errorf("service got MD5 %q, want %q", threat.MD5, validMD5)
					}

					if threat.Name != "Test.Trojan" {
						t.Errorf("service got name %q, want Test.Trojan", threat.Name)
					}

					if threat.Severity != entity.SeverityHigh {
						t.Errorf("service got severity %q, want high", threat.Severity)
					}

					if tt.serviceErr != nil {
						return nil, tt.serviceErr
					}

					return &entity.Threat{
						MD5:         validMD5,
						Name:        "Test.Trojan",
						Description: "Test threat",
						Severity:    entity.SeverityHigh,
						DetectedAt:  time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
						UpdatedAt:   time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
					}, nil
				},
			}

			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			h := NewThreatHandler(service, log)

			r := chi.NewRouter()
			h.RegisterRoutes(r)

			req := httptest.NewRequest(
				http.MethodPost,
				"/info",
				strings.NewReader(tt.body),
			)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}

			if called != tt.wantServiceCall {
				t.Errorf("service called = %v, want %v", called, tt.wantServiceCall)
			}

			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("got Content-Type %q, want application/json", ct)
			}

			if tt.wantStatus == http.StatusCreated {
				var resp ThreatResponse

				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.MD5 != validMD5 {
					t.Errorf("got MD5 %q, want %q", resp.MD5, validMD5)
				}

				if resp.Name != "Test.Trojan" {
					t.Errorf("got name %q, want Test.Trojan", resp.Name)
				}

				if resp.Severity != "high" {
					t.Errorf("got severity %q, want high", resp.Severity)
				}
			} else {
				var resp struct {
					Message string `json:"message"`
					Details string `json:"details"`
				}

				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}

				if resp.Message != tt.wantMessage {
					t.Errorf("got message %q, want %q", resp.Message, tt.wantMessage)
				}

				if tt.serviceErr == repoError && strings.Contains(rec.Body.String(), repoError.Error()) {
					t.Error("response contains internal database error")
				}
			}
		})
	}
}

func assertJSONResponse(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantThreat *entity.Threat) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Fatalf("got status %d, want %d, body: %s", rec.Code, wantStatus, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("got Content-Type %q, want application/json", ct)
	}

	if wantThreat == nil {
		var resp ErrorResponse

		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}

		if resp.Message == "" {
			t.Error("expected non-empty error message")
		}

		return
	}

	var resp ThreatResponse

	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode threat response: %v", err)
	}

	if resp.MD5 != wantThreat.MD5 {
		t.Errorf("got MD5 %q, want %q", resp.MD5, wantThreat.MD5)
	}

	if resp.Name != wantThreat.Name {
		t.Errorf("got name %q, want %q", resp.Name, wantThreat.Name)
	}

	if resp.Description != wantThreat.Description {
		t.Errorf("got description %q, want %q", resp.Description, wantThreat.Description)
	}

	if resp.Severity != string(wantThreat.Severity) {
		t.Errorf("got severity %q, want %q", resp.Severity, wantThreat.Severity)
	}

	if !resp.DetectedAt.Equal(wantThreat.DetectedAt) {
		t.Errorf("got detected_at %v, want %v", resp.DetectedAt, wantThreat.DetectedAt)
	}

	if !resp.UpdatedAt.Equal(wantThreat.UpdatedAt) {
		t.Errorf("got updated_at %v, want %v", resp.UpdatedAt, wantThreat.UpdatedAt)
	}
}

func TestThreatHandler_GetByMD5(t *testing.T) {
	validMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	internalErr := errors.New("database connection failed")

	expected := &entity.Threat{
		MD5:         validMD5,
		Name:        "Test.Trojan",
		Description: "Test threat",
		Severity:    entity.SeverityHigh,
		DetectedAt:  time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		name       string
		md5        string
		serviceErr error
		wantStatus int
	}{
		{
			name:       "threat found",
			md5:        validMD5,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid MD5",
			md5:        "invalid",
			serviceErr: entity.ErrInvalidMD5,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "threat not found",
			md5:        validMD5,
			serviceErr: entity.ErrThreatNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "internal server error",
			md5:        validMD5,
			serviceErr: internalErr,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := 0

			service := &mockThreatService{
				getByMD5Fn: func(ctx context.Context, md5 string) (*entity.Threat, error) {
					called++

					if md5 != tt.md5 {
						t.Errorf("service got MD5 %q, want %q", md5, tt.md5)
					}

					if tt.serviceErr != nil {
						return nil, tt.serviceErr
					}

					return expected, nil
				},
			}

			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			h := NewThreatHandler(service, log)

			r := chi.NewRouter()
			h.RegisterRoutes(r)

			req := httptest.NewRequest(
				http.MethodGet,
				"/info/"+tt.md5,
				nil,
			)

			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)

			if called != 1 {
				t.Errorf("service called %d times, want 1", called)
			}

			var wantThreat *entity.Threat
			if tt.wantStatus == http.StatusOK {
				wantThreat = expected
			}

			assertJSONResponse(t, rec, tt.wantStatus, wantThreat)

			if tt.serviceErr == internalErr && strings.Contains(rec.Body.String(), internalErr.Error()) {
				t.Error("response contains internal database error")
			}
		})
	}
}

func TestThreatHandler_Update(t *testing.T) {
	validMD5 := "d41d8cd98f00b204e9800998ecf8427e"

	validBody := `{
		"name":"Trojan.Updated",
		"description":"Updated threat information",
		"severity":"critical"
	}`

	expected := &entity.Threat{
		MD5:         validMD5,
		Name:        "Trojan.Updated",
		Description: "Updated threat information",
		Severity:    entity.SeverityCritical,
		DetectedAt:  time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		name            string
		body            string
		serviceErr      error
		wantStatus      int
		wantServiceCall bool
	}{
		{
			name:            "successful update",
			body:            validBody,
			wantStatus:      http.StatusOK,
			wantServiceCall: true,
		},
		{
			name:            "invalid JSON",
			body:            `{"name":`,
			wantStatus:      http.StatusBadRequest,
			wantServiceCall: false,
		},
		{
			name:            "invalid severity",
			body:            validBody,
			serviceErr:      entity.ErrInvalidSeverity,
			wantStatus:      http.StatusBadRequest,
			wantServiceCall: true,
		},
		{
			name:            "threat not found",
			body:            validBody,
			serviceErr:      entity.ErrThreatNotFound,
			wantStatus:      http.StatusNotFound,
			wantServiceCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false

			service := &mockThreatService{
				updateFn: func(ctx context.Context, threat *entity.Threat) (*entity.Threat, error) {
					called = true

					if threat.MD5 != validMD5 {
						t.Errorf("service got MD5 %q, want %q", threat.MD5, validMD5)
					}

					if threat.Name != "Trojan.Updated" {
						t.Errorf("service got name %q, want Trojan.Updated", threat.Name)
					}

					if threat.Description != "Updated threat information" {
						t.Errorf("service got description %q", threat.Description)
					}

					if threat.Severity != entity.SeverityCritical {
						t.Errorf("service got severity %q, want critical", threat.Severity)
					}

					if tt.serviceErr != nil {
						return nil, tt.serviceErr
					}

					return expected, nil
				},
			}

			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			h := NewThreatHandler(service, log)

			r := chi.NewRouter()
			h.RegisterRoutes(r)

			req := httptest.NewRequest(
				http.MethodPut,
				"/info/"+validMD5,
				strings.NewReader(tt.body),
			)
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			r.ServeHTTP(rec, req)

			if called != tt.wantServiceCall {
				t.Errorf("service called = %v, want %v", called, tt.wantServiceCall)
			}

			var wantThreat *entity.Threat
			if tt.wantStatus == http.StatusOK {
				wantThreat = expected
			}

			assertJSONResponse(t, rec, tt.wantStatus, wantThreat)
		})
	}
}
