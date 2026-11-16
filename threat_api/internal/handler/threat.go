package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/ovsjke/threat_service/threat_api/internal/entity"
	"log/slog"
	"net/http"
)

type ThreatService interface {
	GetByMD5( ctx context.Context,md5 string,) (*entity.Threat, error)

	Update(ctx context.Context,threat *entity.Threat,) (*entity.Threat, error)

	Create(ctx context.Context,threat *entity.Threat,) (*entity.Threat, error)
}

func WriteJSONResponse(w http.ResponseWriter, statusCode int, data any, log *slog.Logger) {
	body, err := json.Marshal(data)
	if err != nil {
		log.Error("Failed to serialize HTTP response",
			"error", err,
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		_, _ = w.Write([]byte(
			`{"message":"Internal Server Error","details":"Failed to serialize response"}`,
		))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if _, err := w.Write(body); err != nil {
		log.Error("Failed to write HTTP response",
			"error", err,
		)
	}
}
func ErrorSwitch(w http.ResponseWriter, err error, md5 string, log *slog.Logger) {
	switch {
	case errors.Is(err, entity.ErrInvalidMD5):
		WriteError(w, http.StatusBadRequest, "Invalid MD5 format", md5+" is not a valid MD5 hash", log)
		return
	case errors.Is(err, entity.ErrThreatNotFound):
		WriteError(w, http.StatusNotFound, "Threat not found", "No threat found with MD5: "+md5, log)
		return
	case errors.Is(err, entity.ErrInvalidName):
		WriteError(w, http.StatusBadRequest, "Invalid name", "Name must not be empty or contain only whitespace", log)
		return
	case errors.Is(err, entity.ErrInvalidSeverity):
		WriteError(w, http.StatusBadRequest, "Invalid severity", "Severity must be one of: low, medium, high, critical", log)
		return
	case errors.Is(err, entity.ErrThreatAlreadyExists):
		WriteError(w, http.StatusConflict, "Threat already exists", "A threat with the same MD5 already exists", log)
		return
	case errors.Is(err, entity.ErrNameTooLong):
		WriteError(w, http.StatusBadRequest, "Name too long", "Name must not exceed 255 characters", log)
		return
	default:
		log.Error("request failed", "error", err)
		WriteError(w, http.StatusInternalServerError, "Internal server error", "Server error, please try again later", log)
		return
	}
}

func WriteError(w http.ResponseWriter, statusCode int, message string, details string, log *slog.Logger) {
	resp := &ErrorResponse{
		Message: message,
		Details: details,
	}
	WriteJSONResponse(w, statusCode, resp, log)
}

func PrepareResponse(threat *entity.Threat) *ThreatResponse {
	resp := &ThreatResponse{
		MD5:         threat.MD5,
		Name:        threat.Name,
		Description: threat.Description,
		Severity:    string(threat.Severity),
		DetectedAt:  threat.DetectedAt,
		UpdatedAt:   threat.UpdatedAt,
	}
	return resp
}

type ThreatHandler struct {
	service ThreatService
	log     *slog.Logger
}

func NewThreatHandler(service ThreatService, log *slog.Logger) *ThreatHandler {
	return &ThreatHandler{service: service, log: log}
}

func (h *ThreatHandler) RegisterRoutes(r chi.Router) {
	r.Get("/info/{md5}", h.GetInfoByMd5)
	r.Put("/info/{md5}", h.UpdateThreat)
	r.Post("/info", h.CreateThreat)
}

func (h *ThreatHandler) GetInfoByMd5(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	md5 := chi.URLParam(r, "md5")
	threat, err := h.service.GetByMD5(ctx, md5)
	if err != nil {
		ErrorSwitch(w, err, md5, h.log)
		return
	}
	resp := PrepareResponse(threat)
	WriteJSONResponse(w, http.StatusOK, resp, h.log)
}

func (h *ThreatHandler) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req ThreatUpdateRequest
	ctx := r.Context()
	md5 := chi.URLParam(r, "md5")
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body", err.Error(), h.log)
		return
	}
	threat, err := h.service.Update(ctx, &entity.Threat{
		MD5:         md5,
		Name:        req.Name,
		Description: req.Description,
		Severity:    entity.Severity(req.Severity),
	})
	if err != nil {
		ErrorSwitch(w, err, md5, h.log)
		return
	}

	resp := PrepareResponse(threat)

	WriteJSONResponse(w, http.StatusOK, resp, h.log)
}

func (h *ThreatHandler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	var req ThreatCreateRequest
	ctx := r.Context()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid JSON body", err.Error(), h.log)
		return
	}
	threat, err := h.service.Create(ctx, &entity.Threat{
		MD5:         req.MD5,
		Name:        req.Name,
		Description: req.Description,
		Severity:    entity.Severity(req.Severity),
	})
	if err != nil {
		ErrorSwitch(w, err, req.MD5, h.log)
		return
	}
	resp := PrepareResponse(threat)
	WriteJSONResponse(w, http.StatusCreated, resp, h.log)
}
