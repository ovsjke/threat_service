package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"github.com/ovsjke/threat_service/scanner/internal/scanning"
)

const MultipartOverhead int64 = 64 << 10

type Handler struct {
	Service      *scanning.Service
	MaxFileBytes int64
	Timeout      time.Duration
	Log          *slog.Logger
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]string{"status": "ok"})
			return
		}
		w.Header().Set("Allow", "GET")
	case "/ready":
		if r.Method == http.MethodGet {
			ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
			defer cancel()
			if err := h.Service.Ready(ctx); err != nil {
				writeError(w, 503, "engine_unavailable", "ClamAV is not ready")
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ready"})
			return
		}
		w.Header().Set("Allow", "GET")
	case "/scans":
		if r.Method == http.MethodPost {
			h.scan(w, r)
			return
		}
		w.Header().Set("Allow", "POST")
	default:
		writeError(w, 404, "not_found", "Endpoint does not exist")
		return
	}
	writeError(w, 405, "method_not_allowed", "Method is not allowed")
}
func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
	defer cancel()
	// A context alone cannot interrupt a blocked network body read.
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	r.Body = http.MaxBytesReader(w, r.Body, h.MaxFileBytes+MultipartOverhead)
	body := r.Body
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(interrupted); _ = controller.SetReadDeadline(time.Now()); _ = body.Close() })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	if r.ContentLength > h.MaxFileBytes+MultipartOverhead {
		h.failure(w, ctx, scanning.ErrTooLarge)
		return
	}
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, 400, "invalid_multipart", "Expected multipart/form-data with field file")
		return
	}
	part, err := reader.NextPart()
	if errors.Is(err, io.EOF) {
		writeError(w, 400, "missing_file", "Field file is required")
		return
	}
	if err != nil {
		h.failure(w, ctx, &clamav.UploadError{Err: err})
		return
	}
	if part.FormName() != "file" {
		writeError(w, 400, "missing_file", "Expected a single field named file")
		return
	}
	result, err := h.Service.Scan(ctx, part)
	if err != nil {
		h.failure(w, ctx, err)
		return
	}
	// Validate the closing multipart boundary and reject ambiguous extra parts.
	_, err = reader.NextPart()
	if err == nil {
		writeError(w, 400, "invalid_multipart", "Exactly one file part is allowed")
		return
	}
	if !errors.Is(err, io.EOF) {
		h.failure(w, ctx, &clamav.UploadError{Err: err})
		return
	}
	// Enforce the full-body limit even when an epilogue follows the final boundary.
	if _, err = io.Copy(io.Discard, r.Body); err != nil {
		h.failure(w, ctx, &clamav.UploadError{Err: err})
		return
	}
	if ctx.Err() != nil {
		h.failure(w, ctx, ctx.Err())
		return
	}
	h.Log.Info("scan completed", "size", result.Size, "verdict", result.Verdict, "duration_ms", result.DurationMS)
	writeJSON(w, 200, result)
}
func (h *Handler) failure(w http.ResponseWriter, ctx context.Context, err error) {
	var bodyLimit *http.MaxBytesError
	var upload *clamav.UploadError
	var network net.Error
	// A socket read deadline may cancel the parent request just before the
	// context timer fires. Preserve timeout classification in either order.
	deadline, hasDeadline := ctx.Deadline()
	expired := hasDeadline && !time.Now().Before(deadline)
	switch {
	case expired, errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		writeError(w, 504, "scan_timeout", "Scan deadline exceeded")
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		writeError(w, 408, "request_canceled", "Request was canceled")
	case errors.Is(err, scanning.ErrTooLarge), errors.As(err, &bodyLimit):
		writeError(w, 413, "file_too_large", "File or request body exceeds size limit")
	case errors.Is(err, scanning.ErrEmpty):
		writeError(w, 400, "empty_file", "File must not be empty")
	case errors.Is(err, scanning.ErrBusy):
		w.Header().Set("Retry-After", "1")
		writeError(w, 503, "scanner_busy", "All scan slots are occupied; retry later")
	case errors.As(err, &network) && network.Timeout():
		writeError(w, 504, "scan_timeout", "Upload or engine timed out")
	case errors.As(err, &upload):
		writeError(w, 400, "invalid_upload", "Upload is incomplete or malformed")
	default:
		h.Log.Error("scan failed", "error", err)
		writeError(w, 502, "engine_error", "ClamAV did not complete the scan")
	}
}
