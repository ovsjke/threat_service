package scanning

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/ovsjke/threat_service/scanner/internal/clamav"
	"io"
	"time"
)

var (
	ErrTooLarge            = errors.New("file exceeds size limit")
	ErrEmpty               = errors.New("file is empty")
	ErrBusy                = errors.New("all scan slots are occupied")
	ErrThreatNotFound      = errors.New("threat not found")
	ErrThreatAlreadyExists = errors.New("threat already exists")
	ErrCatalogUnavailable  = errors.New("catalog unavailable")
)

type Engine interface {
	Scan(context.Context, io.Reader) (clamav.Result, error)
	Ping(context.Context) error
}
type Threat struct {
	MD5         string `json:"md5"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ThreatCatalog interface {
	Get(ctx context.Context, md5 string) (*Threat, error)
	Create(ctx context.Context, threat Threat) (*Threat, error)
}
type Result struct {
	MD5        string `json:"md5"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Verdict    string `json:"verdict"`
	Signature  string `json:"signature"`
	DurationMS int64  `json:"duration_ms"`

	Threat        *Threat `json:"threat,omitempty"`
	CatalogStatus string  `json:"catalog_status"`
	CatalogError  string  `json:"catalog_error,omitempty"`
}
type Service struct {
	engine   Engine
	catalog  ThreatCatalog
	maxBytes int64
	slots    chan struct{}
}

func New(engine Engine, maxBytes int64, concurrency int) *Service {
	return NewWithCatalog(engine, nil, maxBytes, concurrency)
}

func NewWithCatalog(engine Engine, catalog ThreatCatalog, maxBytes int64, concurrency int) *Service {
	return &Service{engine: engine, catalog: catalog, maxBytes: maxBytes, slots: make(chan struct{}, concurrency)}
}
func (s *Service) Ready(ctx context.Context) error { return s.engine.Ping(ctx) }

// sizeReader probes one byte beyond the limit; that byte is never sent to clamd.
type sizeReader struct {
	source    io.Reader
	max, size int64
}

func (r *sizeReader) Read(p []byte) (int, error) {
	remaining := r.max - r.size
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, err := r.source.Read(p)
	r.size += int64(n)
	if r.size > r.max {
		return 0, ErrTooLarge
	}
	return n, err
}

func (s *Service) Scan(ctx context.Context, source io.Reader) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// Fail fast: no queue and no unbounded wait while uploads retain resources.
	select {
	case s.slots <- struct{}{}:
	default:
		return Result{}, ErrBusy
	}
	start := time.Now()
	limited := &sizeReader{source: source, max: s.maxBytes}
	md5Hash, shaHash := md5.New(), sha256.New()
	result, err := func() (clamav.Result, error) {
		defer func() { <-s.slots }()
		return s.engine.Scan(ctx, io.TeeReader(limited, io.MultiWriter(md5Hash, shaHash)))
	}()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil {
		return Result{}, err
	}
	if limited.size == 0 {
		return Result{}, ErrEmpty
	}
	if result.Verdict != "clean" && result.Verdict != "infected" {
		return Result{}, errors.New("invalid engine verdict")
	}
	out := Result{MD5: hex.EncodeToString(md5Hash.Sum(nil)), SHA256: hex.EncodeToString(shaHash.Sum(nil)), Size: limited.size, Verdict: result.Verdict, Signature: result.Signature, DurationMS: time.Since(start).Milliseconds()}
	if s.catalog == nil {
		return out, nil
	}
	threat, err := s.catalog.Get(ctx, out.MD5)
	out.CatalogStatus = "found"
	if errors.Is(err, ErrThreatNotFound) {
		out.CatalogStatus = "not_found"
		if out.Verdict == "infected" {
			// ClamAV gives a signature, not a severity rating. Use a conservative
			// default until a curator enriches the automatically created entry.
			threat, err = s.catalog.Create(ctx, Threat{MD5: out.MD5, Name: out.Signature,
				Description: "Detected by ClamAV", Severity: "medium"})
			out.CatalogStatus = "created"
			if errors.Is(err, ErrThreatAlreadyExists) {
				threat, err = s.catalog.Get(ctx, out.MD5)
				out.CatalogStatus = "found"
			}
		} else {
			err = nil
		}
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if err != nil {
		out.CatalogStatus = "error"
		if errors.Is(err, ErrCatalogUnavailable) {
			out.CatalogStatus = "unavailable"
		}
		out.CatalogError = err.Error()
	} else {
		out.Threat = threat
	}
	out.DurationMS = time.Since(start).Milliseconds()
	return out, nil
}
