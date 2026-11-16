package scanning

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
)

type fakeCatalog struct {
	get    func(context.Context, string) (*Threat, error)
	create func(context.Context, Threat) (*Threat, error)
}

func (f fakeCatalog) Get(ctx context.Context, md5 string) (*Threat, error) { return f.get(ctx, md5) }
func (f fakeCatalog) Create(ctx context.Context, threat Threat) (*Threat, error) {
	return f.create(ctx, threat)
}

func TestCatalogPipeline(t *testing.T) {
	const md5 = "900150983cd24fb0d6963f7d28e17f72"
	existing := &Threat{MD5: md5, Name: "existing", Description: "curated", Severity: "high"}
	created := &Threat{MD5: md5, Name: "Test.Signature", Description: "Detected by ClamAV", Severity: "medium"}
	unexpected := errors.New("internal catalog failure")
	for _, tc := range []struct {
		name, verdict, status       string
		getErr, createErr, retryErr error
		want                        *Threat
		gets, creates               int
	}{
		{name: "clean missing", verdict: "clean", status: "not_found", getErr: ErrThreatNotFound, gets: 1},
		{name: "clean found", verdict: "clean", status: "found", want: existing, gets: 1},
		{name: "infected found", verdict: "infected", status: "found", want: existing, gets: 1},
		{name: "infected missing", verdict: "infected", status: "created", getErr: ErrThreatNotFound, want: created, gets: 1, creates: 1},
		{name: "create race", verdict: "infected", status: "found", getErr: ErrThreatNotFound, createErr: ErrThreatAlreadyExists, want: existing, gets: 2, creates: 1},
		{name: "infected unavailable", verdict: "infected", status: "unavailable", getErr: ErrCatalogUnavailable, gets: 1},
		{name: "RPC deadline", verdict: "clean", status: "unavailable", getErr: errors.Join(ErrCatalogUnavailable, context.DeadlineExceeded), gets: 1},
		{name: "get unavailable", verdict: "clean", status: "unavailable", getErr: ErrCatalogUnavailable, gets: 1},
		{name: "create unavailable", verdict: "infected", status: "unavailable", getErr: ErrThreatNotFound, createErr: ErrCatalogUnavailable, gets: 1, creates: 1},
		{name: "unexpected get", verdict: "infected", status: "error", getErr: unexpected, gets: 1},
		{name: "unexpected create", verdict: "infected", status: "error", getErr: ErrThreatNotFound, createErr: unexpected, gets: 1, creates: 1},
		{name: "race retry unavailable", verdict: "infected", status: "unavailable", getErr: ErrThreatNotFound, createErr: ErrThreatAlreadyExists, retryErr: ErrCatalogUnavailable, gets: 2, creates: 1},
		{name: "race retry missing", verdict: "infected", status: "error", getErr: ErrThreatNotFound, createErr: ErrThreatAlreadyExists, retryErr: ErrThreatNotFound, gets: 2, creates: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets, creates := 0, 0
			catalog := fakeCatalog{
				get: func(_ context.Context, key string) (*Threat, error) {
					gets++
					if key != md5 {
						t.Errorf("Get MD5 = %q", key)
					}
					err := tc.getErr
					if gets > 1 {
						err = tc.retryErr
					}
					if err != nil {
						return nil, fmt.Errorf("get: %w", err)
					}
					return existing, nil
				},
				create: func(_ context.Context, got Threat) (*Threat, error) {
					creates++
					if got != *created {
						t.Errorf("Create = %+v; want %+v", got, *created)
					}
					if tc.createErr != nil {
						return nil, fmt.Errorf("create: %w", tc.createErr)
					}
					return created, nil
				},
			}
			engine := testEngine{scan: func(_ context.Context, r io.Reader) (clamav.Result, error) {
				_, err := io.Copy(io.Discard, r)
				return clamav.Result{Verdict: tc.verdict, Signature: "Test.Signature"}, err
			}}
			s := NewWithCatalog(engine, catalog, 10, 1)
			got, err := s.Scan(context.Background(), strings.NewReader("abc"))
			if err != nil {
				t.Fatal(err)
			}
			if got.CatalogStatus != tc.status || !reflect.DeepEqual(got.Threat, tc.want) || got.Verdict != tc.verdict || got.MD5 != md5 || got.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || got.Size != 3 {
				t.Fatalf("result = %+v; threat = %+v", got, got.Threat)
			}
			if (got.CatalogError != "") != (tc.status == "error" || tc.status == "unavailable") {
				t.Errorf("catalog error = %q", got.CatalogError)
			}
			if gets != tc.gets || creates != tc.creates {
				t.Errorf("Get/Create = %d/%d, want %d/%d", gets, creates, tc.gets, tc.creates)
			}
		})
	}
}

func TestCatalogCancellation(t *testing.T) {
	for _, stage := range []string{"get", "create", "retry"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			block := func(ctx context.Context) (*Threat, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }
			gets := 0
			catalog := fakeCatalog{
				get: func(ctx context.Context, _ string) (*Threat, error) {
					gets++
					if stage == "get" || gets == 2 {
						return block(ctx)
					}
					return nil, ErrThreatNotFound
				},
				create: func(ctx context.Context, _ Threat) (*Threat, error) {
					if stage == "create" {
						return block(ctx)
					}
					return nil, ErrThreatAlreadyExists
				},
			}
			engine := testEngine{scan: func(_ context.Context, r io.Reader) (clamav.Result, error) {
				_, err := io.Copy(io.Discard, r)
				return clamav.Result{Verdict: "infected", Signature: "test"}, err
			}}
			s := NewWithCatalog(engine, catalog, 10, 1)
			done := make(chan error, 1)
			go func() { _, err := s.Scan(ctx, strings.NewReader("abc")); done <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("catalog not entered")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not finish")
			}
			if len(s.slots) != 0 {
				t.Fatal("slot leaked")
			}
		})
	}
}

func TestCatalogWaitDoesNotOccupyEngineSlot(t *testing.T) {
	entered := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	catalog := fakeCatalog{get: func(ctx context.Context, _ string) (*Threat, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	s := NewWithCatalog(consumingEngine(), catalog, 10, 1)
	done := make(chan error, 2)
	scan := func() { _, err := s.Scan(ctx, strings.NewReader("abc")); done <- err }
	go scan()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first scan blocked")
	}
	go scan()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("second scan rejected: %v", err)
	case <-time.After(time.Second):
		t.Fatal("catalog held engine slot")
	}
	cancel()
	for range 2 {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("scan did not stop")
		}
	}
}

func TestNoCatalogAndSlotRelease(t *testing.T) {
	s := New(consumingEngine(), 3, 1)
	readErr := errors.New("upload read failed")
	for _, tc := range []struct {
		reader io.Reader
		want   error
	}{
		{iotest.ErrReader(readErr), readErr}, {strings.NewReader(""), ErrEmpty}, {strings.NewReader("abcd"), ErrTooLarge}, {strings.NewReader("abc"), nil},
	} {
		got, err := s.Scan(context.Background(), tc.reader)
		if !errors.Is(err, tc.want) {
			t.Fatalf("got %v, want %v", err, tc.want)
		}
		if len(s.slots) != 0 {
			t.Fatal("slot leaked")
		}
		if got.CatalogStatus != "" || got.Threat != nil || got.CatalogError != "" {
			t.Fatalf("unexpected catalog: %+v", got)
		}
	}
}

func TestEngineFailureSkipsCatalogAndReleasesSlot(t *testing.T) {
	want := errors.New("clamd unavailable")
	catalog := fakeCatalog{get: func(context.Context, string) (*Threat, error) {
		t.Error("catalog called after engine error")
		return nil, nil
	}}
	s := NewWithCatalog(testEngine{scan: func(context.Context, io.Reader) (clamav.Result, error) { return clamav.Result{}, want }}, catalog, 10, 1)
	for range 2 {
		if _, err := s.Scan(context.Background(), strings.NewReader("abc")); !errors.Is(err, want) {
			t.Fatalf("got %v", err)
		}
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leaked")
	}
}
