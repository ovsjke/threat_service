package scanning

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ovsjke/threat_service/scanner/internal/clamav"
)

type testEngine struct {
	scan func(context.Context, io.Reader) (clamav.Result, error)
}

func (e testEngine) Scan(ctx context.Context, r io.Reader) (clamav.Result, error) {
	return e.scan(ctx, r)
}
func (e testEngine) Ping(context.Context) error { return nil }
func consumingEngine() testEngine {
	return testEngine{scan: func(_ context.Context, r io.Reader) (clamav.Result, error) {
		_, err := io.Copy(io.Discard, r)
		return clamav.Result{Verdict: "clean"}, err
	}}
}
func TestHashesAndSize(t *testing.T) {
	s := New(consumingEngine(), 3, 1)
	r, err := s.Scan(context.Background(), strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if r.MD5 != "900150983cd24fb0d6963f7d28e17f72" || r.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || r.Size != 3 || r.Verdict != "clean" {
		t.Fatalf("%+v", r)
	}
	for _, tc := range []struct {
		data string
		want error
	}{{"", ErrEmpty}, {"abcd", ErrTooLarge}} {
		_, err := s.Scan(context.Background(), strings.NewReader(tc.data))
		if !errors.Is(err, tc.want) {
			t.Fatalf("%q: %v", tc.data, err)
		}
	}
}
func TestConcurrencyAndCancellation(t *testing.T) {
	entered := make(chan struct{})
	released := make(chan struct{})
	engine := testEngine{scan: func(ctx context.Context, _ io.Reader) (clamav.Result, error) {
		close(entered)
		<-ctx.Done()
		return clamav.Result{}, ctx.Err()
	}}
	s := New(engine, 100, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(released)
		_, err := s.Scan(ctx, strings.NewReader("abc"))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%v", err)
		}
	}()
	<-entered
	if _, err := s.Scan(context.Background(), strings.NewReader("abc")); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy: %v", err)
	}
	cancel()
	<-released
	if len(s.slots) != 0 {
		t.Fatal("slot leaked")
	}
	if _, err := s.Scan(ctx, strings.NewReader("abc")); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled: %v", err)
	}
}
func TestEngineError(t *testing.T) {
	want := errors.New("engine failed")
	s := New(testEngine{scan: func(context.Context, io.Reader) (clamav.Result, error) { return clamav.Result{}, want }}, 100, 1)
	if _, err := s.Scan(context.Background(), strings.NewReader("abc")); !errors.Is(err, want) {
		t.Fatalf("%v", err)
	}
}
