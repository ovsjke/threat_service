package clamav

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestParseResponse(t *testing.T) {
	for _, tc := range []struct {
		response, verdict, signature string
		fail                         bool
	}{
		{"stream: OK", "clean", "", false},
		{"stream: Win.Test.EICAR_HDB-1 FOUND", "infected", "Win.Test.EICAR_HDB-1", false},
		{"stream: signature with spaces FOUND", "infected", "signature with spaces", false},
		{"stream: read ERROR", "", "", true}, {"INSTREAM size limit exceeded. ERROR", "", "", true},
		{"OK", "", "", true}, {"stream:  FOUND", "", "", true}, {"", "", "", true},
	} {
		t.Run(tc.response, func(t *testing.T) {
			r, err := parseResponse(tc.response)
			if (err != nil) != tc.fail || r.Verdict != tc.verdict || r.Signature != tc.signature {
				t.Fatalf("got %+v, %v", r, err)
			}
		})
	}
}
func fakeServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		serve(conn)
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String()
}
func TestINSTREAM(t *testing.T) {
	data := strings.Repeat("abc", 30000)
	address := fakeServer(t, func(conn net.Conn) {
		command := make([]byte, 10)
		if _, err := io.ReadFull(conn, command); err != nil || string(command) != "zINSTREAM\x00" {
			t.Errorf("command: %q, %v", command, err)
			return
		}
		var received bytes.Buffer
		for {
			var header [4]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				t.Error(err)
				return
			}
			n := binary.BigEndian.Uint32(header[:])
			if n == 0 {
				break
			}
			if n > 32*1024 {
				t.Errorf("oversized chunk %d", n)
				return
			}
			if _, err := io.CopyN(&received, conn, int64(n)); err != nil {
				t.Error(err)
				return
			}
		}
		if received.String() != data {
			t.Error("stream differs")
		}
		_, _ = io.WriteString(conn, "stream: OK\x00")
	})
	client := Client{Address: address, DialTimeout: time.Second, Timeout: time.Second}
	r, err := client.Scan(context.Background(), strings.NewReader(data))
	if err != nil || r.Verdict != "clean" {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestScanFailures(t *testing.T) {
	for _, tc := range []struct{ name, response string }{{"engine", "stream: failure ERROR\x00"}, {"truncated", "stream: OK"}, {"disconnect", ""}, {"oversized", strings.Repeat("x", 5000) + "\x00"}} {
		t.Run(tc.name, func(t *testing.T) {
			address := fakeServer(t, func(conn net.Conn) {
				// Consume the command and stream through the zero chunk.
				reader := bufio.NewReader(conn)
				_, _ = reader.ReadString(0)
				for {
					var p [4]byte
					if _, err := io.ReadFull(reader, p[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(p[:])
					if n == 0 {
						break
					}
					_, _ = io.CopyN(io.Discard, reader, int64(n))
				}
				_, _ = io.WriteString(conn, tc.response)
			})
			c := Client{Address: address, DialTimeout: time.Second, Timeout: time.Second}
			if _, err := c.Scan(context.Background(), strings.NewReader("abc")); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
func TestCancelAndTimeout(t *testing.T) {
	for _, cancelRequest := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel", false: "timeout"}[cancelRequest], func(t *testing.T) {
			connected := make(chan struct{})
			address := fakeServer(t, func(conn net.Conn) { close(connected); _, _ = io.Copy(io.Discard, conn) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := Client{Address: address, DialTimeout: time.Second, Timeout: 50 * time.Millisecond}
			done := make(chan error, 1)
			go func() { _, err := c.Scan(ctx, strings.NewReader("abc")); done <- err }()
			<-connected
			if cancelRequest {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected error")
				}
				if cancelRequest && !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
				if !cancelRequest {
					var e net.Error
					if !errors.As(err, &e) || !e.Timeout() {
						t.Fatalf("expected timeout: %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("scan did not stop")
			}
		})
	}
}
func TestPing(t *testing.T) {
	address := fakeServer(t, func(conn net.Conn) {
		p := make([]byte, 6)
		_, _ = io.ReadFull(conn, p)
		if string(p) != "zPING\x00" {
			t.Errorf("%q", p)
		}
		_, _ = io.WriteString(conn, "PONG\x00")
	})
	c := Client{Address: address, DialTimeout: time.Second, Timeout: time.Second}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUploadReadError(t *testing.T) {
	address := fakeServer(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
	c := Client{Address: address, DialTimeout: time.Second, Timeout: time.Second}
	want := errors.New("file read failed")
	_, err := c.Scan(context.Background(), iotest.ErrReader(want))
	var upload *UploadError
	if !errors.Is(err, want) || !errors.As(err, &upload) {
		t.Fatalf("expected UploadError wrapping read error: %v", err)
	}
}

func TestUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	c := Client{Address: address, DialTimeout: time.Second, Timeout: time.Second}
	if _, err := c.Scan(context.Background(), strings.NewReader("abc")); err == nil {
		t.Fatal("scan succeeded without clamd")
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("ping succeeded without clamd")
	}
}

func TestVersion(t *testing.T) {
	want := "ClamAV 1.4.6/28188/Thu Nov 19 2026"

	address := fakeServer(t, func(conn net.Conn) {
		command := make([]byte, len("zVERSION\x00"))

		if _, err := io.ReadFull(conn, command); err != nil {
			t.Errorf("read command: %v", err)
			return
		}

		if string(command) != "zVERSION\x00" {
			t.Errorf("unexpected command: %q", command)
			return
		}

		_, _ = io.WriteString(conn, want+"\x00")
	})

	client := Client{
		Address:     address,
		DialTimeout: time.Second,
		Timeout:     time.Second,
	}

	version, err := client.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if version != want {
		t.Fatalf("got %q, want %q", version, want)
	}
}

func TestVersionUnavailable(t *testing.T) {
	address := fakeServer(t, func(conn net.Conn) {
		command := make([]byte, len("zVERSION\x00"))
		_, _ = io.ReadFull(conn, command)

		_, _ = io.WriteString(
			conn,
			"COMMAND UNAVAILABLE\x00",
		)
	})

	client := Client{
		Address:     address,
		DialTimeout: time.Second,
		Timeout:     time.Second,
	}

	if _, err := client.Version(context.Background()); err == nil {
		t.Fatal("expected error for unavailable VERSION command")
	}
}
