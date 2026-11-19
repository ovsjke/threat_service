// Package clamav implements the small subset of clamd needed by the scanner.
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Result struct{ Verdict, Signature string }

type Client struct {
	Address     string
	DialTimeout time.Duration
	Timeout     time.Duration
}

// UploadError distinguishes a failed source read from a failed engine connection.
type UploadError struct{ Err error }

func (e *UploadError) Error() string { return "read upload: " + e.Err.Error() }
func (e *UploadError) Unwrap() error { return e.Err }

func (c *Client) connect(ctx context.Context) (net.Conn, func(), error) {
	conn, err := (&net.Dialer{Timeout: c.DialTimeout}).DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, func() { stop(); _ = conn.Close() }, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// Scan sends zINSTREAM and bounded chunks, followed by a zero-length chunk.
// The caller must arrange cancellation of a blocked source read (HTTP body).
func (c *Client) Scan(ctx context.Context, source io.Reader) (result Result, err error) {
	conn, closeConn, err := c.connect(ctx)
	if err != nil {
		return result, err
	}
	defer closeConn()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err = writeAll(conn, []byte("zINSTREAM\x00")); err != nil {
		return result, err
	}
	buf := make([]byte, 32*1024)
	var header [4]byte
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := source.Read(buf)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return result, &UploadError{readErr}
		}
		if n > 0 {
			binary.BigEndian.PutUint32(header[:], uint32(n))
			if err = writeAll(conn, header[:]); err != nil {
				return result, err
			}
			if err = writeAll(conn, buf[:n]); err != nil {
				return result, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if err = writeAll(conn, []byte{0, 0, 0, 0}); err != nil {
		return result, err
	}
	response, err := readResponse(conn)
	if err != nil {
		return result, err
	}
	return parseResponse(response)
}

func readResponse(r io.Reader) (string, error) {
	// ReadSlice bounds untrusted engine responses and requires a complete record.
	p, err := bufio.NewReaderSize(r, 4096).ReadSlice(0)
	if err != nil {
		return "", fmt.Errorf("read clamd response: %w", err)
	}
	return string(p[:len(p)-1]), nil
}

func parseResponse(response string) (Result, error) {
	if response == "stream: OK" {
		return Result{Verdict: "clean"}, nil
	}
	if signature, ok := strings.CutPrefix(response, "stream: "); ok && strings.HasSuffix(signature, " FOUND") {
		signature = strings.TrimSuffix(signature, " FOUND")
		if signature != "" {
			return Result{Verdict: "infected", Signature: signature}, nil
		}
	}
	return Result{}, fmt.Errorf("clamd rejected scan: %q", response)
}

func (c *Client) Ping(ctx context.Context) (err error) {
	conn, closeConn, err := c.connect(ctx)
	if err != nil {
		return err
	}
	defer closeConn()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err = writeAll(conn, []byte("zPING\x00")); err != nil {
		return err
	}
	response, err := readResponse(conn)
	if err != nil {
		return err
	}
	if response != "PONG" {
		return fmt.Errorf("unexpected clamd ping response: %q", response)
	}
	return nil
}

func (c *Client) Version(ctx context.Context) (version string, err error) {
	conn, closeConn, err := c.connect(ctx)
	if err != nil {
		return "", fmt.Errorf("connect to clamd: %w", err)
	}
	defer closeConn()

	if err := writeAll(conn, []byte("zVERSION\x00")); err != nil {
		return "", fmt.Errorf("send clamd VERSION: %w", err)
	}

	response, err := readResponse(conn)
	if err != nil {
		return "", fmt.Errorf("read clamd VERSION: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	response = strings.TrimSpace(response)

	if !strings.HasPrefix(response, "ClamAV ") {
		return "", fmt.Errorf(
			"unexpected clamd VERSION response: %q",
			response,
		)
	}

	return response, nil
}
