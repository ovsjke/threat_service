package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestScannerProcess(t *testing.T) {
	if os.Getenv("SCANNER_TEST_PROCESS") == "1" {
		main()
		os.Exit(0)
	}
}

func TestShutdown(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "forced"}[force], func(t *testing.T) {
			engine, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			entered := make(chan struct{})
			release := make(chan struct{})
			engineDone := make(chan struct{})
			defer func() { engine.Close(); close(release); <-engineDone }()
			go func() {
				defer close(engineDone)
				conn, err := engine.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				command, err := r.ReadString(0)
				if err != nil || command != "zINSTREAM\x00" {
					return
				}
				for {
					var p [4]byte
					if _, err := io.ReadFull(r, p[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(p[:])
					if n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
						return
					}
				}
				close(entered)
				<-release
				_, _ = io.WriteString(conn, "stream: OK\x00")
			}()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := strings.Split(listener.Addr().String(), ":")[1]
			listener.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestScannerProcess$")
			grace := "2s"
			if force {
				grace = "100ms"
			}
			// Only the test harness launches a subprocess; production scanning never does.
			command.Env = append(os.Environ(), "SCANNER_TEST_PROCESS=1", "SCANNER_HTTP_PORT="+port, "CLAMAV_ADDRESS="+engine.Addr().String(), "SCANNER_SHUTDOWN_TIMEOUT="+grace, "SCANNER_SCAN_TIMEOUT=5s", "GORACE=atexit_sleep_ms=0")
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			processDone := make(chan error, 1)
			go func() { processDone <- command.Wait() }()
			defer func() { _ = command.Process.Kill() }()
			base := "http://127.0.0.1:" + port
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			defer client.CloseIdleConnections()
			ready := false
			for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
				response, err := client.Get(base + "/health")
				if err == nil {
					response.Body.Close()
					ready = response.StatusCode == 200
					if ready {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("scanner did not start")
			}
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, _ := mw.CreateFormFile("file", "a")
			_, _ = io.WriteString(part, "abc")
			_ = mw.Close()
			requestDone := make(chan int, 1)
			go func() {
				response, err := client.Post(base+"/scans", mw.FormDataContentType(), &body)
				if err != nil {
					requestDone <- 0
					return
				}
				defer response.Body.Close()
				_, _ = io.Copy(io.Discard, response.Body)
				requestDone <- response.StatusCode
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("scan did not reach clamd")
			}
			if err := command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			if !force {
				// Wait for the listener to close, then finish the request during shutdown.
				stopped := false
				for until := time.Now().Add(time.Second); time.Now().Before(until); {
					response, err := client.Get(base + "/health")
					if err != nil {
						stopped = true
						break
					}
					response.Body.Close()
					time.Sleep(10 * time.Millisecond)
				}
				if !stopped {
					t.Fatal("listener stayed open")
				}
				// Send a value instead of closing: the deferred close remains safe.
				release <- struct{}{}
				if status := <-requestDone; status != 200 {
					t.Fatalf("active scan lost: %d", status)
				}
			}
			select {
			case err := <-processDone:
				if (err != nil) != force {
					t.Fatalf("process: %v\n%s", err, output.String())
				}
				if force && !strings.Contains(output.String(), "HTTP shutdown") {
					t.Fatalf("wrong failure: %s", output.String())
				}
			case <-time.After(4 * time.Second):
				t.Fatal("shutdown did not finish")
			}
			if force {
				<-requestDone
			}
		})
	}
}
