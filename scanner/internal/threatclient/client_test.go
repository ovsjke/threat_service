package threatclient

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	threatv1 "github.com/ovsjke/threat_service/contracts/gen/go/threat/v1"
	"github.com/ovsjke/threat_service/scanner/internal/scanning"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type rpcServer struct {
	threatv1.UnimplementedThreatServiceServer
	get    func(context.Context, *threatv1.GetThreatRequest) (*threatv1.Threat, error)
	create func(context.Context, *threatv1.CreateThreatRequest) (*threatv1.Threat, error)
}

func (s rpcServer) GetThreat(ctx context.Context, r *threatv1.GetThreatRequest) (*threatv1.Threat, error) {
	return s.get(ctx, r)
}
func (s rpcServer) CreateThreat(ctx context.Context, r *threatv1.CreateThreatRequest) (*threatv1.Threat, error) {
	return s.create(ctx, r)
}
func newTestClient(t *testing.T, s rpcServer) (*Client, *atomic.Int32) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	threatv1.RegisterThreatServiceServer(server, s)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); listener.Close() })
	dials := new(atomic.Int32)
	conn, err := grpc.NewClient("passthrough:///catalog", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { dials.Add(1); return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Client{conn: conn, client: threatv1.NewThreatServiceClient(conn)}, dials
}
func TestRPCMappingAndConnectionReuse(t *testing.T) {
	want := scanning.Threat{MD5: "900150983cd24fb0d6963f7d28e17f72", Name: "test", Description: "description", Severity: "high"}
	proto := &threatv1.Threat{Md5: want.MD5, Name: want.Name, Description: want.Description, Severity: want.Severity}
	gets, creates := 0, 0
	checkDeadline := func(ctx context.Context) {
		t.Helper()
		d, ok := ctx.Deadline()
		if !ok || time.Until(d) > 3*time.Second || time.Until(d) <= 0 {
			t.Error("missing bounded RPC deadline")
		}
	}
	c, dials := newTestClient(t, rpcServer{
		get: func(ctx context.Context, r *threatv1.GetThreatRequest) (*threatv1.Threat, error) {
			gets++
			checkDeadline(ctx)
			if r.GetMd5() != want.MD5 {
				t.Errorf("Get: %v", r)
			}
			return proto, nil
		},
		create: func(ctx context.Context, r *threatv1.CreateThreatRequest) (*threatv1.Threat, error) {
			creates++
			checkDeadline(ctx)
			if r.GetMd5() != want.MD5 || r.GetName() != want.Name || r.GetDescription() != want.Description || r.GetSeverity() != want.Severity {
				t.Errorf("Create: %v", r)
			}
			return proto, nil
		},
	})
	for range 2 {
		got, err := c.Get(context.Background(), want.MD5)
		if err != nil || !reflect.DeepEqual(got, &want) {
			t.Fatalf("Get: %+v %v", got, err)
		}
		got, err = c.Create(context.Background(), want)
		if err != nil || !reflect.DeepEqual(got, &want) {
			t.Fatalf("Create: %+v %v", got, err)
		}
	}
	if gets != 2 || creates != 2 || dials.Load() != 1 {
		t.Fatalf("get/create/dials: %d/%d/%d", gets, creates, dials.Load())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.conn.GetState() != connectivity.Shutdown {
		t.Fatal("connection not closed")
	}
	if toDomain(nil) != nil {
		t.Fatal("nil mapping")
	}
}
func TestRPCErrors(t *testing.T) {
	for _, tc := range []struct {
		code codes.Code
		want error
	}{
		{codes.NotFound, scanning.ErrThreatNotFound}, {codes.AlreadyExists, scanning.ErrThreatAlreadyExists},
		{codes.Unavailable, scanning.ErrCatalogUnavailable}, {codes.DeadlineExceeded, context.DeadlineExceeded},
		{codes.Canceled, context.Canceled}, {codes.Internal, nil},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			c, _ := newTestClient(t, rpcServer{
				get: func(context.Context, *threatv1.GetThreatRequest) (*threatv1.Threat, error) {
					return nil, status.Error(tc.code, "test failure")
				},
				create: func(context.Context, *threatv1.CreateThreatRequest) (*threatv1.Threat, error) {
					return nil, status.Error(tc.code, "test failure")
				},
			})
			for _, call := range []func() (*scanning.Threat, error){func() (*scanning.Threat, error) { return c.Get(context.Background(), "md5") }, func() (*scanning.Threat, error) { return c.Create(context.Background(), scanning.Threat{}) }} {
				got, err := call()
				if got != nil || err == nil || status.Code(err) != tc.code {
					t.Fatalf("got %+v %v", got, err)
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("missing %v: %v", tc.want, err)
				}
				if tc.code == codes.DeadlineExceeded && !errors.Is(err, scanning.ErrCatalogUnavailable) {
					t.Fatal("RPC timeout not classified unavailable")
				}
				if tc.code != codes.NotFound && errors.Is(err, scanning.ErrThreatNotFound) {
					t.Fatal("error masked as NotFound")
				}
			}
		})
	}
}
func TestRPCParentContext(t *testing.T) {
	for _, method := range []string{"get", "create"} {
		for _, mode := range []string{"cancel", "deadline"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				entered := make(chan struct{})
				block := func(ctx context.Context) (*threatv1.Threat, error) {
					close(entered)
					<-ctx.Done()
					return nil, status.FromContextError(ctx.Err()).Err()
				}
				c, _ := newTestClient(t, rpcServer{
					get: func(ctx context.Context, _ *threatv1.GetThreatRequest) (*threatv1.Threat, error) { return block(ctx) },
					create: func(ctx context.Context, _ *threatv1.CreateThreatRequest) (*threatv1.Threat, error) {
						return block(ctx)
					},
				})
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					var err error
					if method == "get" {
						_, err = c.Get(ctx, "md5")
					} else {
						_, err = c.Create(ctx, scanning.Threat{})
					}
					done <- err
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("RPC did not start")
				}
				want := context.DeadlineExceeded
				if mode == "cancel" {
					cancel()
					want = context.Canceled
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
				case <-time.After(time.Second):
					t.Fatal("RPC did not stop")
				}
			})
		}
	}
}
