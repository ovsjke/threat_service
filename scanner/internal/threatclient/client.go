package threatclient

import (
	"context"
	"errors"
	"fmt"
	"github.com/ovsjke/threat_service/scanner/internal/scanning"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	threatv1 "github.com/ovsjke/threat_service/contracts/gen/go/threat/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn   *grpc.ClientConn
	client threatv1.ThreatServiceClient
}

func New(target string) (*Client, error) {
	conn, err := grpc.NewClient(
		target,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create grpc client: %w", err)
	}

	return &Client{
		conn:   conn,
		client: threatv1.NewThreatServiceClient(conn),
	}, nil
}

func (c *Client) GetThreat(
	ctx context.Context,
	md5 string,
) (*threatv1.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resp, err := c.client.GetThreat(
		ctx,
		&threatv1.GetThreatRequest{
			Md5: md5,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get threat: %w", err)
	}

	return resp, nil
}

func (c *Client) CreateThreat(
	ctx context.Context,
	req *threatv1.CreateThreatRequest,
) (*threatv1.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resp, err := c.client.CreateThreat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create threat: %w", err)
	}

	return resp, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

var _ scanning.ThreatCatalog = (*Client)(nil)

func (c *Client) Get(ctx context.Context, md5 string) (*scanning.Threat, error) {
	threat, err := c.GetThreat(ctx, md5)
	return toDomain(threat), catalogError(err)
}

func (c *Client) Create(ctx context.Context, threat scanning.Threat) (*scanning.Threat, error) {
	result, err := c.CreateThreat(ctx, &threatv1.CreateThreatRequest{
		Md5: threat.MD5, Name: threat.Name, Description: threat.Description, Severity: threat.Severity,
	})
	return toDomain(result), catalogError(err)
}

func toDomain(threat *threatv1.Threat) *scanning.Threat {
	if threat == nil {
		return nil
	}
	return &scanning.Threat{MD5: threat.GetMd5(), Name: threat.GetName(),
		Description: threat.GetDescription(), Severity: threat.GetSeverity()}
}

func catalogError(err error) error {
	if err == nil {
		return nil
	}
	var kind error
	switch status.Code(err) {
	case codes.NotFound:
		kind = scanning.ErrThreatNotFound
	case codes.AlreadyExists:
		kind = scanning.ErrThreatAlreadyExists
	case codes.Unavailable:
		kind = scanning.ErrCatalogUnavailable
	case codes.DeadlineExceeded:
		kind = errors.Join(scanning.ErrCatalogUnavailable, context.DeadlineExceeded)
	case codes.Canceled:
		kind = context.Canceled
	default:
		return err
	}
	return errors.Join(kind, err)
}
