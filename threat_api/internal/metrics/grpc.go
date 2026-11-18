package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var grpcRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "threat_grpc_requests_total",
		Help: "Total number of gRPC requests",
	},
	[]string{"method", "code"},
)

var grpcRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "threat_grpc_request_duration_seconds",
		Help: "Duration of gRPC requests in seconds",
		Buckets: []float64{
			0.001, 0.005, 0.01, 0.025,
			0.05, 0.1, 0.25, 0.5, 1, 2, 5,
		},
	},
	[]string{"method"},
)

func init() {
	prometheus.MustRegister(
		grpcRequestsTotal,
		grpcRequestDuration,
	)
}

func UnaryServerInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()

	resp, err := handler(ctx, req)

	grpcRequestsTotal.WithLabelValues(
		info.FullMethod,
		status.Code(err).String(),
	).Inc()

	grpcRequestDuration.WithLabelValues(
		info.FullMethod,
	).Observe(time.Since(start).Seconds())

	return resp, err
}