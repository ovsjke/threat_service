package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

var requestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "threat_http_requests_total",
		Help: "Total number of HTTP requests",
	},
	[]string{"method", "route", "status"},
)

var requestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name: "threat_http_request_duration_seconds",
		Help: "HTTP request duration in seconds",
		Buckets: []float64{
			0.001, 0.005, 0.01, 0.025,
			0.05, 0.1, 0.25, 0.5, 1, 2, 5,
		},
	},
	[]string{"method", "route"},
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration)
}

func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		requestsTotal.WithLabelValues(
			r.Method,
			route,
			strconv.Itoa(status),
		).Inc()

		requestDuration.WithLabelValues(
			r.Method,
			route,
		).Observe(time.Since(start).Seconds())
	})
}