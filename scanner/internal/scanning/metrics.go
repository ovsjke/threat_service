package scanning

import "github.com/prometheus/client_golang/prometheus"

var cacheLookups = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "scanner_cache_lookups_total",
		Help: "Scanner Redis cache lookups by result.",
	},
	[]string{"result"},
)

var cacheSetErrors = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "scanner_cache_set_errors_total",
		Help: "Failed scanner cache writes.",
	},
)

var clamavScans = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "scanner_clamav_scans_total",
		Help: "Actual ClamAV scan calls by result.",
	},
	[]string{"result"},
)

var clamavDuration = prometheus.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "scanner_clamav_duration_seconds",
		Help:    "Duration of actual ClamAV scan calls.",
		Buckets: prometheus.DefBuckets,
	},
)

func init() {
	prometheus.MustRegister(
		cacheLookups,
		cacheSetErrors,
		clamavScans,
		clamavDuration,
	)
}
