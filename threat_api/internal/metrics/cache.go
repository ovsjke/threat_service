package metrics

import "github.com/prometheus/client_golang/prometheus"

var ThreatCacheLookups = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "threat_cache_lookups_total",
		Help: "Redis cache lookups by result",
	},
	[]string{"result"},
)

var ThreatCacheSetErrors = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "threat_cache_set_errors_total",
		Help: "Failed Redis SET operations",
	},
)

var ThreatCacheInvalidationErrors = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "threat_cache_invalidation_errors_total",
		Help: "Failed Redis cache invalidations",
	},
)

func init() {
	prometheus.MustRegister(
		ThreatCacheLookups,
		ThreatCacheSetErrors,
		ThreatCacheInvalidationErrors,
	)
}
