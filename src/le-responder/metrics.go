package main

import "github.com/prometheus/client_golang/prometheus"

var (
	metricErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "le_responder_errors_total",
	}, []string{"task"})
)

func init() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(metricErrors)
}
