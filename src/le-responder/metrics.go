package main

import "github.com/prometheus/client_golang/prometheus"

var (
	metricErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "le_responder_errors_total",
	}, []string{"task"})
	metricIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "le_responder_certificates_total",
	}, []string{"source"})
	metricHealth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "le_responder_health",
	}, []string{"task"})
)

func init() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(metricErrors)
	prometheus.MustRegister(metricIssued)
	prometheus.MustRegister(metricHealth)
}
