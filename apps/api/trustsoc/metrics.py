from prometheus_client import Counter, Gauge, Histogram

TELEMETRY_EVENTS = Counter(
    "trustsoc_telemetry_events_total", "Telemetry events received", ["event_type", "outcome"]
)
TELEMETRY_LATENCY = Histogram("trustsoc_telemetry_latency_seconds", "Telemetry delivery latency")
SOURCE_TRUST_SCORE = Gauge(
    "trustsoc_source_trust_score", "Current telemetry trust score", ["source_id", "source_type"]
)
SIMULATION_RUNS = Counter(
    "trustsoc_simulation_runs_total", "Simulation runs", ["simulation_type", "status"]
)
