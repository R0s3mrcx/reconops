from prometheus_client import Counter, Histogram, Gauge

scans_total = Counter(
    "reconops_scans_total",
    "Total number of scans initiated",
    ["scan_type", "status"],
)

scan_duration_seconds = Histogram(
    "reconops_scan_duration_seconds",
    "Time taken to complete a scan",
    ["scan_type"],
    buckets=[5, 15, 30, 60, 120, 300],
)

findings_total = Counter(
    "reconops_findings_total",
    "Total findings discovered",
    ["category", "is_shadow"],
)

active_scans_gauge = Gauge(
    "reconops_active_scans",
    "Number of currently running scans",
)

shadow_services_total = Counter(
    "reconops_shadow_services_total",
    "Total shadow services detected across all scans",
)
