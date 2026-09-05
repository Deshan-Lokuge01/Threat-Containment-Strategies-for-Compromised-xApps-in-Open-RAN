"""
ZT-XGuard Mathematical Resource-Behaviour Detector
src/ztx_model/__init__.py

Package version and public API surface for Step 36.
"""

__version__ = "0.1.0"
__step__ = 77
__project__ = "ZT-XGuard"
__target_venue__ = "IEEE CCNC"

# Immutability sentinel — any module that touches N1/N2/N3 must import this
DATASET_ROLES = {
    "N1": "normal-model-fitting-run-1",
    "N2": "normal-model-fitting-run-2",
    "N3": "clean-detector-calibration-only",
    "N4": "untouched-final-evaluation",
}

FITTING_RUNS = frozenset({"N1", "N2"})
CALIBRATION_RUNS = frozenset({"N3"})
UNTOUCHED_RUNS = frozenset({"N4"})

PUBLIC_STATES = frozenset({"NORMAL", "SUSPICIOUS", "COMPROMISED"})
# OBSERVED is explicitly banned — never add it

PRIMARY_METRIC_COLUMNS = (
    "m1_cpu_millicores",
    "m2_cpu_throttle_ratio",
    "m3_memory_working_set_bytes",
    "m4_memory_growth_bytes_per_s",
    "m5_network_rx_bytes_per_s",
    "m6_network_tx_bytes_per_s",
    "m7_filesystem_read_bytes_per_s",
    "m8_filesystem_write_bytes_per_s",
    "m9_socket_count",
    "m10_fd_count",
    "m11_thread_count",
)

EXPECTED_RAW_ROWS = 1800
EXPECTED_ELIGIBLE_ROWS = 1772
EXPECTED_WARMUP_ROWS = 28
EXPECTED_COLUMNS = 63
