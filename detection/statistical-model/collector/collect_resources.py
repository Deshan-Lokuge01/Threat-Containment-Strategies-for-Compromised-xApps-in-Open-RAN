#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


def read_key_values(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()

        if len(parts) != 2:
            continue

        try:
            result[parts[0]] = int(parts[1])
        except ValueError:
            continue

    return result


def read_memory(cgroup: Path) -> tuple[int, int, int]:
    memory_current = int(
        (cgroup / "memory.current").read_text(
            encoding="utf-8"
        ).strip()
    )

    memory_stat = read_key_values(cgroup / "memory.stat")
    inactive_file = memory_stat.get("inactive_file", 0)

    working_set = max(
        memory_current - inactive_file,
        0,
    )

    return memory_current, inactive_file, working_set


def read_io_bytes(cgroup: Path) -> tuple[int, int]:
    read_bytes = 0
    write_bytes = 0

    for line in (cgroup / "io.stat").read_text(
        encoding="utf-8"
    ).splitlines():

        for item in line.split()[1:]:
            key, separator, value = item.partition("=")

            if not separator:
                continue

            try:
                parsed = int(value)
            except ValueError:
                continue

            if key == "rbytes":
                read_bytes += parsed
            elif key == "wbytes":
                write_bytes += parsed

    return read_bytes, write_bytes


def read_network_bytes(pid: int) -> tuple[int, int]:
    rx_bytes = 0
    tx_bytes = 0

    path = Path(f"/proc/{pid}/net/dev")

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():

        if ":" not in line:
            continue

        interface, values = line.split(":", 1)

        if interface.strip() == "lo":
            continue

        fields = values.split()

        if len(fields) >= 16:
            rx_bytes += int(fields[0])
            tx_bytes += int(fields[8])

    return rx_bytes, tx_bytes


def read_process_counts(
    cgroup: Path,
) -> tuple[int, int, int, int]:

    pids: list[int] = []

    for value in (cgroup / "cgroup.procs").read_text(
        encoding="utf-8"
    ).splitlines():

        try:
            pids.append(int(value))
        except ValueError:
            continue

    fd_count = 0
    socket_targets: set[str] = set()

    for pid in pids:
        fd_path = Path(f"/proc/{pid}/fd")

        try:
            entries = list(fd_path.iterdir())
        except (FileNotFoundError, PermissionError):
            continue

        fd_count += len(entries)

        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue

            if target.startswith("socket:["):
                socket_targets.add(target)

    try:
        thread_count = len(
            (cgroup / "cgroup.threads").read_text(
                encoding="utf-8"
            ).splitlines()
        )
    except FileNotFoundError:
        thread_count = 0

    return (
        len(pids),
        fd_count,
        len(socket_targets),
        thread_count,
    )


def read_limits(cgroup: Path) -> dict[str, object]:
    cpu_parts = (cgroup / "cpu.max").read_text(
        encoding="utf-8"
    ).split()

    memory_max = (cgroup / "memory.max").read_text(
        encoding="utf-8"
    ).strip()

    return {
        "cpu_limit_enabled": int(cpu_parts[0] != "max"),
        "cpu_quota_us": (
            ""
            if cpu_parts[0] == "max"
            else int(cpu_parts[0])
        ),
        "cpu_period_us": int(cpu_parts[1]),
        "memory_limit_enabled": int(memory_max != "max"),
        "memory_limit_bytes": (
            ""
            if memory_max == "max"
            else int(memory_max)
        ),
    }


def read_host_context() -> tuple[int, int]:
    values: dict[str, int] = {}

    for line in Path("/proc/meminfo").read_text(
        encoding="utf-8"
    ).splitlines():

        key, separator, remainder = line.partition(":")

        if not separator:
            continue

        try:
            values[key] = int(
                remainder.split()[0]
            ) * 1024
        except (ValueError, IndexError):
            continue

    available = values.get("MemAvailable", 0)

    swap_used = max(
        values.get("SwapTotal", 0)
        - values.get("SwapFree", 0),
        0,
    )

    return available, swap_used


def read_snapshot(
    pid: int,
    cgroup: Path,
) -> dict[str, object]:

    if not Path(f"/proc/{pid}").exists():
        raise RuntimeError(
            "Target container host PID disappeared."
        )

    if not cgroup.is_dir():
        raise RuntimeError(
            "Target container cgroup disappeared."
        )

    cpu_stat = read_key_values(cgroup / "cpu.stat")

    (
        memory_current,
        inactive_file,
        working_set,
    ) = read_memory(cgroup)

    network_rx, network_tx = read_network_bytes(pid)

    (
        process_count,
        fd_count,
        socket_count,
        thread_count,
    ) = read_process_counts(cgroup)

    filesystem_read, filesystem_write = read_io_bytes(
        cgroup
    )

    host_memory, host_swap = read_host_context()

    return {
        "monotonic": time.monotonic(),
        "unix_ns": time.time_ns(),

        "cpu_usage_usec": cpu_stat.get(
            "usage_usec",
            0,
        ),
        "cpu_nr_periods": cpu_stat.get(
            "nr_periods",
            0,
        ),
        "cpu_nr_throttled": cpu_stat.get(
            "nr_throttled",
            0,
        ),
        "cpu_throttled_usec": cpu_stat.get(
            "throttled_usec",
            0,
        ),

        "memory_current": memory_current,
        "memory_inactive_file": inactive_file,
        "memory_working_set": working_set,

        "network_rx": network_rx,
        "network_tx": network_tx,

        "filesystem_read": filesystem_read,
        "filesystem_write": filesystem_write,

        "process_count": process_count,
        "fd_count": fd_count,
        "socket_count": socket_count,
        "thread_count": thread_count,

        "host_mem_available": host_memory,
        "host_swap_used": host_swap,
    }


def calculate_rate(
    current: int,
    previous: int,
    seconds: float,
) -> tuple[float | None, bool]:

    if seconds <= 0:
        return None, False

    if current < previous:
        return None, True

    return (
        (current - previous) / seconds,
        False,
    )


def calculate_slope(
    points: deque[tuple[float, int]],
    required_span: float,
) -> float | None:

    if len(points) < 3:
        return None

    actual_span = points[-1][0] - points[0][0]

    if actual_span < required_span:
        return None

    x_mean = sum(
        x for x, _ in points
    ) / len(points)

    y_mean = sum(
        y for _, y in points
    ) / len(points)

    denominator = sum(
        (x - x_mean) ** 2
        for x, _ in points
    )

    if denominator <= 0:
        return None

    numerator = sum(
        (x - x_mean) * (y - y_mean)
        for x, y in points
    )

    return numerator / denominator


def create_http_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )


def fetch_runtime_metrics(
    opener: urllib.request.OpenerDirector,
    url: str,
    timeout: float = 0.5,
) -> tuple[dict[str, object] | None, str]:

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ZT-XGuard-Collector/2"
            },
        )

        with opener.open(
            request,
            timeout=timeout,
        ) as response:
            payload = response.read()

        decoded = json.loads(
            payload.decode("utf-8")
        )

        if not isinstance(decoded, dict):
            return None, "non_object_json"

        return decoded, ""

    except Exception as error:
        return (
            None,
            f"{type(error).__name__}:{error}",
        )


def read_json_counter(
    data: dict[str, object] | None,
    key: str,
) -> int | None:

    if data is None:
        return None

    try:
        return int(data[key])
    except (KeyError, TypeError, ValueError):
        return None


def event_age_seconds(
    event_timestamp_ns: int | None,
    current_timestamp_ns: int,
) -> float | None:

    if event_timestamp_ns is None:
        return None

    if event_timestamp_ns <= 0:
        return None

    return max(
        (
            current_timestamp_ns
            - event_timestamp_ns
        ) / 1_000_000_000,
        0.0,
    )


def format_float(
    value: float | None,
    digits: int = 6,
) -> str:

    if value is None:
        return ""

    if not math.isfinite(value):
        return ""

    return f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--pid",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--cgroup",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--profile",
        required=True,
    )
    parser.add_argument(
        "--run-id",
        required=True,
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=300.0,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
    )
    parser.add_argument(
        "--memory-slope-window",
        type=float,
        default=30.0,
    )
    parser.add_argument(
        "--metrics-url",
        required=True,
    )
    parser.add_argument(
        "--pod-name",
        default="",
    )
    parser.add_argument(
        "--pod-uid",
        default="",
    )
    parser.add_argument(
        "--container-id",
        default="",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    if args.duration <= 0:
        raise SystemExit(
            "Duration must be positive."
        )

    if args.interval <= 0:
        raise SystemExit(
            "Interval must be positive."
        )

    if args.memory_slope_window <= 0:
        raise SystemExit(
            "Memory slope window must be positive."
        )

    if not args.cgroup.is_dir():
        raise SystemExit(
            f"Cgroup does not exist: {args.cgroup}"
        )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    limits = read_limits(args.cgroup)
    opener = create_http_opener()

    fields = [
        "timestamp_utc",
        "timestamp_unix_ns",
        "sample_index",
        "elapsed_s",
        "sample_interval_s",
        "sample_lag_ms",
        "timing_ok",

        "run_id",
        "profile",
        "pod_name",
        "pod_uid",
        "container_id",
        "host_pid",
        "cgroup_path",

        "m1_cpu_millicores",
        "m2_cpu_throttle_ratio",
        "m3_memory_working_set_bytes",
        "m4_memory_growth_bytes_per_s",
        "m4_memory_slope_ready",
        "m5_network_rx_bytes_per_s",
        "m6_network_tx_bytes_per_s",
        "m7_filesystem_read_bytes_per_s",
        "m8_filesystem_write_bytes_per_s",
        "m9_socket_count",
        "m10_fd_count",
        "m11_thread_count",

        "cpu_usage_usec_total",
        "cpu_nr_periods_total",
        "cpu_nr_throttled_total",
        "cpu_throttled_usec_total",

        "memory_current_bytes",
        "memory_inactive_file_bytes",

        "network_rx_bytes_total",
        "network_tx_bytes_total",

        "filesystem_read_bytes_total",
        "filesystem_write_bytes_total",

        "process_count",

        "rmr_rx_total",
        "rmr_rx_per_s",
        "rmr_tx_total",
        "rmr_tx_per_s",

        "ric_indication_total",
        "ric_indication_per_s",

        "work_units_total",
        "work_units_per_s",

        "heartbeat_total",
        "heartbeat_per_s",
        "heartbeat_stall_age_s",

        "last_rmr_rx_age_s",
        "last_work_age_s",
        "rmr_tx_status",

        "metrics_endpoint_ok",
        "metrics_endpoint_error",

        "cpu_limit_enabled",
        "cpu_quota_us",
        "cpu_period_us",

        "memory_limit_enabled",
        "memory_limit_bytes",

        "host_mem_available_bytes",
        "host_swap_used_bytes",

        "resource_counter_reset",
        "runtime_counter_reset",
        "sample_quality",
    ]

    previous = read_snapshot(
        args.pid,
        args.cgroup,
    )

    previous_runtime, _ = fetch_runtime_metrics(
        opener,
        args.metrics_url,
    )

    previous_runtime_monotonic = (
        previous["monotonic"]
        if previous_runtime is not None
        else None
    )

    previous_heartbeat = read_json_counter(
        previous_runtime,
        "heartbeat_total",
    )

    last_heartbeat_change = (
        previous["monotonic"]
        if previous_heartbeat is not None
        else None
    )

    memory_history: deque[
        tuple[float, int]
    ] = deque()

    memory_history.append(
        (
            float(previous["monotonic"]),
            int(previous["memory_working_set"]),
        )
    )

    start_monotonic = float(
        previous["monotonic"]
    )

    sample_count = int(
        args.duration / args.interval
    )

    summary = {
        "schema": "ztx-kpimon-raw-v2",
        "target_rows": sample_count,
        "rows_written": 0,
        "timing_errors": 0,
        "endpoint_errors": 0,
        "resource_counter_resets": 0,
        "runtime_counter_resets": 0,
        "fatal_error": "",
    }

    with args.output.open(
        "w",
        newline="",
        encoding="utf-8",
        buffering=1,
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )

        writer.writeheader()

        for sample_index in range(
            1,
            sample_count + 1,
        ):
            deadline = (
                start_monotonic
                + sample_index * args.interval
            )

            remaining = (
                deadline - time.monotonic()
            )

            if remaining > 0:
                time.sleep(remaining)

            try:
                current = read_snapshot(
                    args.pid,
                    args.cgroup,
                )
            except Exception as error:
                summary["fatal_error"] = (
                    f"{type(error).__name__}:{error}"
                )
                break

            current_monotonic = float(
                current["monotonic"]
            )

            previous_monotonic = float(
                previous["monotonic"]
            )

            interval_seconds = (
                current_monotonic
                - previous_monotonic
            )

            sample_lag_ms = max(
                (
                    current_monotonic
                    - deadline
                ) * 1000,
                0.0,
            )

            timing_ok = int(
                0.5 * args.interval
                <= interval_seconds
                <= 1.5 * args.interval
                and sample_lag_ms
                <= 0.5 * args.interval * 1000
            )

            summary["timing_errors"] += (
                1 - timing_ok
            )

            cpu_rate, reset_cpu = calculate_rate(
                int(current["cpu_usage_usec"]),
                int(previous["cpu_usage_usec"]),
                interval_seconds,
            )

            period_rate, reset_period = (
                calculate_rate(
                    int(current["cpu_nr_periods"]),
                    int(previous["cpu_nr_periods"]),
                    interval_seconds,
                )
            )

            throttled_period_rate, reset_throttle = (
                calculate_rate(
                    int(
                        current[
                            "cpu_nr_throttled"
                        ]
                    ),
                    int(
                        previous[
                            "cpu_nr_throttled"
                        ]
                    ),
                    interval_seconds,
                )
            )

            network_rx_rate, reset_network_rx = (
                calculate_rate(
                    int(current["network_rx"]),
                    int(previous["network_rx"]),
                    interval_seconds,
                )
            )

            network_tx_rate, reset_network_tx = (
                calculate_rate(
                    int(current["network_tx"]),
                    int(previous["network_tx"]),
                    interval_seconds,
                )
            )

            filesystem_read_rate, reset_fs_read = (
                calculate_rate(
                    int(
                        current[
                            "filesystem_read"
                        ]
                    ),
                    int(
                        previous[
                            "filesystem_read"
                        ]
                    ),
                    interval_seconds,
                )
            )

            filesystem_write_rate, reset_fs_write = (
                calculate_rate(
                    int(
                        current[
                            "filesystem_write"
                        ]
                    ),
                    int(
                        previous[
                            "filesystem_write"
                        ]
                    ),
                    interval_seconds,
                )
            )

            resource_reset = int(
                any(
                    (
                        reset_cpu,
                        reset_period,
                        reset_throttle,
                        reset_network_rx,
                        reset_network_tx,
                        reset_fs_read,
                        reset_fs_write,
                    )
                )
            )

            summary[
                "resource_counter_resets"
            ] += resource_reset

            cpu_millicores = (
                None
                if cpu_rate is None
                else cpu_rate / 1000.0
            )

            if not limits["cpu_limit_enabled"]:
                throttle_ratio = 0.0
            elif (
                period_rate is None
                or throttled_period_rate is None
                or period_rate <= 0
            ):
                throttle_ratio = 0.0
            else:
                throttle_ratio = min(
                    max(
                        throttled_period_rate
                        / period_rate,
                        0.0,
                    ),
                    1.0,
                )

            memory_history.append(
                (
                    current_monotonic,
                    int(
                        current[
                            "memory_working_set"
                        ]
                    ),
                )
            )

            cutoff = (
                current_monotonic
                - args.memory_slope_window
            )

            while (
                len(memory_history) > 1
                and memory_history[0][0] < cutoff
            ):
                memory_history.popleft()

            memory_slope = calculate_slope(
                memory_history,
                max(
                    args.memory_slope_window
                    - 1.5 * args.interval,
                    args.interval,
                ),
            )

            runtime, runtime_error = (
                fetch_runtime_metrics(
                    opener,
                    args.metrics_url,
                )
            )

            if runtime_error:
                summary[
                    "endpoint_errors"
                ] += 1

            runtime_interval = None

            if (
                runtime is not None
                and previous_runtime_monotonic
                is not None
            ):
                runtime_interval = (
                    current_monotonic
                    - float(
                        previous_runtime_monotonic
                    )
                )

            runtime_rates: dict[
                str,
                float | None,
            ] = {}

            runtime_reset = False

            for key in (
                "rmr_rx_total",
                "rmr_tx_total",
                "ric_indication_total",
                "work_units_total",
                "heartbeat_total",
            ):
                current_value = read_json_counter(
                    runtime,
                    key,
                )

                previous_value = read_json_counter(
                    previous_runtime,
                    key,
                )

                if (
                    current_value is None
                    or previous_value is None
                    or runtime_interval is None
                ):
                    runtime_rates[key] = None
                    continue

                value_rate, value_reset = (
                    calculate_rate(
                        current_value,
                        previous_value,
                        runtime_interval,
                    )
                )

                runtime_rates[key] = value_rate
                runtime_reset = (
                    runtime_reset or value_reset
                )

            summary[
                "runtime_counter_resets"
            ] += int(runtime_reset)

            heartbeat_total = read_json_counter(
                runtime,
                "heartbeat_total",
            )

            if heartbeat_total is not None:
                if (
                    previous_heartbeat is None
                    or heartbeat_total
                    != previous_heartbeat
                ):
                    last_heartbeat_change = (
                        current_monotonic
                    )

                previous_heartbeat = (
                    heartbeat_total
                )

            heartbeat_stall_age = (
                None
                if last_heartbeat_change is None
                else current_monotonic
                - float(last_heartbeat_change)
            )

            last_rmr_rx_age = event_age_seconds(
                read_json_counter(
                    runtime,
                    "last_rmr_rx_unix_nano",
                ),
                int(current["unix_ns"]),
            )

            last_work_age = event_age_seconds(
                read_json_counter(
                    runtime,
                    "last_work_unix_nano",
                ),
                int(current["unix_ns"]),
            )

            quality_issues: list[str] = []

            if not timing_ok:
                quality_issues.append("timing")

            if resource_reset:
                quality_issues.append(
                    "resource_counter_reset"
                )

            if runtime_reset:
                quality_issues.append(
                    "runtime_counter_reset"
                )

            if runtime is None:
                quality_issues.append(
                    "metrics_endpoint"
                )

            if memory_slope is None:
                quality_issues.append(
                    "memory_slope_warmup"
                )

            sample_quality = (
                "ok"
                if not quality_issues
                else ";".join(quality_issues)
            )

            writer.writerow(
                {
                    "timestamp_utc": datetime.now(
                        timezone.utc
                    ).isoformat(
                        timespec="milliseconds"
                    ),

                    "timestamp_unix_ns": int(
                        current["unix_ns"]
                    ),

                    "sample_index": sample_index,

                    "elapsed_s": format_float(
                        current_monotonic
                        - start_monotonic
                    ),

                    "sample_interval_s": (
                        format_float(
                            interval_seconds
                        )
                    ),

                    "sample_lag_ms": (
                        format_float(
                            sample_lag_ms,
                            3,
                        )
                    ),

                    "timing_ok": timing_ok,

                    "run_id": args.run_id,
                    "profile": args.profile,

                    "pod_name": args.pod_name,
                    "pod_uid": args.pod_uid,
                    "container_id": (
                        args.container_id
                    ),

                    "host_pid": args.pid,
                    "cgroup_path": str(
                        args.cgroup
                    ),

                    "m1_cpu_millicores": (
                        format_float(
                            cpu_millicores,
                            3,
                        )
                    ),

                    "m2_cpu_throttle_ratio": (
                        format_float(
                            throttle_ratio
                        )
                    ),

                    "m3_memory_working_set_bytes": (
                        int(
                            current[
                                "memory_working_set"
                            ]
                        )
                    ),

                    "m4_memory_growth_bytes_per_s": (
                        format_float(
                            memory_slope,
                            3,
                        )
                    ),

                    "m4_memory_slope_ready": int(
                        memory_slope is not None
                    ),

                    "m5_network_rx_bytes_per_s": (
                        format_float(
                            network_rx_rate,
                            3,
                        )
                    ),

                    "m6_network_tx_bytes_per_s": (
                        format_float(
                            network_tx_rate,
                            3,
                        )
                    ),

                    "m7_filesystem_read_bytes_per_s": (
                        format_float(
                            filesystem_read_rate,
                            3,
                        )
                    ),

                    "m8_filesystem_write_bytes_per_s": (
                        format_float(
                            filesystem_write_rate,
                            3,
                        )
                    ),

                    "m9_socket_count": int(
                        current["socket_count"]
                    ),

                    "m10_fd_count": int(
                        current["fd_count"]
                    ),

                    "m11_thread_count": int(
                        current["thread_count"]
                    ),

                    "cpu_usage_usec_total": int(
                        current["cpu_usage_usec"]
                    ),

                    "cpu_nr_periods_total": int(
                        current["cpu_nr_periods"]
                    ),

                    "cpu_nr_throttled_total": int(
                        current[
                            "cpu_nr_throttled"
                        ]
                    ),

                    "cpu_throttled_usec_total": int(
                        current[
                            "cpu_throttled_usec"
                        ]
                    ),

                    "memory_current_bytes": int(
                        current["memory_current"]
                    ),

                    "memory_inactive_file_bytes": int(
                        current[
                            "memory_inactive_file"
                        ]
                    ),

                    "network_rx_bytes_total": int(
                        current["network_rx"]
                    ),

                    "network_tx_bytes_total": int(
                        current["network_tx"]
                    ),

                    "filesystem_read_bytes_total": int(
                        current[
                            "filesystem_read"
                        ]
                    ),

                    "filesystem_write_bytes_total": int(
                        current[
                            "filesystem_write"
                        ]
                    ),

                    "process_count": int(
                        current["process_count"]
                    ),

                    "rmr_rx_total": (
                        read_json_counter(
                            runtime,
                            "rmr_rx_total",
                        )
                        or 0
                    ),

                    "rmr_rx_per_s": (
                        format_float(
                            runtime_rates[
                                "rmr_rx_total"
                            ]
                        )
                    ),

                    "rmr_tx_total": (
                        read_json_counter(
                            runtime,
                            "rmr_tx_total",
                        )
                        or 0
                    ),

                    "rmr_tx_per_s": (
                        format_float(
                            runtime_rates[
                                "rmr_tx_total"
                            ]
                        )
                    ),

                    "ric_indication_total": (
                        read_json_counter(
                            runtime,
                            "ric_indication_total",
                        )
                        or 0
                    ),

                    "ric_indication_per_s": (
                        format_float(
                            runtime_rates[
                                "ric_indication_total"
                            ]
                        )
                    ),

                    "work_units_total": (
                        read_json_counter(
                            runtime,
                            "work_units_total",
                        )
                        or 0
                    ),

                    "work_units_per_s": (
                        format_float(
                            runtime_rates[
                                "work_units_total"
                            ]
                        )
                    ),

                    "heartbeat_total": (
                        heartbeat_total or 0
                    ),

                    "heartbeat_per_s": (
                        format_float(
                            runtime_rates[
                                "heartbeat_total"
                            ]
                        )
                    ),

                    "heartbeat_stall_age_s": (
                        format_float(
                            heartbeat_stall_age,
                            3,
                        )
                    ),

                    "last_rmr_rx_age_s": (
                        format_float(
                            last_rmr_rx_age,
                            3,
                        )
                    ),

                    "last_work_age_s": (
                        format_float(
                            last_work_age,
                            3,
                        )
                    ),

                    "rmr_tx_status": (
                        ""
                        if runtime is None
                        else runtime.get(
                            "rmr_tx_status",
                            "",
                        )
                    ),

                    "metrics_endpoint_ok": int(
                        runtime is not None
                    ),

                    "metrics_endpoint_error": (
                        runtime_error
                    ),

                    **limits,

                    "host_mem_available_bytes": (
                        int(
                            current[
                                "host_mem_available"
                            ]
                        )
                    ),

                    "host_swap_used_bytes": (
                        int(
                            current[
                                "host_swap_used"
                            ]
                        )
                    ),

                    "resource_counter_reset": (
                        resource_reset
                    ),

                    "runtime_counter_reset": int(
                        runtime_reset
                    ),

                    "sample_quality": (
                        sample_quality
                    ),
                }
            )

            summary["rows_written"] += 1

            previous = current

            if runtime is not None:
                previous_runtime = runtime
                previous_runtime_monotonic = (
                    current_monotonic
                )

    summary.update(
        {
            "run_id": args.run_id,
            "profile": args.profile,
            "output_csv": str(args.output),
        }
    )

    summary_path = Path(
        f"{args.output}.summary.json"
    )

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

    if summary["fatal_error"]:
        raise SystemExit(
            "Collection terminated because "
            "the target changed."
        )

    if (
        summary["rows_written"]
        != sample_count
    ):
        raise SystemExit(
            "Collection did not produce "
            "the expected row count."
        )


if __name__ == "__main__":
    main()
