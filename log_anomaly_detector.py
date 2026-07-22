"""
Log Monitoring and Anomaly Detection Module.

This module processes Combined Log Format files sequentially and identifies
statistical anomalies in error status codes using rolling Z-Score calculations.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
import re
import statistics
from typing import Iterator, Optional


# Regular expression matching the standard Combined Log Format
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


@dataclass(frozen=True)
class LogEvent:
    """Represents a structured entry extracted from a server log line."""
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: Optional[int]


def parse_line(line: str) -> Optional[LogEvent]:
    """
    Parses a single log line into a LogEvent dataclass.

    Returns None safely if the line fails validation or parsing to prevent
    pipeline interruptions.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    try:
        parsed_timestamp = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        status_code = int(data["status"])
        response_size = None if data["size"] == "-" else int(data["size"])
    except (ValueError, KeyError):
        return None

    return LogEvent(
        ip=data["ip"],
        timestamp=parsed_timestamp,
        method=data["method"],
        path=data["path"],
        status=status_code,
        size=response_size,
    )


def read_log_stream(filepath: str) -> Iterator[LogEvent]:
    """
    Yields parsed LogEvent instances from a log file line-by-line.
    
    Prevents memory overflow by streaming large log files instead of loading
    them entirely into memory.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as file:
        for raw_line in file:
            event = parse_line(raw_line)
            if event is not None:
                yield event


class ResponseCodeMonitor:
    """
    Monitors status code counts per time window and identifies spikes
    using statistical baseline comparisons (Z-Score).
    """

    def __init__(self, window_size: int = 20, z_threshold: float = 3.0) -> None:
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.history: dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))

    def ingest_bucket(self, bucket_label: str, status_counts: dict[int, int]) -> None:
        """
        Processes a single time-bucket's status code counts and evaluates
        whether the error frequency constitutes an anomaly.
        """
        error_count = sum(count for status, count in status_counts.items() if status >= 400)
        error_history = self.history["errors"]

        # Requires a baseline of at least 5 history points before testing
        if len(error_history) >= 5:
            mean_errors = statistics.mean(error_history)
            std_dev = statistics.pstdev(error_history) or 1.0  # Prevent division by zero
            z_score = (error_count - mean_errors) / std_dev

            if z_score > self.z_threshold:
                self._raise_alert(bucket_label, error_count, z_score)

        error_history.append(error_count)

    def _raise_alert(self, bucket_label: str, count: int, z_score: float) -> None:
        """Triggers notification logic upon detecting an anomaly."""
        print(
            f"[ALERT] Anomalous error spike detected at {bucket_label}: "
            f"{count} errors (Z-Score: {z_score:.2f})"
        )
