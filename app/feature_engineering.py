import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Any

import pandas as pd


MALICIOUS_BINARY_PATTERN = re.compile(r"\b(wget|curl)\b", re.IGNORECASE)


def parse_timestamp(value):
    if not value:
        return pd.NaT

    return pd.to_datetime(value, errors="coerce", utc=True)


def calculate_entropy(commands: List[str]) -> float:
    """
    Menghitung entropy dari perintah yang diketik attacker.
    Entropy dihitung berbasis karakter dari gabungan command.
    """
    text = " ".join([cmd for cmd in commands if cmd])

    if not text:
        return 0.0

    counter = Counter(text)
    total = len(text)

    entropy = 0.0
    for count in counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return float(entropy)


def calculate_average_time_between_commands(command_timestamps: List[pd.Timestamp]) -> float:
    timestamps = [ts for ts in command_timestamps if pd.notna(ts)]
    timestamps = sorted(timestamps)

    if len(timestamps) < 2:
        return 0.0

    differences = []

    for index in range(1, len(timestamps)):
        delta = timestamps[index] - timestamps[index - 1]
        differences.append(delta.total_seconds())

    if not differences:
        return 0.0

    return float(sum(differences) / len(differences))


def extract_src_ip(events: List[Dict[str, Any]]) -> str:
    for event in events:
        src_ip = (
            event.get("src_ip")
            or event.get("src_ip_address")
            or event.get("source_ip")
            or event.get("remote_host")
        )

        if src_ip:
            return str(src_ip)

    return ""


def build_session_features(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Mengubah event JSON Cowrie menjadi fitur per session.

    Fitur:
    - login_attempt_count
    - login_success_rate
    - login_failure_rate
    - command_entropy
    - command_sequence_length
    - avg_time_between_commands
    - malicious_binary_usage
    """
    sessions = defaultdict(list)

    for event in events:
        session_id = event.get("session")

        if not session_id:
            continue

        sessions[str(session_id)].append(event)

    rows = []

    for session_id, session_events in sessions.items():
        login_success_count = 0
        login_failed_count = 0
        commands = []
        command_timestamps = []

        src_ip = extract_src_ip(session_events)

        first_timestamp = pd.NaT
        last_timestamp = pd.NaT

        for event in session_events:
            event_id = event.get("eventid", "")
            timestamp = parse_timestamp(event.get("timestamp"))

            if pd.notna(timestamp):
                if pd.isna(first_timestamp) or timestamp < first_timestamp:
                    first_timestamp = timestamp

                if pd.isna(last_timestamp) or timestamp > last_timestamp:
                    last_timestamp = timestamp

            if event_id == "cowrie.login.success":
                login_success_count += 1

            elif event_id in {"cowrie.login.failed", "cowrie.login.failure"}:
                login_failed_count += 1

            elif event_id == "cowrie.command.input":
                command = event.get("input", "")

                if command:
                    commands.append(str(command))
                    command_timestamps.append(timestamp)

        login_attempt_count = login_success_count + login_failed_count

        if login_attempt_count > 0:
            login_success_rate = login_success_count / login_attempt_count
            login_failure_rate = login_failed_count / login_attempt_count
        else:
            login_success_rate = 0.0
            login_failure_rate = 0.0

        command_entropy = calculate_entropy(commands)
        command_sequence_length = len(commands)
        avg_time_between_commands = calculate_average_time_between_commands(command_timestamps)

        malicious_binary_usage = sum(
            1 for command in commands if MALICIOUS_BINARY_PATTERN.search(command)
        )

        rows.append(
            {
                "session_id": session_id,
                "source_ip": src_ip,
                "first_seen": first_timestamp.isoformat() if pd.notna(first_timestamp) else None,
                "last_seen": last_timestamp.isoformat() if pd.notna(last_timestamp) else None,

                "login_attempt_count": login_attempt_count,
                "login_success_rate": login_success_rate,
                "login_failure_rate": login_failure_rate,
                "command_entropy": command_entropy,
                "command_sequence_length": command_sequence_length,
                "avg_time_between_commands": avg_time_between_commands,
                "malicious_binary_usage": malicious_binary_usage,
            }
        )

    return pd.DataFrame(rows)