#!/usr/bin/env python3
"""AI-assisted analyzer for Google Cloud Armor logs.

This script ingests JSON/JSONL Cloud Armor logs, extracts security-relevant
signals, and generates a concise incident-focused report.
"""

from __future__ import annotations

import argparse
import glob
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ArmorEvent:
    timestamp: str
    ip: str
    method: str
    url: str
    status: int
    action: str
    policy: str
    rule: str
    region: str


class CloudArmorLogAgent:
    """Agent that reasons over Cloud Armor logs and proposes next actions."""

    def __init__(self, events: list[ArmorEvent]) -> None:
        self.events = events

    @classmethod
    def from_file(cls, path: str | Path) -> "CloudArmorLogAgent":
        entries = _read_json_input(path)
        events = [_to_event(row) for row in entries]
        return cls([event for event in events if event is not None])

    @classmethod
    def from_files(cls, paths: list[str | Path]) -> "CloudArmorLogAgent":
        events: list[ArmorEvent] = []
        for path in paths:
            entries = _read_json_input(path)
            events.extend(event for event in (_to_event(row) for row in entries) if event is not None)
        return cls(events)

    def summarize(self) -> dict[str, Any]:
        by_action = Counter(event.action for event in self.events)
        by_ip = Counter(event.ip for event in self.events)
        by_policy = Counter(event.policy for event in self.events)
        by_region = Counter(event.region for event in self.events if event.region != "unknown")
        status_counts = Counter(event.status for event in self.events)

        first_seen = min((event.timestamp for event in self.events), default="n/a")
        last_seen = max((event.timestamp for event in self.events), default="n/a")

        url_hotspots: dict[str, int] = defaultdict(int)
        for event in self.events:
            url_hotspots[event.url] += 1

        return {
            "total_events": len(self.events),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "actions": by_action,
            "top_ips": by_ip.most_common(10),
            "top_policies": by_policy.most_common(5),
            "top_regions": by_region.most_common(10),
            "status_codes": status_counts,
            "top_urls": Counter(url_hotspots).most_common(10),
        }

    def detect_findings(self) -> list[str]:
        findings: list[str] = []
        summary = self.summarize()
        actions: Counter = summary["actions"]

        blocked = actions.get("deny", 0) + actions.get("blocked", 0)
        allowed = actions.get("allow", 0)
        preview = actions.get("preview", 0)

        if blocked > 0:
            findings.append(f"{blocked} requests were blocked by Cloud Armor.")
        if preview > 0:
            findings.append(
                f"{preview} requests matched preview-only rules; evaluate enforcing these rules."
            )
        if allowed > 0 and blocked > 0 and allowed > blocked * 2:
            findings.append(
                "A high volume of traffic is still allowed compared with blocked traffic; "
                "review whether sensitive endpoints need stricter policy rules."
            )

        top_ip_data = summary["top_ips"]
        if top_ip_data:
            top_ip, top_count = top_ip_data[0]
            if summary["total_events"] > 0 and top_count / summary["total_events"] >= 0.3:
                findings.append(
                    f"IP {top_ip} generated {top_count} requests (>=30% of observed traffic), "
                    "which may indicate concentrated probing or abuse."
                )

        status_counts: Counter = summary["status_codes"]
        if status_counts.get(403, 0) > 0:
            findings.append("HTTP 403 responses confirm policy enforcement events in the log window.")
        if status_counts.get(429, 0) > 0:
            findings.append(
                "HTTP 429 responses suggest rate limiting is active; verify thresholds align with normal usage."
            )

        if not findings:
            findings.append("No high-confidence anomalies detected from current sample.")

        return findings

    def recommend_actions(self) -> list[str]:
        summary = self.summarize()
        recs = [
            "Enable Cloud Armor Adaptive Protection and monitor suggested rules.",
            "Export logs to BigQuery for longer-term trend analysis and threat hunting.",
            "Add alerting for sudden spikes in deny/preview actions and single-IP concentration.",
        ]

        if summary["top_ips"]:
            ip, count = summary["top_ips"][0]
            recs.append(
                f"Investigate source IP {ip} ({count} requests) and consider a temporary IP or ASN block if malicious."
            )

        if summary["top_urls"]:
            url, count = summary["top_urls"][0]
            recs.append(
                f"Harden endpoint {url} ({count} hits) with stricter WAF rules and bot controls if needed."
            )

        return recs

    def generate_report(self) -> str:
        summary = self.summarize()
        findings = self.detect_findings()
        recs = self.recommend_actions()

        lines = [
            "# Cloud Armor Log Analysis Report",
            "",
            "## Overview",
            f"- Total events: **{summary['total_events']}**",
            f"- Time range: **{summary['first_seen']}** to **{summary['last_seen']}**",
            "",
            "## Action Distribution",
        ]

        for action, count in summary["actions"].most_common():
            lines.append(f"- {action}: {count}")

        lines.extend(["", "## Top Source IPs"])
        for ip, count in summary["top_ips"]:
            lines.append(f"- {ip}: {count}")

        lines.extend(["", "## Top Target URLs"])
        for url, count in summary["top_urls"]:
            lines.append(f"- {url}: {count}")

        lines.extend(["", "## Key Findings"])
        for finding in findings:
            lines.append(f"- {finding}")

        lines.extend(["", "## Recommended Actions"])
        for rec in recs:
            lines.append(f"- {rec}")

        return "\n".join(lines) + "\n"


def _read_json_input(path: str | Path) -> list[dict[str, Any]]:
    content = Path(path).read_text(encoding="utf-8").strip()
    if not content:
        return []

    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    rows: list[dict[str, Any]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _to_event(entry: dict[str, Any]) -> ArmorEvent | None:
    payload = entry.get("jsonPayload", {})
    request = entry.get("httpRequest", {})
    policy = payload.get("enforcedSecurityPolicy", {})

    timestamp = _normalize_timestamp(entry.get("timestamp", "unknown"))
    ip = request.get("remoteIp", "unknown")
    method = request.get("requestMethod", "UNKNOWN")
    url = request.get("requestUrl", "unknown")
    status = _to_int(request.get("status"), default=0)
    action = str(policy.get("outcome", "unknown")).lower()
    policy_name = str(policy.get("name", "unknown"))
    rule_name = str(policy.get("configuredAction", policy.get("priority", "unknown")))
    region = str(payload.get("clientRegionCode", "unknown"))

    return ArmorEvent(
        timestamp=timestamp,
        ip=ip,
        method=method,
        url=url,
        status=status,
        action=action,
        policy=policy_name,
        rule=rule_name,
        region=region,
    )


def _normalize_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.isoformat()
    except ValueError:
        return value


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Google Cloud Armor logs and generate an incident-focused report."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="One or more paths/glob patterns to JSON or JSONL log files",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional path to write report markdown. Prints to stdout when omitted.",
    )
    return parser


def _expand_input_paths(values: list[str]) -> list[str]:
    resolved: list[str] = []
    for value in values:
        matches = sorted(glob.glob(value))
        if matches:
            resolved.extend(match for match in matches if Path(match).is_file())
        elif Path(value).is_file():
            resolved.append(value)

    unique_files: list[str] = []
    seen: set[str] = set()
    for file_path in resolved:
        if file_path not in seen:
            seen.add(file_path)
            unique_files.append(file_path)
    return unique_files


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    input_files = _expand_input_paths(args.input)
    if not input_files:
        parser.error("No input files found. Provide at least one valid path or glob pattern.")

    agent = CloudArmorLogAgent.from_files(input_files)
    report = agent.generate_report()

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
