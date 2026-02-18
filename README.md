# codexassist

## Cloud Armor AI Log Agent

This repository includes a lightweight AI-style agent that analyzes Google Cloud Armor logs and produces a security report with:

- Traffic/action summary (`allow`, `deny`, `preview`, etc.)
- Top source IPs and targeted URLs
- High-signal findings (policy enforcement, concentration indicators, preview rule matches)
- Recommended remediation and monitoring actions

## Usage

```bash
python3 cloud_armor_agent.py --input cloud_armor_logs.jsonl
```

Write output to a markdown file:

```bash
python3 cloud_armor_agent.py --input cloud_armor_logs.jsonl --output report.md
```

## Supported input formats

- A JSON array of Cloud Logging entries
- A single JSON object
- JSONL (one JSON object per line)

The parser expects standard Cloud Logging fields used by Cloud Armor, including:

- `timestamp`
- `httpRequest.remoteIp`
- `httpRequest.requestMethod`
- `httpRequest.requestUrl`
- `httpRequest.status`
- `jsonPayload.enforcedSecurityPolicy.*`
