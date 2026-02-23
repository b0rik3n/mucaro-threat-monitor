# Múcaro Threat Monitor

Open-source, analyst-focused cybersecurity news monitor.

Múcaro Threat Monitor helps SOC teams quickly scan relevant cyber news with time-based filtering, category filtering, concise summaries, and one-click source access.

## What it does

- Pulls cyber news from trusted security sources
- Filters by lookback window (`1h`, `6h`, `12h`, `24h`, `3d`, `7d`)
- Filters by category (CVEs, ransomware, APT, breaches, phishing, malware, cloud, IAM, zero-day, detection engineering, compliance, ICS/OT)
- Supports auto-refresh (off, 10m, 30m, 60m)
- Provides summary snippets for fast triage
- Opens original source content in one click

## Quick start

```bash
cd mucaro-threat-monitor
npm install
npm run dev
```

Open `http://localhost:3000`

## Status

Active development.

External code contributions are currently paused while core architecture stabilizes. Issues and feedback are welcome.

## Current feed sources

- The Hacker News
- BleepingComputer
- Krebs on Security
- CISA Alerts
- Dark Reading
- Cybersecurity Dive
- SecurityWeek
- The DFIR Report
- Unit 42
- Koi Security

## Security notes

- `/api/iocs` validates URLs with protocol checks, host allowlist checks, and private/internal IP blocking.
- Default IOC host allowlist covers built-in feed sources. Extend with `IOC_EXTRA_ALLOWED_HOSTS` (comma-separated hostnames) when needed.
- API rate limiting is in-memory and best-effort for low traffic; use distributed/persistent rate limiting for larger production traffic.

## License

MIT
