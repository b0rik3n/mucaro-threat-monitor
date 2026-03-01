# Múcaro Threat Monitor

OS-agnostic cybersecurity news monitor for SOC analysts.

Múcaro Threat Monitor pulls current cyber news from trusted sources, lets you filter by lookback window and category, and gives quick summaries with one-click source access.

## Features

- Time lookback picker (`1h`, `6h`, `12h`, `24h`, `3d`, `7d`)
- Category filter (vulns, ransomware, APT, breaches, phishing, malware, cloud, IAM, zero-days, detection engineering, compliance, ICS/OT)
- Auto-refresh modes (off, 10m, 30m, 60m) + manual refresh
- News card UI with source, published timestamp, summary, and link-out
- Thumbnail enrichment fallback via OpenGraph/Twitter metadata
- Source-branded fallback placeholder when no preview image exists
- Basic event/webinar filtering to keep feed news-focused

## Current Sources

- The Hacker News
- BleepingComputer
- Krebs on Security
- CISA Alerts
- Dark Reading
- Cybersecurity Dive
- SecurityWeek
- The DFIR Report
- Unit 42
- Google Threat Intelligence
- Koi Security

## Tech Stack

- Next.js (App Router)
- TypeScript
- Tailwind CSS
- `rss-parser`

## Quick Start

```bash
npm install
npm run dev
```

Open: `http://localhost:3000`

## Production Build

```bash
npm run build
npm run start
```

## API

### `GET /api/news?lookback=<window>`

Example:

```bash
curl "http://localhost:3000/api/news?lookback=24h"
```

Valid lookback values:

- `1h`
- `6h`
- `12h`
- `24h`
- `3d`
- `7d`

## Roadmap

- Model-based summaries (local Ollama option)
- User-defined source management
- Saved/bookmarked articles
- Analyst watchlists and keyword alerts
- Better source/category relevance scoring

## Notes

- Feed content quality/format varies by publisher.
- Some entries may have limited metadata or no images.
- Event-like posts are filtered with pattern rules, but edge cases may still appear.

## License

MIT

---

Built for analysts who want signal fast.

## Contribution Status

External code contributions are currently paused while the core architecture stabilizes.

You are welcome to open issues for bugs, feed/source parsing problems, and feature requests.