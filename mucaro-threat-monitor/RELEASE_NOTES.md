# Release Notes

## v0.1.1 - Feed Source Update

### Added

- Added **Google Threat Intelligence** RSS feed to the news ingestion pipeline
- Updated project documentation source list to include Google Threat Intelligence

---

## v0.1.0 - Initial Public Build

### Added

- Initial app scaffold with Next.js + TypeScript + Tailwind
- SOC-focused dashboard UI for cyber news monitoring
- Lookback window selector:
  - 1h, 6h, 12h, 24h, 3d, 7d
- Category selector with analyst-focused taxonomy:
  - Vulnerabilities & CVEs
  - Ransomware
  - Threat Actors / APT
  - Data Breaches
  - Phishing & Social Engineering
  - Malware
  - Cloud Security
  - Identity & Access (IAM)
  - Zero-Day / Exploits
  - Defense / Detection Engineering
  - Regulatory & Compliance
  - ICS/OT Security
- Auto-refresh control:
  - Off, Every 30s, Every 1m, Every 5m
- Manual "Refresh now" action
- "Last updated" timestamp in header
- Branded app title: **Múcaro Threat Monitor**
- Múcaro logo integration in header

### Feed & Content Pipeline

- RSS ingestion from:
  - The Hacker News
  - BleepingComputer
  - Krebs on Security
  - CISA Cybersecurity Advisories
  - Dark Reading
  - The DFIR Report
  - Unit 42
- Time-based filtering according to selected lookback window
- URL-based deduplication
- Heuristic summary extraction/cleanup for article snippets
- News-only filtering rules to reduce event/webinar content

### Thumbnail Handling

- Native feed thumbnail support
- OpenGraph/Twitter image fallback extraction from source pages
- Source-branded fallback card when no image is available

### UI Copy Updates

- Article action button text updated to: **Open Source**

### Build Status

- Lint: passing
- Production build: passing

---

If you find noisy entries or source-specific parsing issues, open an issue with the article URL and source name.