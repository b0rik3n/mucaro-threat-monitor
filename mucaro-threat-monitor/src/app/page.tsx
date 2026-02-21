"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

type LookbackOption = "1h" | "6h" | "12h" | "24h" | "3d" | "7d";

type NewsItem = {
  id: string;
  title: string;
  link: string;
  source: string;
  publishedAt: string;
  thumbnail?: string;
  summary: string;
};

type CategoryOption =
  | "all"
  | "vuln-cve"
  | "ransomware"
  | "apt"
  | "breach"
  | "phishing"
  | "malware"
  | "cloud"
  | "iam"
  | "zero-day"
  | "detection"
  | "compliance"
  | "ics-ot";

type RefreshOption = "off" | "30s" | "1m" | "5m";

const LOOKBACKS: { label: string; value: LookbackOption }[] = [
  { label: "Last 1 hour", value: "1h" },
  { label: "Last 6 hours", value: "6h" },
  { label: "Last 12 hours", value: "12h" },
  { label: "Last 24 hours", value: "24h" },
  { label: "Last 3 days", value: "3d" },
  { label: "Last 7 days", value: "7d" },
];

const CATEGORY_OPTIONS: { label: string; value: CategoryOption }[] = [
  { label: "All categories", value: "all" },
  { label: "Vulnerabilities & CVEs", value: "vuln-cve" },
  { label: "Ransomware", value: "ransomware" },
  { label: "Threat Actors / APT", value: "apt" },
  { label: "Data Breaches", value: "breach" },
  { label: "Phishing & Social Engineering", value: "phishing" },
  { label: "Malware", value: "malware" },
  { label: "Cloud Security", value: "cloud" },
  { label: "Identity & Access (IAM)", value: "iam" },
  { label: "Zero-Day / Exploits", value: "zero-day" },
  { label: "Defense / Detection Engineering", value: "detection" },
  { label: "Regulatory & Compliance", value: "compliance" },
  { label: "ICS/OT Security", value: "ics-ot" },
];

const REFRESH_OPTIONS: { label: string; value: RefreshOption }[] = [
  { label: "Off", value: "off" },
  { label: "Every 30 seconds", value: "30s" },
  { label: "Every 1 minute", value: "1m" },
  { label: "Every 5 minutes", value: "5m" },
];

const REFRESH_MS: Record<Exclude<RefreshOption, "off">, number> = {
  "30s": 30_000,
  "1m": 60_000,
  "5m": 300_000,
};

const CATEGORY_KEYWORDS: Record<Exclude<CategoryOption, "all">, string[]> = {
  "vuln-cve": ["cve-", "vulnerability", "vulnerabilities", "patch", "cvss", "advisory"],
  ransomware: ["ransomware", "ransom", "locker", "decryptor"],
  apt: ["apt", "threat actor", "nation-state", "campaign", "ta"],
  breach: ["breach", "leak", "stolen", "exposed", "data theft", "compromised"],
  phishing: ["phishing", "smishing", "vishing", "social engineering", "credential theft"],
  malware: ["malware", "trojan", "worm", "botnet", "payload", "backdoor", "loader"],
  cloud: ["aws", "azure", "gcp", "cloud", "s3", "kubernetes", "container", "saas"],
  iam: ["identity", "iam", "oauth", "sso", "mfa", "authentication", "authorization", "okta", "entra"],
  "zero-day": ["zero-day", "0-day", "exploit", "weaponized", "in-the-wild"],
  detection: ["detection", "sigma", "yara", "edr", "xdr", "siem", "rule", "hunt", "playbook"],
  compliance: ["compliance", "regulation", "sec filing", "gdpr", "hipaa", "pci", "nist", "iso 27001"],
  "ics-ot": ["ics", "ot", "scada", "industrial", "plc", "critical infrastructure"],
};

function formatPublished(value: string): string {
  const date = new Date(value);
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function getFaviconUrl(link: string): string | null {
  try {
    const hostname = new URL(link).hostname;
    return `https://www.google.com/s2/favicons?domain=${hostname}&sz=64`;
  } catch {
    return null;
  }
}

function itemMatchesCategory(item: NewsItem, category: CategoryOption): boolean {
  if (category === "all") return true;

  const haystack = `${item.title} ${item.summary}`.toLowerCase();
  return CATEGORY_KEYWORDS[category].some((kw) => haystack.includes(kw));
}

export default function Home() {
  const [lookback, setLookback] = useState<LookbackOption>("24h");
  const [category, setCategory] = useState<CategoryOption>("all");
  const [autoRefresh, setAutoRefresh] = useState<RefreshOption>("off");
  const [items, setItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const loadNews = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/news?lookback=${lookback}`);
      if (!res.ok) throw new Error("Could not load feed.");

      const data = await res.json();
      setItems(data.items ?? []);
      setLastUpdated(new Date().toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [lookback]);

  useEffect(() => {
    loadNews();
  }, [loadNews]);

  useEffect(() => {
    if (autoRefresh === "off") return;

    const id = setInterval(() => {
      loadNews();
    }, REFRESH_MS[autoRefresh]);

    return () => clearInterval(id);
  }, [autoRefresh, loadNews]);

  const headerText = useMemo(() => {
    const selected = LOOKBACKS.find((l) => l.value === lookback)?.label ?? "Last 24 hours";
    return `${selected} cybersecurity intelligence`;
  }, [lookback]);

  const filteredItems = useMemo(
    () => items.filter((item) => itemMatchesCategory(item, category)),
    [items, category]
  );

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto w-full max-w-7xl px-4 py-8 md:px-8">
        <header className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="flex items-center gap-3">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="/branding/mucaro-logo.svg"
                alt="Múcaro Threat Monitor logo"
                className="h-8 w-8 rounded-md"
              />
              <h1 className="text-3xl font-bold tracking-tight">Múcaro Threat Monitor</h1>
            </div>
            <p className="mt-2 text-sm text-slate-300">{headerText}</p>
            <p className="mt-1 text-xs text-slate-500">
              Last updated: {lastUpdated ? formatPublished(lastUpdated) : "not yet"}
            </p>
          </div>

          <div className="flex flex-col gap-3 rounded-xl border border-slate-700 bg-slate-900/70 p-3 md:flex-row md:flex-wrap md:items-end">
            <div>
              <label htmlFor="lookback" className="mb-2 block text-xs uppercase tracking-wider text-slate-400">
                Lookback window
              </label>
              <select
                id="lookback"
                className="w-52 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2"
                value={lookback}
                onChange={(e) => setLookback(e.target.value as LookbackOption)}
              >
                {LOOKBACKS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="category" className="mb-2 block text-xs uppercase tracking-wider text-slate-400">
                Category
              </label>
              <select
                id="category"
                className="w-64 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2"
                value={category}
                onChange={(e) => setCategory(e.target.value as CategoryOption)}
              >
                {CATEGORY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="autoRefresh" className="mb-2 block text-xs uppercase tracking-wider text-slate-400">
                Auto-refresh
              </label>
              <select
                id="autoRefresh"
                className="w-52 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2"
                value={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.value as RefreshOption)}
              >
                {REFRESH_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={loadNews}
              className="rounded-lg border border-cyan-700 bg-cyan-900/30 px-3 py-2 text-sm font-medium text-cyan-200 transition hover:bg-cyan-800/40"
            >
              Refresh now
            </button>
          </div>
        </header>

        {loading ? (
          <p className="text-slate-400">Loading latest intelligence...</p>
        ) : error ? (
          <p className="rounded-lg border border-red-700 bg-red-950/50 p-4 text-red-300">{error}</p>
        ) : filteredItems.length === 0 ? (
          <p className="rounded-lg border border-slate-700 bg-slate-900/50 p-4 text-slate-300">
            No results found for this time window/category. Try expanding lookback or changing category.
          </p>
        ) : (
          <section className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
            {filteredItems.map((item) => (
              <article
                key={item.id}
                className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-[0_0_0_1px_rgba(148,163,184,0.04)] transition hover:border-cyan-500/50 hover:shadow-cyan-900/30"
              >
                <a href={item.link} target="_blank" rel="noreferrer" className="block">
                  <div className="aspect-video w-full bg-slate-800">
                    {item.thumbnail ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img src={item.thumbnail} alt={item.title} className="h-full w-full object-cover" />
                    ) : (
                      <div className="flex h-full flex-col items-center justify-center bg-gradient-to-br from-slate-800 via-slate-900 to-cyan-950 text-center">
                        {getFaviconUrl(item.link) ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img
                            src={getFaviconUrl(item.link) as string}
                            alt={`${item.source} logo`}
                            className="mb-3 h-10 w-10 rounded-md border border-slate-600 bg-slate-800 p-1"
                          />
                        ) : null}
                        <span className="mb-1 rounded-full border border-slate-600 px-3 py-1 text-xs text-slate-300">
                          {item.source}
                        </span>
                        <span className="text-sm font-medium text-slate-200">No preview image</span>
                      </div>
                    )}
                  </div>
                </a>

                <div className="space-y-3 p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="rounded-full border border-slate-700 px-2 py-1">{item.source}</span>
                    <time>{formatPublished(item.publishedAt)}</time>
                  </div>

                  <h2 className="text-base font-semibold leading-snug text-slate-100">{item.title}</h2>

                  <p className="text-sm leading-6 text-slate-300">{item.summary}</p>

                  <a
                    href={item.link}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center rounded-lg bg-cyan-500 px-3 py-2 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400"
                  >
                    Open Source
                  </a>
                </div>
              </article>
            ))}
          </section>
        )}
      </div>
    </main>
  );
}
