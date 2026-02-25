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
  hasIocSectionHint: boolean;
};

type IocResult = {
  hasIocSection: boolean;
  sectionLabel?: string;
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    hashes: string[];
    cves: string[];
  };
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

type RefreshOption = "off" | "10m" | "30m" | "60m";

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
  { label: "Every 10 minutes", value: "10m" },
  { label: "Every 30 minutes", value: "30m" },
  { label: "Every 60 minutes", value: "60m" },
];

const REFRESH_MS: Record<Exclude<RefreshOption, "off">, number> = {
  "10m": 600_000,
  "30m": 1_800_000,
  "60m": 3_600_000,
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

function flattenIocs(result: IocResult): { type: string; value: string }[] {
  return [
    ...result.iocs.ips.map((v) => ({ type: "ip", value: v })),
    ...result.iocs.domains.map((v) => ({ type: "domain", value: v })),
    ...result.iocs.urls.map((v) => ({ type: "url", value: v })),
    ...result.iocs.hashes.map((v) => ({ type: "hash", value: v })),
    ...result.iocs.cves.map((v) => ({ type: "cve", value: v })),
  ];
}

function buildSplunkIpTermQuery(ips: string[], indexName = "<your_index>"): string {
  const uniqueIps = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))];
  if (uniqueIps.length === 0) return "";

  const terms = uniqueIps.map((ip) => `TERM(${ip})`).join(" OR ");
  return `index=${indexName} ${terms}`;
}

function buildKibanaIpQuery(ips: string[]): string {
  const uniqueIps = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))];
  if (uniqueIps.length === 0) return "";

  const ipList = uniqueIps.map((ip) => `"${ip}"`).join(" or ");
  return `source.ip: (${ipList}) or destination.ip: (${ipList}) or client.ip: (${ipList}) or server.ip: (${ipList})`;
}

export default function Home() {
  const [lookback, setLookback] = useState<LookbackOption>("24h");
  const [category, setCategory] = useState<CategoryOption>("all");
  const [autoRefresh, setAutoRefresh] = useState<RefreshOption>("off");
  const [items, setItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [iocLoadingById, setIocLoadingById] = useState<Record<string, boolean>>({});
  const [iocById, setIocById] = useState<Record<string, IocResult | undefined>>({});
  const [splunkCopiedById, setSplunkCopiedById] = useState<Record<string, boolean>>({});
  const [kibanaCopiedById, setKibanaCopiedById] = useState<Record<string, boolean>>({});

  const loadNews = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/news?lookback=${lookback}`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error("Could not load feed.");

      const data = await res.json();
      setItems(data.items ?? []);
      setLastUpdated(new Date().toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      if (!silent) setLoading(false);
    }
  }, [lookback]);

  useEffect(() => {
    loadNews();
  }, [loadNews]);

  useEffect(() => {
    if (autoRefresh === "off") return;

    const id = setInterval(() => {
      loadNews(true);
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

  async function handleExtractIocs(item: NewsItem) {
    setIocLoadingById((prev) => ({ ...prev, [item.id]: true }));

    try {
      const res = await fetch("/api/iocs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: item.link }),
      });

      if (!res.ok) throw new Error("Failed to extract IOCs");
      const data = (await res.json()) as IocResult;
      setIocById((prev) => ({ ...prev, [item.id]: data }));
    } catch {
      setIocById((prev) => ({
        ...prev,
        [item.id]: {
          hasIocSection: false,
          iocs: { ips: [], domains: [], urls: [], hashes: [], cves: [] },
        },
      }));
    } finally {
      setIocLoadingById((prev) => ({ ...prev, [item.id]: false }));
    }
  }
  function downloadFile(filename: string, content: string, contentType: string) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function handleDownloadCsv(item: NewsItem) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const rows = flattenIocs(result);
    const now = new Date().toISOString();
    const csvRows = [
      ["type", "value", "article_url", "source", "extracted_at"],
      ...rows.map((r) => [r.type, r.value, item.link, item.source, now]),
    ];

    const csv = csvRows
      .map((row) => row.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))
      .join("\n");

    downloadFile(`iocs-${item.id.slice(0, 16)}.csv`, csv, "text/csv;charset=utf-8");
  }

  function handleDownloadJson(item: NewsItem) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const payload = {
      source: item.source,
      articleUrl: item.link,
      extractedAt: new Date().toISOString(),
      sectionLabel: result.sectionLabel,
      iocs: result.iocs,
    };

    downloadFile(
      `iocs-${item.id.slice(0, 16)}.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
  }

  async function handleCopySplunkIpQuery(item: NewsItem) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const query = buildSplunkIpTermQuery(result.iocs.ips);
    if (!query) return;

    try {
      await navigator.clipboard.writeText(query);
      setSplunkCopiedById((prev) => ({ ...prev, [item.id]: true }));
      window.setTimeout(() => {
        setSplunkCopiedById((prev) => ({ ...prev, [item.id]: false }));
      }, 1800);
    } catch {
      // Clipboard can fail on insecure contexts, fallback to file download.
      downloadFile(`splunk-ip-query-${item.id.slice(0, 16)}.txt`, query, "text/plain;charset=utf-8");
    }
  }

  async function handleCopyKibanaIpQuery(item: NewsItem) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const query = buildKibanaIpQuery(result.iocs.ips);
    if (!query) return;

    try {
      await navigator.clipboard.writeText(query);
      setKibanaCopiedById((prev) => ({ ...prev, [item.id]: true }));
      window.setTimeout(() => {
        setKibanaCopiedById((prev) => ({ ...prev, [item.id]: false }));
      }, 1800);
    } catch {
      downloadFile(`kibana-ip-query-${item.id.slice(0, 16)}.txt`, query, "text/plain;charset=utf-8");
    }
  }

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
              onClick={() => loadNews()}
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
                className="flex h-full flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-[0_0_0_1px_rgba(148,163,184,0.04)] transition hover:border-cyan-500/50 hover:shadow-cyan-900/30"
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

                <div className="flex h-full flex-col space-y-3 p-4">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="rounded-full border border-slate-700 px-2 py-1">{item.source}</span>
                    <time>{formatPublished(item.publishedAt)}</time>
                  </div>

                  <h2 className="text-base font-semibold leading-snug text-slate-100">{item.title}</h2>

                  <p className="min-h-[96px] max-h-[96px] overflow-hidden text-sm leading-6 text-slate-300">{item.summary}</p>

                  <div className="mt-auto flex flex-wrap items-center gap-2">
                    <a
                      href={item.link}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center rounded-lg bg-cyan-500 px-3 py-2 text-xs font-semibold text-slate-950 transition hover:bg-cyan-400"
                    >
                      Open Source
                    </a>
                    {item.hasIocSectionHint ? (
                      <button
                        onClick={() => handleExtractIocs(item)}
                        className="inline-flex items-center rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-xs font-semibold text-slate-200 transition hover:border-cyan-600 hover:text-cyan-200"
                      >
                        {iocLoadingById[item.id] ? "Extracting..." : "Extract IOCs"}
                      </button>
                    ) : null}
                  </div>

                  {iocById[item.id] ? (
                    <div className="rounded-lg border border-slate-700 bg-slate-950/70 p-3 text-xs text-slate-300">
                      {iocById[item.id]?.hasIocSection ? (
                        <>
                          <p className="mb-2 text-slate-400">
                            IOC section found ({iocById[item.id]?.sectionLabel ?? "ioc"}).
                          </p>
                          <p>IPs: {iocById[item.id]?.iocs.ips.length ?? 0}</p>
                          <p>Domains: {iocById[item.id]?.iocs.domains.length ?? 0}</p>
                          <p>URLs: {iocById[item.id]?.iocs.urls.length ?? 0}</p>
                          <p>Hashes: {iocById[item.id]?.iocs.hashes.length ?? 0}</p>
                          <p>CVEs: {iocById[item.id]?.iocs.cves.length ?? 0}</p>

                          <div className="mt-3 flex flex-wrap gap-2">
                            <button
                              onClick={() => handleDownloadCsv(item)}
                              className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500 hover:text-cyan-200"
                            >
                              Download CSV
                            </button>
                            <button
                              onClick={() => handleDownloadJson(item)}
                              className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500 hover:text-cyan-200"
                            >
                              Download JSON
                            </button>
                            {(iocById[item.id]?.iocs.ips.length ?? 0) > 0 ? (
                              <>
                                <button
                                  onClick={() => handleCopySplunkIpQuery(item)}
                                  className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500 hover:text-cyan-200"
                                >
                                  {splunkCopiedById[item.id] ? "Splunk query copied" : "Copy Splunk IP query"}
                                </button>
                                <button
                                  onClick={() => handleCopyKibanaIpQuery(item)}
                                  className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:border-cyan-500 hover:text-cyan-200"
                                >
                                  {kibanaCopiedById[item.id] ? "Kibana query copied" : "Copy Kibana IP query"}
                                </button>
                              </>
                            ) : null}
                          </div>
                        </>
                      ) : (
                        <p>No explicit IOC section detected in this article.</p>
                      )}
                    </div>
                  ) : null}
                </div>
              </article>
            ))}
          </section>
        )}
      </div>
    </main>
  );
}
