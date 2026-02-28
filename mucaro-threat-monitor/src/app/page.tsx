"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type LookbackOption = "1h" | "6h" | "12h" | "24h" | "3d" | "7d" | "30d";

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
  | "ics-ot"
  | "with-iocs";

type RefreshOption = "off" | "10m" | "30m" | "60m";
type ThemeOption = "dark" | "light" | "nord" | "high-contrast" | "matrix";

const LOOKBACKS: { label: string; value: LookbackOption }[] = [
  { label: "Last 1 hour", value: "1h" },
  { label: "Last 6 hours", value: "6h" },
  { label: "Last 12 hours", value: "12h" },
  { label: "Last 24 hours", value: "24h" },
  { label: "Last 3 days", value: "3d" },
  { label: "Last 7 days", value: "7d" },
  { label: "Last 30 days", value: "30d" },
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
  { label: "Reports with IOCs", value: "with-iocs" },
];

const REFRESH_OPTIONS: { label: string; value: RefreshOption }[] = [
  { label: "Off", value: "off" },
  { label: "Every 10 minutes", value: "10m" },
  { label: "Every 30 minutes", value: "30m" },
  { label: "Every 60 minutes", value: "60m" },
];

const THEME_OPTIONS: { label: string; value: ThemeOption }[] = [
  { label: "SOC Dark", value: "dark" },
  { label: "Nord Calm", value: "nord" },
  { label: "High Contrast", value: "high-contrast" },
  { label: "Light", value: "light" },
  { label: "Matrix", value: "matrix" },
];

const REFRESH_MS: Record<Exclude<RefreshOption, "off">, number> = {
  "10m": 600_000,
  "30m": 1_800_000,
  "60m": 3_600_000,
};

const CATEGORY_KEYWORDS: Record<Exclude<CategoryOption, "all" | "with-iocs">, string[]> = {
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
  if (category === "with-iocs") return item.hasIocSectionHint;

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

function extractPureIp(value: string): string | null {
  const text = value.trim();
  if (!text) return null;

  const ipv4Match = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipv4Match?.[0]) {
    const octets = ipv4Match[0].split(".").map(Number);
    if (octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      return ipv4Match[0];
    }
  }

  const bracketedIpv6Match = text.match(/\[([A-Fa-f0-9:]+)\]/);
  if (bracketedIpv6Match?.[1]) return bracketedIpv6Match[1];

  const ipv6Match = text.match(/\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/);
  if (ipv6Match?.[0]) return ipv6Match[0];

  return null;
}

function normalizeIpsForQuery(ips: string[]): string[] {
  return [...new Set(ips.map(extractPureIp).filter((ip): ip is string => Boolean(ip)))];
}

function buildSplunkIpTermQuery(ips: string[], indexName = "<your_index>"): string {
  const uniqueIps = normalizeIpsForQuery(ips);
  if (uniqueIps.length === 0) return "";

  const terms = uniqueIps.map((ip) => `TERM(${ip})`).join(" OR ");
  return `index=${indexName} ${terms}`;
}

function buildKibanaIpQuery(ips: string[]): string {
  const uniqueIps = normalizeIpsForQuery(ips);
  if (uniqueIps.length === 0) return "";

  const ipList = uniqueIps.map((ip) => `"${ip}"`).join(" or ");
  return `source.ip: (${ipList}) or destination.ip: (${ipList}) or client.ip: (${ipList}) or server.ip: (${ipList})`;
}

function buildSigmaRuleFromIps(item: NewsItem, ips: string[]): string {
  const uniqueIps = normalizeIpsForQuery(ips);
  if (uniqueIps.length === 0) return "";

  const now = new Date().toISOString().slice(0, 10);
  const safeTitle = item.title.replace(/"/g, "'").slice(0, 100);
  const yamlIpList = uniqueIps.map((ip) => `      - "${ip}"`).join("\n");

  return `title: IOC IP Match - ${safeTitle}\nid: REPLACE-WITH-UUID\nstatus: experimental\ndescription: |\n  Auto-generated from Múcaro Threat Monitor IOC extraction.\n  Source: ${item.link}\nauthor: Mucaro Threat Monitor\ndate: ${now}\nlogsource:\n  category: network_connection\ndetection:\n  selection_source:\n    source.ip:\n${yamlIpList}\n  selection_destination:\n    destination.ip:\n${yamlIpList}\n  selection_client:\n    client.ip:\n${yamlIpList}\n  selection_server:\n    server.ip:\n${yamlIpList}\n  condition: 1 of selection_*\nfalsepositives:\n  - Legitimate known infrastructure\nlevel: medium\ntags:\n  - attack.command-and-control\n  - attack.t1071\n`;
}

export default function Home() {
  const [lookback, setLookback] = useState<LookbackOption>("24h");
  const [category, setCategory] = useState<CategoryOption>("all");
  const [autoRefresh, setAutoRefresh] = useState<RefreshOption>("off");
  const [theme, setTheme] = useState<ThemeOption>("dark");
  const [themeWidgetOpen, setThemeWidgetOpen] = useState(false);
  const themeWidgetRef = useRef<HTMLDivElement | null>(null);
  const [items, setItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [iocLoadingById, setIocLoadingById] = useState<Record<string, boolean>>({});
  const [iocById, setIocById] = useState<Record<string, IocResult | undefined>>({});
  const [splunkCopiedById, setSplunkCopiedById] = useState<Record<string, boolean>>({});
  const [kibanaCopiedById, setKibanaCopiedById] = useState<Record<string, boolean>>({});
  const [sigmaCopiedById, setSigmaCopiedById] = useState<Record<string, boolean>>({});

  const loadNews = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
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

  useEffect(() => {
    const savedTheme = localStorage.getItem("mucaro-theme") as ThemeOption | null;
    if (savedTheme && ["dark", "light", "nord", "high-contrast", "matrix"].includes(savedTheme)) {
      setTheme(savedTheme);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("mucaro-theme", theme);
  }, [theme]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setThemeWidgetOpen(false);
    };

    const onPointerDown = (event: MouseEvent) => {
      if (!themeWidgetRef.current) return;
      if (!themeWidgetRef.current.contains(event.target as Node)) {
        setThemeWidgetOpen(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("mousedown", onPointerDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("mousedown", onPointerDown);
    };
  }, []);

  const themeClasses = useMemo(() => {
    return {
      dark: {
        page: "bg-slate-950 text-slate-100",
        panel: "border-slate-700 bg-slate-900/70",
        select: "border-slate-700 bg-slate-950 text-slate-100",
        card: "border-slate-800 bg-slate-900/70",
        cardHover: "hover:border-cyan-500/50 hover:shadow-cyan-900/30",
        muted: "text-slate-300",
        submuted: "text-slate-400",
        subtle: "text-slate-500",
        accentBtn: "bg-cyan-500 text-slate-950 hover:bg-cyan-400",
        inputBtn: "border-slate-600 bg-slate-800 text-slate-200 hover:border-cyan-600 hover:text-cyan-200",
        badge: "border-slate-700",
        footerBorder: "border-slate-800",
        divider: "text-slate-700",
      },
      light: {
        page: "bg-slate-100 text-slate-900",
        panel: "border-slate-300 bg-white/90",
        select: "border-slate-300 bg-white text-slate-900",
        card: "border-slate-200 bg-white",
        cardHover: "hover:border-blue-400/60 hover:shadow-blue-200/40",
        muted: "text-slate-700",
        submuted: "text-slate-600",
        subtle: "text-slate-500",
        accentBtn: "bg-blue-600 text-white hover:bg-blue-500",
        inputBtn: "border-slate-300 bg-white text-slate-700 hover:border-blue-500 hover:text-blue-700",
        badge: "border-slate-300",
        footerBorder: "border-slate-300",
        divider: "text-slate-400",
      },
      nord: {
        page: "bg-slate-900 text-slate-100",
        panel: "border-slate-600 bg-slate-800/80",
        select: "border-slate-500 bg-slate-800 text-slate-100",
        card: "border-slate-600 bg-slate-800/70",
        cardHover: "hover:border-sky-400/60 hover:shadow-sky-900/30",
        muted: "text-slate-200",
        submuted: "text-slate-300",
        subtle: "text-slate-400",
        accentBtn: "bg-sky-500 text-slate-950 hover:bg-sky-400",
        inputBtn: "border-slate-500 bg-slate-800 text-slate-100 hover:border-sky-500 hover:text-sky-200",
        badge: "border-slate-500",
        footerBorder: "border-slate-600",
        divider: "text-slate-500",
      },
      "high-contrast": {
        page: "bg-black text-white",
        panel: "border-white bg-black",
        select: "border-white bg-black text-white",
        card: "border-white bg-black",
        cardHover: "hover:border-yellow-300 hover:shadow-yellow-900/30",
        muted: "text-white",
        submuted: "text-slate-200",
        subtle: "text-slate-300",
        accentBtn: "bg-yellow-300 text-black hover:bg-yellow-200",
        inputBtn: "border-white bg-black text-white hover:border-yellow-300 hover:text-yellow-200",
        badge: "border-white",
        footerBorder: "border-white",
        divider: "text-slate-300",
      },
      matrix: {
        page: "bg-black text-green-300",
        panel: "border-green-900 bg-green-950/30",
        select: "border-green-900 bg-black text-green-300",
        card: "border-green-900 bg-black/70",
        cardHover: "hover:border-green-500/60 hover:shadow-green-900/30",
        muted: "text-green-400",
        submuted: "text-green-500",
        subtle: "text-green-700",
        accentBtn: "bg-green-500 text-black hover:bg-green-400",
        inputBtn: "border-green-900 bg-black text-green-300 hover:border-green-500 hover:text-green-200",
        badge: "border-green-900",
        footerBorder: "border-green-900",
        divider: "text-green-900",
      },
    }[theme];
  }, [theme]);

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

  async function handleCopySigmaRule(item: NewsItem) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const rule = buildSigmaRuleFromIps(item, result.iocs.ips);
    if (!rule) return;

    try {
      await navigator.clipboard.writeText(rule);
      setSigmaCopiedById((prev) => ({ ...prev, [item.id]: true }));
      window.setTimeout(() => {
        setSigmaCopiedById((prev) => ({ ...prev, [item.id]: false }));
      }, 1800);
    } catch {
      downloadFile(`sigma-rule-${item.id.slice(0, 16)}.yml`, rule, "text/yaml;charset=utf-8");
    }
  }

  return (
    <main className={`min-h-screen ${themeClasses.page}`}>
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
            <p className={`mt-2 text-sm ${themeClasses.muted}`}>{headerText}</p>
            <p className={`mt-1 text-xs ${themeClasses.subtle}`}>
              Last updated: {lastUpdated ? formatPublished(lastUpdated) : "not yet"}
            </p>
          </div>

          <div className={`flex flex-col gap-3 rounded-xl border p-3 md:flex-row md:flex-wrap md:items-end ${themeClasses.panel}`}>
            <div>
              <label htmlFor="lookback" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                Lookback window
              </label>
              <select
                id="lookback"
                className={`w-52 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
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
              <label htmlFor="category" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                Category
              </label>
              <select
                id="category"
                className={`w-64 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
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
              <label htmlFor="autoRefresh" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                Auto-refresh
              </label>
              <select
                id="autoRefresh"
                className={`w-52 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
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
              className={`rounded-lg border px-3 py-2 text-sm font-medium transition ${
                theme === "light"
                  ? "border-blue-300 bg-blue-50 text-blue-700 hover:bg-blue-100"
                  : theme === "nord"
                    ? "border-slate-500 bg-slate-800 text-slate-100 hover:bg-slate-700"
                    : theme === "high-contrast"
                      ? "border-white bg-black text-white hover:bg-neutral-900"
                      : theme === "matrix"
                        ? "border-green-800 bg-green-950/40 text-green-300 hover:bg-green-900/40"
                        : "border-cyan-700 bg-cyan-900/30 text-cyan-200 hover:bg-cyan-800/40"
              }`}
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
          <p className={`rounded-lg border p-4 ${themeClasses.panel} ${themeClasses.muted}`}>
            No results found for this time window/category. Try expanding lookback or changing category.
          </p>
        ) : (
          <section className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
            {filteredItems.map((item) => (
              <article
                key={item.id}
                className={`flex h-full flex-col overflow-hidden rounded-2xl border shadow-[0_0_0_1px_rgba(148,163,184,0.04)] transition ${themeClasses.card} ${themeClasses.cardHover}`}
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
                  <div className={`flex items-center justify-between text-xs ${themeClasses.submuted}`}>
                    <span className={`rounded-full border px-2 py-1 ${themeClasses.badge}`}>{item.source}</span>
                    <time>{formatPublished(item.publishedAt)}</time>
                  </div>

                  <h2 className="text-base font-semibold leading-snug text-slate-100">{item.title}</h2>

                  <p className={`min-h-[96px] max-h-[96px] overflow-hidden text-sm leading-6 ${themeClasses.muted}`}>{item.summary}</p>

                  <div className="mt-auto flex flex-wrap items-center gap-2">
                    <a
                      href={item.link}
                      target="_blank"
                      rel="noreferrer"
                      className={`inline-flex items-center rounded-lg px-3 py-2 text-xs font-semibold transition ${themeClasses.accentBtn}`}
                    >
                      Open Source
                    </a>
                    {item.hasIocSectionHint ? (
                      <button
                        onClick={() => handleExtractIocs(item)}
                        className={`inline-flex items-center rounded-lg border px-3 py-2 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                      >
                        {iocLoadingById[item.id] ? "Extracting..." : "Extract IOCs"}
                      </button>
                    ) : null}
                  </div>

                  {iocById[item.id] ? (
                    <div className={`rounded-lg border p-3 text-xs ${themeClasses.panel} ${themeClasses.muted}`}>
                      {iocById[item.id]?.hasIocSection ? (
                        <>
                          <p className={`mb-2 ${themeClasses.submuted}`}>
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
                              className={`rounded border px-2 py-1 text-xs transition ${themeClasses.inputBtn}`}
                            >
                              Download CSV
                            </button>
                            <button
                              onClick={() => handleDownloadJson(item)}
                              className={`rounded border px-2 py-1 text-xs transition ${themeClasses.inputBtn}`}
                            >
                              Download JSON
                            </button>
                            {(iocById[item.id]?.iocs.ips.length ?? 0) > 0 ? (
                              <>
                                <button
                                  onClick={() => handleCopySplunkIpQuery(item)}
                                  className={`rounded border px-2 py-1 text-xs transition ${themeClasses.inputBtn}`}
                                >
                                  {splunkCopiedById[item.id] ? "Splunk query copied" : "Copy Splunk IP query"}
                                </button>
                                <button
                                  onClick={() => handleCopyKibanaIpQuery(item)}
                                  className={`rounded border px-2 py-1 text-xs transition ${themeClasses.inputBtn}`}
                                >
                                  {kibanaCopiedById[item.id] ? "Kibana query copied" : "Copy Kibana IP query"}
                                </button>
                                <button
                                  onClick={() => handleCopySigmaRule(item)}
                                  className={`rounded border px-2 py-1 text-xs transition ${themeClasses.inputBtn}`}
                                >
                                  {sigmaCopiedById[item.id] ? "Sigma rule copied" : "Copy Sigma rule"}
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
        <div ref={themeWidgetRef} className="fixed right-0 top-20 z-50">
          <div className="group relative flex items-center justify-end">
            <button
              onClick={() => setThemeWidgetOpen((prev) => !prev)}
              aria-label="Open theme selector"
              className={`rounded-l-xl rounded-r-none border px-3 py-2 text-xs font-semibold shadow-lg transition-transform transition-opacity duration-200 ${themeWidgetOpen ? "translate-x-0 opacity-100" : "translate-x-[68%] opacity-60 group-hover:translate-x-0 group-hover:opacity-100"} ${themeClasses.inputBtn}`}
            >
              ❮ Theme
            </button>

            {themeWidgetOpen ? (
              <div className={`absolute right-0 top-11 w-56 rounded-xl border p-3 shadow-2xl backdrop-blur ${themeClasses.panel}`}>
                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>Theme</p>
                <div className="flex flex-col gap-2">
                  {THEME_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => {
                        setTheme(option.value);
                        setThemeWidgetOpen(false);
                      }}
                      className={`rounded-md border px-2 py-2 text-left text-xs transition ${
                        theme === option.value ? themeClasses.accentBtn : themeClasses.inputBtn
                      }`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </div>

        <footer className={`mt-10 border-t pt-4 text-center text-xs ${themeClasses.footerBorder} ${themeClasses.subtle}`}>
          <div className="flex flex-col items-center justify-center gap-2 sm:flex-row sm:gap-3">
            <span>© {new Date().getFullYear()} Múcaro. All rights reserved.</span>
            <span className={`hidden sm:inline ${themeClasses.divider}`}>•</span>
            <a
              href="https://x.com/mucaroTM"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 hover:text-cyan-300"
            >
              Follow on X
            </a>
          </div>
        </footer>
      </div>
    </main>
  );
}
