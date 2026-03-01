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
type LayoutOption = "grid" | "dense";

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

const LAYOUT_OPTIONS: { label: string; value: LayoutOption }[] = [
  { label: "Cards Grid", value: "grid" },
  { label: "Dense Triage", value: "dense" },
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


function itemMatchesCategory(item: NewsItem, category: CategoryOption): boolean {
  if (category === "all") return true;
  if (category === "with-iocs") return item.hasIocSectionHint;

  const haystack = `${item.title} ${item.summary}`.toLowerCase();
  return CATEGORY_KEYWORDS[category].some((kw) => haystack.includes(kw));
}

type TrendTile = {
  id: string;
  label: string;
  mentions: number;
  deltaPct: number;
  sparkline: number[];
};

function sparkPoints(values: number[], width = 120, height = 28): string {
  if (values.length === 0) return "";
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? width / (values.length - 1) : width;

  return values
    .map((value, idx) => {
      const x = idx * step;
      const y = height - (value / max) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

function getHostname(link: string): string {
  try {
    return new URL(link).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

function getWebsiteLogo(link: string): { primary: string; fallback: string; host: string } {
  const host = getHostname(link);
  const primary = host ? `https://logo.clearbit.com/${host}` : "";
  const fallback = host ? `https://www.google.com/s2/favicons?domain=${host}&sz=128` : "";
  return { primary, fallback, host };
}

export default function Home() {
  const [lookback, setLookback] = useState<LookbackOption>("24h");
  const [category, setCategory] = useState<CategoryOption>("all");
  const [autoRefresh, setAutoRefresh] = useState<RefreshOption>("off");
  const [theme, setTheme] = useState<ThemeOption>("dark");
  const [layout, setLayout] = useState<LayoutOption>("grid");
  const [displayWidgetOpen, setDisplayWidgetOpen] = useState(false);
  const displayWidgetRef = useRef<HTMLDivElement | null>(null);
  const [items, setItems] = useState<NewsItem[]>([]);
  const [trendSourceItems, setTrendSourceItems] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [iocLoadingById, setIocLoadingById] = useState<Record<string, boolean>>({});
  const [, setIocById] = useState<Record<string, IocResult | undefined>>({});

  const loadNews = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/news?lookback=${lookback}`);
      if (!res.ok) throw new Error("Could not load feed.");

      const data = await res.json();

      setItems(data.items ?? []);
      setTrendSourceItems(data.items ?? []);
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
    const savedLayout = localStorage.getItem("mucaro-layout") as LayoutOption | null;
    if (savedLayout && ["grid", "dense"].includes(savedLayout)) {
      setLayout(savedLayout);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("mucaro-layout", layout);
  }, [layout]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDisplayWidgetOpen(false);
      }
    };

    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (displayWidgetRef.current && !displayWidgetRef.current.contains(target)) {
        setDisplayWidgetOpen(false);
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

  const trendTiles = useMemo<TrendTile[]>(() => {
    const topicDefs = [
      { id: "vuln-cve", label: "Vuln / CVE" },
      { id: "ransomware", label: "Ransomware" },
      { id: "zero-day", label: "Zero-Day" },
      { id: "malware", label: "Malware" },
      { id: "phishing", label: "Phishing" },
      { id: "apt", label: "APT / Actor" },
      { id: "breach", label: "Breaches" },
      { id: "cloud", label: "Cloud" },
      { id: "iam", label: "Identity" },
      { id: "ics-ot", label: "ICS / OT" },
    ] as const;

    const now = Date.now();
    const bucketMs = 4 * 60 * 60 * 1000;
    const bucketCount = 6;

    return topicDefs
      .map((topic) => {
        const matching = trendSourceItems.filter((item) => itemMatchesCategory(item, topic.id));

        const sparkline = Array.from({ length: bucketCount }, () => 0);
        for (const item of matching) {
          const ageMs = now - new Date(item.publishedAt).getTime();
          if (ageMs < 0 || ageMs > bucketMs * bucketCount) continue;
          const idxFromRight = Math.floor(ageMs / bucketMs);
          const bucketIdx = bucketCount - 1 - idxFromRight;
          if (bucketIdx >= 0 && bucketIdx < bucketCount) sparkline[bucketIdx] += 1;
        }

        const recent = sparkline[bucketCount - 1] + sparkline[bucketCount - 2];
        const prior = Math.max(sparkline[bucketCount - 3] + sparkline[bucketCount - 4], 1);
        const deltaPct = Math.round(((recent - prior) / prior) * 100);

        return {
          id: topic.id,
          label: topic.label,
          mentions: matching.length,
          deltaPct,
          sparkline,
        };
      })
      .sort((a, b) => b.mentions - a.mentions)
      .slice(0, 6);
  }, [trendSourceItems]);

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

        {!loading && !error && trendTiles.length > 0 ? (
          <section className={`mb-6 rounded-xl border p-3 ${themeClasses.panel}`}>
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <h2 className="text-xs font-semibold uppercase tracking-wider">Trending Topics</h2>
                {category !== "all" ? (
                  <button
                    type="button"
                    onClick={() => setCategory("all")}
                    className={`rounded-md border px-2 py-1 text-[10px] font-semibold transition ${themeClasses.inputBtn}`}
                    title="Clear category filter"
                  >
                    Clear filter
                  </button>
                ) : null}
              </div>
              <span className={`text-[11px] ${themeClasses.submuted}`}>24h mini-sparks</span>
            </div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
              {trendTiles.map((trend) => {
                const points = sparkPoints(trend.sparkline);
                const isUp = trend.deltaPct >= 0;
                const isActive = category === (trend.id as CategoryOption);
                return (
                  <button
                    key={trend.id}
                    type="button"
                    onClick={() => setCategory(trend.id as CategoryOption)}
                    className={`rounded-lg border p-2 text-left transition ${themeClasses.card} ${themeClasses.cardHover} ${isActive ? "ring-2 ring-cyan-500" : ""}`}
                    title={`Filter feed by ${trend.label}`}
                  >
                    <div className="mb-1 flex items-start justify-between gap-1">
                      <h3 className="text-[11px] font-semibold leading-tight">{trend.label}</h3>
                      <span className={`text-[10px] font-semibold ${isUp ? "text-emerald-400" : "text-rose-400"}`}>
                        {isUp ? "+" : ""}
                        {trend.deltaPct}%
                      </span>
                    </div>
                    <p className={`mb-1 text-[10px] ${themeClasses.submuted}`}>{trend.mentions} mentions</p>
                    <svg viewBox="0 0 120 28" className="h-7 w-full" role="img" aria-label={`${trend.label} sparkline`}>
                      <polyline
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        points={points}
                        className={isUp ? "text-emerald-400" : "text-cyan-400"}
                      />
                    </svg>
                  </button>
                );
              })}
            </div>
          </section>
        ) : null}

        {loading ? (
          <p className="text-slate-400">Loading latest intelligence...</p>
        ) : error ? (
          <p className="rounded-lg border border-red-700 bg-red-950/50 p-4 text-red-300">{error}</p>
        ) : filteredItems.length === 0 ? (
          <p className={`rounded-lg border p-4 ${themeClasses.panel} ${themeClasses.muted}`}>
            No results found for this time window/category. Try expanding lookback or changing category.
          </p>
        ) : (
          <section
            className={`grid ${
              layout === "dense"
                ? "grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4"
                : "grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3"
            }`}
          >
            {filteredItems.map((item) => (
              <article
                key={item.id}
                className={`flex h-full flex-col overflow-hidden rounded-2xl border shadow-[0_0_0_1px_rgba(148,163,184,0.04)] transition ${themeClasses.card} ${themeClasses.cardHover}`}
              >
                <a href={item.link} target="_blank" rel="noreferrer" className="block">
                  <div className={`${layout === "dense" ? "aspect-[16/8]" : "aspect-video"} w-full bg-slate-800`}>
                    {item.thumbnail ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img src={item.thumbnail} alt={item.title} className="h-full w-full object-cover" />
                    ) : (
                      <div className="flex h-full flex-col items-center justify-center bg-gradient-to-br from-slate-800 via-slate-900 to-cyan-950 text-center">
                        {(() => {
                          const logo = getWebsiteLogo(item.link);
                          return logo.primary ? (
                            // eslint-disable-next-line @next/next/no-img-element
                            <img
                              src={logo.primary}
                              alt={`${logo.host} logo`}
                              className="mb-2 h-14 w-14 rounded-xl border border-slate-600 bg-white p-2"
                              onError={(e) => {
                                if (logo.fallback && e.currentTarget.src !== logo.fallback) {
                                  e.currentTarget.src = logo.fallback;
                                }
                              }}
                            />
                          ) : null;
                        })()}
                        <span className="text-xs font-medium text-slate-300">{getHostname(item.link) || item.source}</span>
                      </div>
                    )}
                  </div>
                </a>

                <div className={`flex h-full flex-1 flex-col ${layout === "dense" ? "space-y-2 p-3" : "space-y-3 p-4"}`}>
                  <div className={`flex items-center justify-between text-xs ${themeClasses.submuted}`}>
                    <span className={`rounded-full border px-2 py-1 ${themeClasses.badge}`}>{item.source}</span>
                    <time>{formatPublished(item.publishedAt)}</time>
                  </div>

                  <h2 className={`${layout === "dense" ? "text-sm" : "text-base"} font-semibold leading-snug`}>{item.title}</h2>

                  <p className={`${layout === "dense" ? "min-h-[64px] max-h-[64px] text-xs" : "min-h-[96px] max-h-[96px] text-sm"} overflow-hidden leading-6 ${themeClasses.muted}`}>
                    {item.summary}
                  </p>

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
                </div>
              </article>
            ))}
          </section>
        )}
        <div ref={displayWidgetRef} className="fixed right-0 top-20 z-50">
          <div className="group relative flex items-center justify-end">
            <button
              onClick={() => setDisplayWidgetOpen((prev) => !prev)}
              aria-label="Open display options"
              className={`rounded-l-xl rounded-r-none border px-3 py-2 text-xs font-semibold shadow-lg transition-transform transition-opacity duration-200 ${displayWidgetOpen ? "translate-x-0 opacity-100" : "translate-x-[68%] opacity-60 group-hover:translate-x-0 group-hover:opacity-100"} ${themeClasses.inputBtn}`}
            >
              ❮ Display
            </button>

            {displayWidgetOpen ? (
              <div className={`absolute right-0 top-11 w-64 rounded-xl border p-3 shadow-2xl backdrop-blur ${themeClasses.panel}`}>
                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>Theme</p>
                <div className="mb-3 flex flex-col gap-2">
                  {THEME_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => setTheme(option.value)}
                      className={`rounded-md border px-2 py-2 text-left text-xs transition ${
                        theme === option.value ? themeClasses.accentBtn : themeClasses.inputBtn
                      }`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>

                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>Layout</p>
                <div className="flex flex-col gap-2">
                  {LAYOUT_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => setLayout(option.value)}
                      className={`rounded-md border px-2 py-2 text-left text-xs transition ${
                        layout === option.value ? themeClasses.accentBtn : themeClasses.inputBtn
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
