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
type LangOption = "en" | "es";

const LOOKBACKS: { value: LookbackOption; label: Record<LangOption, string> }[] = [
  { value: "1h", label: { en: "Last 1 hour", es: "Última hora" } },
  { value: "6h", label: { en: "Last 6 hours", es: "Últimas 6 horas" } },
  { value: "12h", label: { en: "Last 12 hours", es: "Últimas 12 horas" } },
  { value: "24h", label: { en: "Last 24 hours", es: "Últimas 24 horas" } },
  { value: "3d", label: { en: "Last 3 days", es: "Últimos 3 días" } },
  { value: "7d", label: { en: "Last 7 days", es: "Últimos 7 días" } },
  { value: "30d", label: { en: "Last 30 days", es: "Últimos 30 días" } },
];

const CATEGORY_OPTIONS: { value: CategoryOption; label: Record<LangOption, string> }[] = [
  { value: "all", label: { en: "All categories", es: "Categorías" } },
  { value: "vuln-cve", label: { en: "Vulnerabilities & CVEs", es: "Vulnerabilidades y CVEs" } },
  { value: "ransomware", label: { en: "Ransomware", es: "Ransomware" } },
  { value: "apt", label: { en: "Threat Actors / APT", es: "Actores de amenaza / APT" } },
  { value: "breach", label: { en: "Data Breaches", es: "Filtraciones de datos" } },
  { value: "phishing", label: { en: "Phishing & Social Engineering", es: "Phishing e ingeniería social" } },
  { value: "malware", label: { en: "Malware", es: "Malware" } },
  { value: "cloud", label: { en: "Cloud Security", es: "Seguridad en la nube" } },
  { value: "iam", label: { en: "Identity & Access (IAM)", es: "Identidad y acceso (IAM)" } },
  { value: "zero-day", label: { en: "Zero-Day / Exploits", es: "Zero-Day / Exploits" } },
  { value: "detection", label: { en: "Defense / Detection Engineering", es: "Defensa / Ingeniería de detección" } },
  { value: "compliance", label: { en: "Regulatory & Compliance", es: "Regulación y cumplimiento" } },
  { value: "ics-ot", label: { en: "ICS/OT Security", es: "Seguridad ICS/OT" } },
  { value: "with-iocs", label: { en: "Reports with IOCs", es: "Reportes con IOCs" } },
];

const REFRESH_OPTIONS: { value: RefreshOption; label: Record<LangOption, string> }[] = [
  { value: "off", label: { en: "Off", es: "Desactivado" } },
  { value: "10m", label: { en: "Every 10 minutes", es: "Cada 10 minutos" } },
  { value: "30m", label: { en: "Every 30 minutes", es: "Cada 30 minutos" } },
  { value: "60m", label: { en: "Every 60 minutes", es: "Cada 60 minutos" } },
];

const THEME_OPTIONS: { value: ThemeOption; label: Record<LangOption, string> }[] = [
  { value: "dark", label: { en: "SOC Dark", es: "SOC oscuro" } },
  { value: "nord", label: { en: "Nord Calm", es: "Nord calmado" } },
  { value: "high-contrast", label: { en: "High Contrast", es: "Alto contraste" } },
  { value: "light", label: { en: "Light", es: "Claro" } },
  { value: "matrix", label: { en: "Matrix", es: "Matrix" } },
];

const LAYOUT_OPTIONS: { value: LayoutOption; label: Record<LangOption, string> }[] = [
  { value: "grid", label: { en: "Cards Grid", es: "Cuadrícula" } },
  { value: "dense", label: { en: "Dense Triage", es: "Vista compacta" } },
];

const LANG_OPTIONS: { label: string; value: LangOption }[] = [
  { label: "English", value: "en" },
  { label: "Español", value: "es" },
];

const UI_TEXT: Record<LangOption, Record<string, string>> = {
  en: {
    subtitleSuffix: "cybersecurity intelligence",
    lookback: "Lookback window",
    category: "Category",
    autoRefresh: "Auto-refresh",
    language: "Language",
    refreshNow: "Refresh now",
    openSource: "Open Source",
    extractIocs: "Extract IOCs",
    extracting: "Extracting...",
    warning: "IOCs are auto-extracted and may include false positives. Do not auto-block from this output. Validate each IOC against source context, telemetry, and intel confidence before taking action.",
    splunk: "Splunk",
    kibana: "Kibana",
    esql: "ES|QL",
    noResults: "No results found for this time window/category. Try expanding lookback or changing category.",
    title: "Múcaro Threat Monitor",
    theme: "Theme",
    layout: "Layout",
  },
  es: {
    subtitleSuffix: "inteligencia de ciberseguridad",
    lookback: "Ventana de tiempo",
    category: "Categoría",
    autoRefresh: "Auto-actualización",
    language: "Idioma",
    refreshNow: "Actualizar",
    openSource: "Abrir fuente",
    extractIocs: "Extraer IOCs",
    extracting: "Extrayendo...",
    warning: "Los IOCs se extraen automáticamente y pueden incluir falsos positivos. No bloquees automáticamente con esta salida. Valida cada IOC con el contexto de la fuente, la telemetría y el nivel de confianza antes de tomar acción.",
    splunk: "Splunk",
    kibana: "Kibana",
    esql: "ES|QL",
    noResults: "No se encontraron resultados para esta ventana/categoría. Intenta ampliar el rango o cambiar la categoría.",
    title: "Múcaro",
    theme: "Tema",
    layout: "Diseño",
  },
};

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

function flattenIocs(result: IocResult): { type: string; value: string }[] {
  return [
    ...result.iocs.ips.map((v) => ({ type: "ip", value: v })),
    ...result.iocs.domains.map((v) => ({ type: "domain", value: v })),
    ...result.iocs.urls.map((v) => ({ type: "url", value: v })),
    ...result.iocs.hashes.map((v) => ({ type: "hash", value: v })),
    ...result.iocs.cves.map((v) => ({ type: "cve", value: v })),
  ];
}

type IocTypeKey = "ips" | "domains" | "urls" | "hashes" | "cves";
type QueryPlatform = "splunk" | "kibana" | "esql";

type QueryPreviewState = {
  itemId: string;
  platform: QueryPlatform;
  type: IocTypeKey;
  indexName: string;
  query: string;
};

function buildSplunkIocQuery(type: IocTypeKey, values: string[], indexName = "<your_index>"): string {
  const uniqueValues = [...new Set(values.map((v) => v.trim()).filter(Boolean))];
  if (uniqueValues.length === 0) return "";

  const quoted = uniqueValues.map((v) => `"${v.replace(/"/g, '\\"')}"`);

  if (type === "ips") {
    const terms = uniqueValues.map((ip) => `TERM(${ip})`).join(" OR ");
    return `index=${indexName} (${terms})`;
  }

  if (type === "domains") {
    return `index=${indexName} (domain IN (${quoted.join(", ")}) OR dest_domain IN (${quoted.join(", ")}) OR query IN (${quoted.join(", ")}))`;
  }

  if (type === "urls") {
    return `index=${indexName} (url IN (${quoted.join(", ")}) OR uri IN (${quoted.join(", ")}) OR request IN (${quoted.join(", ")}))`;
  }

  if (type === "hashes") {
    return `index=${indexName} (file_hash IN (${quoted.join(", ")}) OR hash IN (${quoted.join(", ")}) OR sha256 IN (${quoted.join(", ")}) OR md5 IN (${quoted.join(", ")}))`;
  }

  return `index=${indexName} cve IN (${quoted.join(", ")})`;
}

function buildKibanaIocQuery(type: IocTypeKey, values: string[]): string {
  const uniqueValues = [...new Set(values.map((v) => v.trim()).filter(Boolean))];
  if (uniqueValues.length === 0) return "";

  const quoted = uniqueValues.map((v) => `"${v.replace(/"/g, '\\"')}"`).join(" or ");

  if (type === "ips") {
    return `source.ip: (${quoted}) or destination.ip: (${quoted}) or client.ip: (${quoted}) or server.ip: (${quoted})`;
  }

  if (type === "domains") {
    return `dns.question.name: (${quoted}) or url.domain: (${quoted}) or destination.domain: (${quoted})`;
  }

  if (type === "urls") {
    return `url.full: (${quoted}) or http.request.referrer: (${quoted}) or event.original: (${quoted})`;
  }

  if (type === "hashes") {
    return `file.hash.md5: (${quoted}) or file.hash.sha1: (${quoted}) or file.hash.sha256: (${quoted}) or hash: (${quoted})`;
  }

  return `vulnerability.id: (${quoted}) or cve: (${quoted})`;
}

function buildEsqlIocQuery(type: IocTypeKey, values: string[], source = "logs-*"): string {
  const uniqueValues = [...new Set(values.map((v) => v.trim()).filter(Boolean))];
  if (uniqueValues.length === 0) return "";

  const list = uniqueValues.map((v) => `"${v.replace(/"/g, '\\"')}"`).join(", ");

  if (type === "ips") {
    return `FROM ${source}\n| WHERE source.ip IN (${list}) OR destination.ip IN (${list}) OR client.ip IN (${list}) OR server.ip IN (${list})\n| LIMIT 100`;
  }

  if (type === "domains") {
    return `FROM ${source}\n| WHERE dns.question.name IN (${list}) OR url.domain IN (${list}) OR destination.domain IN (${list})\n| LIMIT 100`;
  }

  if (type === "urls") {
    return `FROM ${source}\n| WHERE url.full IN (${list}) OR http.request.referrer IN (${list}) OR event.original IN (${list})\n| LIMIT 100`;
  }

  if (type === "hashes") {
    return `FROM ${source}\n| WHERE file.hash.md5 IN (${list}) OR file.hash.sha1 IN (${list}) OR file.hash.sha256 IN (${list}) OR hash IN (${list})\n| LIMIT 100`;
  }

  return `FROM ${source}\n| WHERE vulnerability.id IN (${list}) OR cve IN (${list})\n| LIMIT 100`;
}

function getIocTypeCounts(result: IocResult): { key: IocTypeKey; label: string; count: number }[] {
  return [
    { key: "ips", label: "IPs", count: result.iocs.ips.length },
    { key: "domains", label: "Domains", count: result.iocs.domains.length },
    { key: "urls", label: "URLs", count: result.iocs.urls.length },
    { key: "hashes", label: "Hashes", count: result.iocs.hashes.length },
    { key: "cves", label: "CVEs", count: result.iocs.cves.length },
  ];
}

export default function Home() {
  const [lookback, setLookback] = useState<LookbackOption>("24h");
  const [category, setCategory] = useState<CategoryOption>("all");
  const [autoRefresh, setAutoRefresh] = useState<RefreshOption>("off");
  const [theme, setTheme] = useState<ThemeOption>("dark");
  const [layout, setLayout] = useState<LayoutOption>("grid");
  const [language, setLanguage] = useState<LangOption>("en");
  const [displayWidgetOpen, setDisplayWidgetOpen] = useState(false);
  const displayWidgetRef = useRef<HTMLDivElement | null>(null);
  const [items, setItems] = useState<NewsItem[]>([]);
  const [thumbFailedById, setThumbFailedById] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [iocLoadingById, setIocLoadingById] = useState<Record<string, boolean>>({});
  const [iocById, setIocById] = useState<Record<string, IocResult | undefined>>({});
  const [iocStatusById, setIocStatusById] = useState<Record<string, { tone: "ok" | "warn" | "error"; text: string } | undefined>>({});
  const [splunkCopiedById, setSplunkCopiedById] = useState<Record<string, IocTypeKey | undefined>>({});
  const [kibanaCopiedById, setKibanaCopiedById] = useState<Record<string, IocTypeKey | undefined>>({});
  const [esqlCopiedById, setEsqlCopiedById] = useState<Record<string, IocTypeKey | undefined>>({});
  const [queryPreview, setQueryPreview] = useState<QueryPreviewState | null>(null);

  const loadNews = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/news?lookback=${lookback}`);
      if (!res.ok) throw new Error("Could not load feed.");

      const data = await res.json();

      setItems(data.items ?? []);
      setThumbFailedById({});
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
    const savedLanguage = localStorage.getItem("mucaro-language") as LangOption | null;
    if (savedLanguage && ["en", "es"].includes(savedLanguage)) {
      setLanguage(savedLanguage);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("mucaro-language", language);
  }, [language]);

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

  const t = UI_TEXT[language];

  const headerText = useMemo(() => {
    const selected = LOOKBACKS.find((l) => l.value === lookback)?.label[language] ?? "Last 24 hours";
    return `${selected} ${t.subtitleSuffix}`;
  }, [lookback, language, t.subtitleSuffix]);

  const filteredItems = useMemo(
    () => items.filter((item) => itemMatchesCategory(item, category)),
    [items, category]
  );

  async function handleExtractIocs(item: NewsItem) {
    setIocLoadingById((prev) => ({ ...prev, [item.id]: true }));
    setIocStatusById((prev) => ({ ...prev, [item.id]: undefined }));

    try {
      const res = await fetch("/api/iocs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: item.link }),
      });

      if (!res.ok) {
        let message = "Failed to extract IOCs";
        try {
          const payload = (await res.json()) as { error?: string; details?: string };
          message = payload.details || payload.error || message;
        } catch {
          // Ignore parse errors and fall back to generic text.
        }
        throw new Error(message);
      }

      const data = (await res.json()) as IocResult;
      setIocById((prev) => ({ ...prev, [item.id]: data }));

      if (!data.hasIocSection) {
        setIocStatusById((prev) => ({
          ...prev,
          [item.id]: { tone: "warn", text: "No IOC section detected on this article." },
        }));
        return;
      }

      const total =
        data.iocs.ips.length +
        data.iocs.domains.length +
        data.iocs.urls.length +
        data.iocs.hashes.length +
        data.iocs.cves.length;

      setIocStatusById((prev) => ({
        ...prev,
        [item.id]: { tone: "ok", text: `Extracted ${total} IOC${total === 1 ? "" : "s"}.` },
      }));
    } catch (error) {
      setIocById((prev) => ({
        ...prev,
        [item.id]: {
          hasIocSection: false,
          iocs: { ips: [], domains: [], urls: [], hashes: [], cves: [] },
        },
      }));

      setIocStatusById((prev) => ({
        ...prev,
        [item.id]: {
          tone: "error",
          text: error instanceof Error ? error.message : "IOC extraction failed.",
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

  function openQueryPreview(item: NewsItem, platform: QueryPlatform, type: IocTypeKey) {
    const result = iocById[item.id];
    if (!result?.hasIocSection) return;

    const values = result.iocs[type];
    if (!values.length) return;

    const indexName = platform === "splunk" ? "<your_index>" : "logs-*";
    const query =
      platform === "splunk"
        ? buildSplunkIocQuery(type, values, indexName)
        : platform === "kibana"
          ? buildKibanaIocQuery(type, values)
          : buildEsqlIocQuery(type, values, indexName);

    setQueryPreview({
      itemId: item.id,
      platform,
      type,
      indexName,
      query,
    });
  }

  function handlePreviewIndexChange(indexName: string) {
    if (!queryPreview || (queryPreview.platform !== "splunk" && queryPreview.platform !== "esql")) return;
    const result = iocById[queryPreview.itemId];
    if (!result?.hasIocSection) return;

    const nextQuery =
      queryPreview.platform === "splunk"
        ? buildSplunkIocQuery(queryPreview.type, result.iocs[queryPreview.type], indexName)
        : buildEsqlIocQuery(queryPreview.type, result.iocs[queryPreview.type], indexName);

    setQueryPreview((prev) => (prev ? { ...prev, indexName, query: nextQuery } : prev));
  }

  function handlePreviewQueryChange(query: string) {
    setQueryPreview((prev) => (prev ? { ...prev, query } : prev));
  }

  async function handleCopyPreviewQuery() {
    if (!queryPreview) return;

    try {
      await navigator.clipboard.writeText(queryPreview.query);
      if (queryPreview.platform === "splunk") {
        setSplunkCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: queryPreview.type }));
        window.setTimeout(() => {
          setSplunkCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: undefined }));
        }, 1800);
      } else if (queryPreview.platform === "kibana") {
        setKibanaCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: queryPreview.type }));
        window.setTimeout(() => {
          setKibanaCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: undefined }));
        }, 1800);
      } else {
        setEsqlCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: queryPreview.type }));
        window.setTimeout(() => {
          setEsqlCopiedById((prev) => ({ ...prev, [queryPreview.itemId]: undefined }));
        }, 1800);
      }
    } catch {
      downloadFile(
        `${queryPreview.platform}-${queryPreview.type}-query-${queryPreview.itemId.slice(0, 16)}.txt`,
        queryPreview.query,
        "text/plain;charset=utf-8"
      );
    } finally {
      setQueryPreview(null);
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
              <h1 className="text-3xl font-bold tracking-tight">{t.title}</h1>
            </div>
            <p className={`mt-2 text-sm ${themeClasses.muted}`}>{headerText}</p>
            <p className={`mt-1 text-xs ${themeClasses.subtle}`}>
              Last updated: {lastUpdated ? formatPublished(lastUpdated) : "not yet"}
            </p>
          </div>

          <div className={`flex flex-col gap-3 rounded-xl border p-3 md:flex-row md:flex-wrap md:items-end ${themeClasses.panel}`}>
            <div>
              <label htmlFor="lookback" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                {t.lookback}
              </label>
              <select
                id="lookback"
                className={`w-52 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                value={lookback}
                onChange={(e) => setLookback(e.target.value as LookbackOption)}
              >
                {LOOKBACKS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label[language]}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="category" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                {t.category}
              </label>
              <select
                id="category"
                className={`w-64 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                value={category}
                onChange={(e) => setCategory(e.target.value as CategoryOption)}
              >
                {CATEGORY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label[language]}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="autoRefresh" className={`mb-2 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                {t.autoRefresh}
              </label>
              <select
                id="autoRefresh"
                className={`w-52 rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                value={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.value as RefreshOption)}
              >
                {REFRESH_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label[language]}
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
              {t.refreshNow}
            </button>
          </div>
        </header>

        {loading ? (
          <p className="text-slate-400">Loading latest intelligence...</p>
        ) : error ? (
          <p className="rounded-lg border border-red-700 bg-red-950/50 p-4 text-red-300">{error}</p>
        ) : filteredItems.length === 0 ? (
          <p className={`rounded-lg border p-4 ${themeClasses.panel} ${themeClasses.muted}`}>
            {t.noResults}
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
                    {item.thumbnail && !thumbFailedById[item.id] ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img
                        src={item.thumbnail}
                        alt={item.title}
                        className="h-full w-full object-cover"
                        onError={() => {
                          setThumbFailedById((prev) => ({ ...prev, [item.id]: true }));
                        }}
                      />
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

                  <div className="mt-auto space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <a
                        href={item.link}
                        target="_blank"
                        rel="noreferrer"
                        className={`inline-flex items-center rounded-lg px-3 py-2 text-xs font-semibold transition ${themeClasses.accentBtn}`}
                      >
                        {t.openSource}
                      </a>
                      {item.hasIocSectionHint ? (
                        <button
                          onClick={() => handleExtractIocs(item)}
                          className={`inline-flex items-center rounded-lg border px-3 py-2 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                        >
                          {iocLoadingById[item.id] ? t.extracting : t.extractIocs}
                        </button>
                      ) : null}
                      {iocById[item.id]?.hasIocSection ? (
                        <div className="flex flex-wrap gap-1">
                          <button
                            onClick={() => handleDownloadCsv(item)}
                            className={`inline-flex items-center rounded-lg border px-2 py-1 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                            title="Download IOCs as CSV"
                          >
                            CSV
                          </button>
                          <button
                            onClick={() => handleDownloadJson(item)}
                            className={`inline-flex items-center rounded-lg border px-2 py-1 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                            title="Download IOCs as JSON"
                          >
                            JSON
                          </button>

                        </div>
                      ) : null}
                    </div>

                    {iocStatusById[item.id] ? (
                      <p
                        className={`text-xs ${
                          iocStatusById[item.id]?.tone === "ok"
                            ? "text-emerald-400"
                            : iocStatusById[item.id]?.tone === "warn"
                              ? "text-amber-300"
                              : "text-red-300"
                        }`}
                      >
                        {iocStatusById[item.id]?.text}
                      </p>
                    ) : null}

                    {iocById[item.id]?.hasIocSection ? (
                      <div className="space-y-2">
                        <p className="rounded-md border border-amber-500/50 bg-amber-950/30 px-2 py-1 text-[11px] text-amber-200">
                          {t.warning}
                        </p>
                        <div className="space-y-1.5">
                          <p className={`text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.splunk}</p>
                          <div className="flex flex-wrap gap-1.5">
                            {getIocTypeCounts(iocById[item.id] as IocResult).map((entry) => (
                              <button
                                key={`splunk-${entry.key}`}
                                onClick={() => openQueryPreview(item, "splunk", entry.key)}
                                disabled={entry.count === 0}
                                className={`inline-flex items-center rounded-full border px-2 py-1 text-[11px] font-semibold transition ${themeClasses.inputBtn} ${entry.count === 0 ? "cursor-not-allowed opacity-40" : ""}`}
                                title={entry.count > 0 ? `Copy Splunk query for ${entry.label}` : `No ${entry.label.toLowerCase()} extracted`}
                              >
                                {splunkCopiedById[item.id] === entry.key ? `✓ ${entry.label}: ${entry.count}` : `${entry.label}: ${entry.count}`}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-1.5">
                          <p className={`text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.kibana}</p>
                          <div className="flex flex-wrap gap-1.5">
                            {getIocTypeCounts(iocById[item.id] as IocResult).map((entry) => (
                              <button
                                key={`kibana-${entry.key}`}
                                onClick={() => openQueryPreview(item, "kibana", entry.key)}
                                disabled={entry.count === 0}
                                className={`inline-flex items-center rounded-full border px-2 py-1 text-[11px] font-semibold transition ${themeClasses.inputBtn} ${entry.count === 0 ? "cursor-not-allowed opacity-40" : ""}`}
                                title={entry.count > 0 ? `Copy Kibana query for ${entry.label}` : `No ${entry.label.toLowerCase()} extracted`}
                              >
                                {kibanaCopiedById[item.id] === entry.key ? `✓ ${entry.label}: ${entry.count}` : `${entry.label}: ${entry.count}`}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-1.5">
                          <p className={`text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.esql}</p>
                          <div className="flex flex-wrap gap-1.5">
                            {getIocTypeCounts(iocById[item.id] as IocResult).map((entry) => (
                              <button
                                key={`esql-${entry.key}`}
                                onClick={() => openQueryPreview(item, "esql", entry.key)}
                                disabled={entry.count === 0}
                                className={`inline-flex items-center rounded-full border px-2 py-1 text-[11px] font-semibold transition ${themeClasses.inputBtn} ${entry.count === 0 ? "cursor-not-allowed opacity-40" : ""}`}
                                title={entry.count > 0 ? `Copy ES|QL query for ${entry.label}` : `No ${entry.label.toLowerCase()} extracted`}
                              >
                                {esqlCopiedById[item.id] === entry.key ? `✓ ${entry.label}: ${entry.count}` : `${entry.label}: ${entry.count}`}
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>
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
                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.theme}</p>
                <div className="mb-3 flex flex-col gap-2">
                  {THEME_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => setTheme(option.value)}
                      className={`rounded-md border px-2 py-2 text-left text-xs transition ${
                        theme === option.value ? themeClasses.accentBtn : themeClasses.inputBtn
                      }`}
                    >
                      {option.label[language]}
                    </button>
                  ))}
                </div>

                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.layout}</p>
                <div className="mb-3 flex flex-col gap-2">
                  {LAYOUT_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      onClick={() => setLayout(option.value)}
                      className={`rounded-md border px-2 py-2 text-left text-xs transition ${
                        layout === option.value ? themeClasses.accentBtn : themeClasses.inputBtn
                      }`}
                    >
                      {option.label[language]}
                    </button>
                  ))}
                </div>

                <p className={`mb-2 text-[11px] uppercase tracking-wider ${themeClasses.submuted}`}>{t.language}</p>
                <select
                  id="language"
                  className={`w-full rounded-lg border px-2 py-2 text-xs outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                  value={language}
                  onChange={(e) => setLanguage(e.target.value as LangOption)}
                >
                  {LANG_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}
          </div>
        </div>

        {queryPreview ? (
          <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4">
            <div className={`w-full max-w-2xl rounded-xl border p-4 shadow-2xl ${themeClasses.panel}`}>
              <div className="mb-3 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold">
                  {queryPreview.platform === "splunk" ? "Splunk" : queryPreview.platform === "kibana" ? "Kibana" : "ES|QL"} query preview · {queryPreview.type.toUpperCase()}
                </h3>
                <button
                  onClick={() => setQueryPreview(null)}
                  className={`rounded-lg border px-2 py-1 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                >
                  Close
                </button>
              </div>

              {queryPreview.platform === "splunk" || queryPreview.platform === "esql" ? (
                <div className="mb-3">
                  <label className={`mb-1 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                    {queryPreview.platform === "splunk" ? "Splunk index" : "ES|QL source"}
                  </label>
                  <input
                    value={queryPreview.indexName}
                    onChange={(e) => handlePreviewIndexChange(e.target.value)}
                    className={`w-full rounded-lg border px-3 py-2 text-sm outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                  />
                </div>
              ) : null}

              <div className="mb-3">
                <label className={`mb-1 block text-xs uppercase tracking-wider ${themeClasses.submuted}`}>
                  Query
                </label>
                <textarea
                  value={queryPreview.query}
                  onChange={(e) => handlePreviewQueryChange(e.target.value)}
                  rows={6}
                  className={`w-full rounded-lg border px-3 py-2 text-xs outline-none ring-cyan-500 focus:ring-2 ${themeClasses.select}`}
                />
              </div>

              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setQueryPreview(null)}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold transition ${themeClasses.inputBtn}`}
                >
                  Cancel
                </button>
                <button
                  onClick={handleCopyPreviewQuery}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold transition ${themeClasses.accentBtn}`}
                >
                  Copy query
                </button>
              </div>
            </div>
          </div>
        ) : null}

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
