export type IocExtractionResult = {
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

const IOC_SECTION_MARKERS = [
  "indicators of compromise",
  "indicator of compromise",
];

const IOC_MAX_BYTES = 2 * 1024 * 1024;

async function readTextWithLimit(response: Response, maxBytes: number): Promise<string> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (contentLength > maxBytes) {
    throw new Error("Response too large");
  }

  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;

    total += value.byteLength;
    if (total > maxBytes) {
      throw new Error("Response too large");
    }

    text += decoder.decode(value, { stream: true });
  }

  text += decoder.decode();
  return text;
}

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function findIocSectionInHtml(html: string): { label?: string; sectionHtml?: string } {
  const headingRegex = /<h([1-6])[^>]*>\s*(?:<[^>]+>\s*)*(indicators?\s+of\s+compromise|iocs?)\s*(?:<[^>]+>\s*)*<\/h\1>/gi;
  const headingMatch = headingRegex.exec(html);

  if (!headingMatch || headingMatch.index < 0) return {};

  const headingEnd = headingRegex.lastIndex;
  const rest = html.slice(headingEnd);
  const nextHeadingOffset = rest.search(/<h[1-6][^>]*>/i);
  const sectionHtml = nextHeadingOffset === -1 ? rest : rest.slice(0, nextHeadingOffset);

  return {
    label: headingMatch[2]?.toLowerCase(),
    sectionHtml,
  };
}

function findIocSectionText(text: string): { label?: string; sectionText?: string } {
  const lower = text.toLowerCase();

  for (const marker of IOC_SECTION_MARKERS) {
    const idx = lower.indexOf(marker);
    if (idx !== -1) {
      const sectionText = text.slice(idx, idx + 30000);
      return { label: marker, sectionText };
    }
  }

  return {};
}

function uniq(values: string[]): string[] {
  return [...new Set(values.map((v) => v.trim()).filter(Boolean))];
}

const NON_DOMAIN_TLDS = new Set([
  "exe",
  "dll",
  "bin",
  "so",
  "msi",
  "bat",
  "cmd",
  "ps1",
  "vbs",
  "js",
  "jar",
  "apk",
  "dmg",
  "pkg",
  "zip",
  "rar",
  "7z",
  "gz",
  "tar",
  "bz2",
  "xz",
  "iso",
  "img",
  "tmp",
  "log",
  "cfg",
  "conf",
  "ini",
  "dat",
  "json",
  "xml",
  "yml",
  "yaml",
]);

function isLikelyDomain(value: string): boolean {
  const lower = value.toLowerCase();
  const parts = lower.split(".");
  if (parts.length < 2) return false;

  const tld = parts[parts.length - 1];
  if (NON_DOMAIN_TLDS.has(tld)) return false;

  return true;
}

function normalizeDefanged(text: string): string {
  return text
    .replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().startsWith("hxxps") ? "https://" : "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[\/\]/g, "/");
}

export function extractIocsFromSection(sectionText: string): IocExtractionResult["iocs"] {
  const normalized = normalizeDefanged(sectionText);

  const ips = uniq(normalized.match(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/\d+)?\b/g) ?? []).map(
    (ip) => ip.replace(/:\d{1,5}.*/, "")
  );

  const urls = uniq(
    (normalized.match(/\bhttps?:\/\/[^\s)"'>]+/gi) ?? []).map((u) =>
      u.replace(/[),.;]+$/, "")
    )
  );

  const domains = uniq(
    normalized.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) ?? []
  ).filter((d) => !d.includes("@") && isLikelyDomain(d));

  const hashes = uniq(
    sectionText.match(/\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b/g) ?? []
  );

  const cves = uniq(sectionText.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []);

  return { ips, domains, urls, hashes, cves };
}

export async function extractIocsFromArticle(url: string): Promise<IocExtractionResult> {
  const response = await fetch(url, {
    headers: { "User-Agent": "MucaroThreatMonitor/1.0" },
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch article (${response.status})`);
  }

  const html = await readTextWithLimit(response, IOC_MAX_BYTES);

  const htmlSection = findIocSectionInHtml(html);
  if (htmlSection.sectionHtml) {
    const sectionText = stripHtml(htmlSection.sectionHtml);
    return {
      hasIocSection: true,
      sectionLabel: htmlSection.label,
      iocs: extractIocsFromSection(sectionText),
    };
  }

  const text = stripHtml(html);
  const { label, sectionText } = findIocSectionText(text);

  if (!sectionText) {
    return {
      hasIocSection: false,
      iocs: { ips: [], domains: [], urls: [], hashes: [], cves: [] },
    };
  }

  return {
    hasIocSection: true,
    sectionLabel: label,
    iocs: extractIocsFromSection(sectionText),
  };
}
