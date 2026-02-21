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
  "iocs",
  "ioc",
];

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function findIocSectionText(text: string): { label?: string; sectionText?: string } {
  const lower = text.toLowerCase();

  for (const marker of IOC_SECTION_MARKERS) {
    const idx = lower.indexOf(marker);
    if (idx !== -1) {
      // Keep extraction strict to content explicitly near IOC section marker.
      const sectionText = text.slice(idx, idx + 30000);
      return { label: marker, sectionText };
    }
  }

  return {};
}

function uniq(values: string[]): string[] {
  return [...new Set(values.map((v) => v.trim()).filter(Boolean))];
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
  ).filter((d) => !d.includes("@"));

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

  const html = await response.text();
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
