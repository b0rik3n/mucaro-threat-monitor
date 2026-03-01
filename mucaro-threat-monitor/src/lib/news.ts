import Parser from "rss-parser";

export type LookbackOption = "1h" | "6h" | "12h" | "24h" | "3d" | "7d" | "30d";
export type SourceType = "media" | "vendor" | "cert-csirt" | "government";

export type FeedSource = {
  name: string;
  url: string;
  sourceType: SourceType;
  region: string;
  priorityWeight: number;
};

export type NewsItem = {
  id: string;
  title: string;
  link: string;
  source: string;
  publishedAt: string;
  thumbnail?: string;
  summary: string;
  hasIocSectionHint: boolean;
};

const SOURCE_FALLBACK_THUMBNAILS: Record<string, string> = {
  "SecurityWeek": "https://logo.clearbit.com/securityweek.com",
  "The Hacker News": "https://logo.clearbit.com/thehackernews.com",
  BleepingComputer: "https://logo.clearbit.com/bleepingcomputer.com",
  "Krebs on Security": "https://logo.clearbit.com/krebsonsecurity.com",
  "Dark Reading": "https://logo.clearbit.com/darkreading.com",
  "Cybersecurity Dive": "https://logo.clearbit.com/cybersecuritydive.com",
  "Unit 42": "https://logo.clearbit.com/paloaltonetworks.com",
  "Google Threat Intelligence": "https://logo.clearbit.com/google.com",
  "CISA Alerts": "https://logo.clearbit.com/cisa.gov",
};

export const FEEDS: FeedSource[] = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", sourceType: "media", region: "global", priorityWeight: 1.0 },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", sourceType: "media", region: "global", priorityWeight: 1.0 },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/", sourceType: "media", region: "US", priorityWeight: 1.0 },
  { name: "CISA Alerts", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", sourceType: "government", region: "US", priorityWeight: 1.4 },
  { name: "Dark Reading", url: "https://www.darkreading.com/rss.xml", sourceType: "media", region: "global", priorityWeight: 1.0 },
  { name: "Cybersecurity Dive", url: "https://www.cybersecuritydive.com/feeds/news/", sourceType: "media", region: "US", priorityWeight: 1.0 },
  { name: "SecurityWeek", url: "https://www.securityweek.com/feed/", sourceType: "media", region: "global", priorityWeight: 1.0 },
  { name: "The DFIR Report", url: "https://thedfirreport.com/feed/", sourceType: "media", region: "global", priorityWeight: 1.1 },
  { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/", sourceType: "vendor", region: "global", priorityWeight: 1.1 },
  { name: "Google Threat Intelligence", url: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss", sourceType: "vendor", region: "global", priorityWeight: 1.1 },
  { name: "Koi Security", url: "https://www.koi.ai/blog/rss.xml", sourceType: "vendor", region: "global", priorityWeight: 1.0 },

  // CERT / CSIRT pack
  { name: "CERT-EU", url: "https://cert.europa.eu/publications/security-advisories/rss", sourceType: "cert-csirt", region: "EU", priorityWeight: 1.6 },
  { name: "CERT-FR", url: "https://www.cert.ssi.gouv.fr/feed/", sourceType: "cert-csirt", region: "FR", priorityWeight: 1.6 },
  { name: "JPCERT/CC", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", sourceType: "cert-csirt", region: "JP", priorityWeight: 1.5 },
  { name: "CERT Polska", url: "https://cert.pl/en/feed/", sourceType: "cert-csirt", region: "PL", priorityWeight: 1.5 },
  { name: "CIRCL", url: "https://www.circl.lu/feed/", sourceType: "cert-csirt", region: "LU", priorityWeight: 1.5 },
  { name: "NCSC Netherlands", url: "https://www.ncsc.nl/rss.xml", sourceType: "cert-csirt", region: "NL", priorityWeight: 1.5 },
  { name: "NCSC UK", url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed", sourceType: "cert-csirt", region: "UK", priorityWeight: 1.5 },
  { name: "CERT-Bund (BSI)", url: "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed.xml", sourceType: "cert-csirt", region: "DE", priorityWeight: 1.5 },
  { name: "ENISA News", url: "https://www.enisa.europa.eu/news/enisa-news/RSS", sourceType: "government", region: "EU", priorityWeight: 1.3 },
];

const parser = new Parser({
  timeout: 10000,
  headers: {
    "User-Agent": "SOC-News-Scout/1.0",
  },
});

const pageMetaCache = new Map<string, { image?: string; description?: string; hasIocHeading?: boolean }>();

export function getSourceProfile(sourceName: string): FeedSource | undefined {
  return FEEDS.find((source) => source.name === sourceName);
}

export function getSourceWeight(sourceName: string): number {
  return getSourceProfile(sourceName)?.priorityWeight ?? 1;
}

function extractMetaImage(html: string): string | undefined {
  const patterns = [
    /<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["'][^>]*>/i,
    /<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["'][^>]*>/i,
    /<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["'][^>]*>/i,
    /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["'][^>]*>/i,
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match?.[1]) return match[1];
  }
}

function extractMetaDescription(html: string): string | undefined {
  const patterns = [
    /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["'][^>]*>/i,
    /<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["'][^>]*>/i,
    /<meta[^>]+name=["']twitter:description["'][^>]+content=["']([^"']+)["'][^>]*>/i,
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match?.[1]) return cleanText(match[1]);
  }
}

async function fetchPageMeta(url: string): Promise<{ image?: string; description?: string; hasIocHeading?: boolean }> {
  const cached = pageMetaCache.get(url);
  if (cached) return cached;

  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "SOC-News-Scout/1.0" },
      signal: AbortSignal.timeout(7000),
    });

    if (!response.ok) return {};

    const html = await response.text();
    const meta = {
      image: extractMetaImage(html),
      description: extractMetaDescription(html),
      hasIocHeading: hasIocHeadingInHtml(html),
    };

    pageMetaCache.set(url, meta);
    return meta;
  } catch {
    return {};
  }
}

export function parseLookbackToMs(lookback: LookbackOption): number {
  const map: Record<LookbackOption, number> = {
    "1h": 60 * 60 * 1000,
    "6h": 6 * 60 * 60 * 1000,
    "12h": 12 * 60 * 60 * 1000,
    "24h": 24 * 60 * 60 * 1000,
    "3d": 3 * 24 * 60 * 60 * 1000,
    "7d": 7 * 24 * 60 * 60 * 1000,
    "30d": 30 * 24 * 60 * 60 * 1000,
  };

  return map[lookback] ?? map["24h"];
}

function cleanText(input?: string): string {
  if (!input) return "No summary available.";

  return input
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .replace(/&nbsp;/g, " ")
    .trim();
}

function summarize(input?: string): string {
  const text = cleanText(input);
  if (!text) return "No summary available.";

  const trimmed = text.length > 300 ? `${text.slice(0, 300).trim()}...` : text;
  return trimmed;
}

function isNewsLikeItem(item: Parser.Item): boolean {
  const title = (item.title ?? "").toLowerCase();
  const link = (item.link ?? "").toLowerCase();

  const blockedLinkPatterns = ["/events/", "/webinar", "/summit", "/conference", "/register", "/press-releases/"];
  const blockedTitlePatterns = ["webinar", "summit", "conference", "register now", "live at", "press release"];

  const blockedByLink = blockedLinkPatterns.some((p) => link.includes(p));
  const blockedByTitle = blockedTitlePatterns.some((p) => title.includes(p));

  return !(blockedByLink || blockedByTitle);
}

function titleFromLink(link: string): string {
  try {
    const { pathname } = new URL(link);
    const slug = pathname.split("/").filter(Boolean).pop() ?? "untitled";
    return slug
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  } catch {
    return "Untitled";
  }
}

function hasIocHeadingInHtml(html: string): boolean {
  const headingRegex = /<(h[1-6])[^>]*>\s*(?:<[^>]+>\s*)*(?:indicators?\s+of\s+compromise|iocs?)\s*(?:<[^>]+>\s*)*<\/\1>/i;
  return headingRegex.test(html);
}

function pickThumbnail(item: Parser.Item): string | undefined {
  const anyItem = item as Parser.Item & {
    enclosure?: { url?: string; type?: string };
    "media:content"?: { $?: { url?: string } }[];
    "media:thumbnail"?: { $?: { url?: string } }[];
    "media:group"?: { "media:content"?: { $?: { url?: string } }[] };
  };

  return (
    anyItem.enclosure?.url ||
    anyItem["media:thumbnail"]?.[0]?.$?.url ||
    anyItem["media:content"]?.[0]?.$?.url ||
    anyItem["media:group"]?.["media:content"]?.[0]?.$?.url
  );
}

export async function fetchCyberNews(lookback: LookbackOption): Promise<NewsItem[]> {
  const cutoff = Date.now() - parseLookbackToMs(lookback);

  const settled = await Promise.allSettled(
    FEEDS.map(async (feed) => {
      const parsed = await parser.parseURL(feed.url);

      return (parsed.items ?? [])
        .map((item): NewsItem | null => {
          const publishedRaw = item.isoDate || item.pubDate;
          const publishedAt = publishedRaw ? new Date(publishedRaw) : null;

          if (!item.link || !publishedAt) return null;
          if (publishedAt.getTime() < cutoff) return null;

          const normalizedTitle = (item.title ?? "").trim() || titleFromLink(item.link);
          const normalizedItem = {
            ...item,
            title: normalizedTitle,
          } as Parser.Item;

          if (!isNewsLikeItem(normalizedItem)) return null;

          return {
            id: `${feed.name}-${item.link}`,
            title: normalizedTitle,
            link: item.link,
            source: feed.name,
            publishedAt: publishedAt.toISOString(),
            thumbnail: pickThumbnail(item),
            summary: summarize(item.contentSnippet || item.content),
            hasIocSectionHint: false,
          };
        })
        .filter((entry): entry is NewsItem => entry !== null);
    })
  );

  const merged = settled
    .filter((s): s is PromiseFulfilledResult<NewsItem[]> => s.status === "fulfilled")
    .flatMap((s) => s.value);

  const deduped = Object.values(
    merged.reduce<Record<string, NewsItem>>((acc, item) => {
      acc[item.link] = item;
      return acc;
    }, {})
  ).sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime());

  const enriched = await Promise.all(
    deduped.map(async (item) => {
      const meta = await fetchPageMeta(item.link);
      const summary = item.summary === "No summary available." ? (meta.description ?? item.summary) : item.summary;
      return {
        ...item,
        thumbnail: meta.image ?? item.thumbnail ?? SOURCE_FALLBACK_THUMBNAILS[item.source],
        summary,
        hasIocSectionHint: Boolean(meta.hasIocHeading),
      };
    })
  );

  return enriched;
}
