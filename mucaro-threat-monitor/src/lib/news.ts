import Parser from "rss-parser";

export type LookbackOption = "1h" | "6h" | "12h" | "24h" | "3d" | "7d";

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

const FEEDS = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { name: "CISA Alerts", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "Dark Reading", url: "https://www.darkreading.com/rss.xml" },
  { name: "The DFIR Report", url: "https://thedfirreport.com/feed/" },
  { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/" },
  { name: "Koi Security", url: "https://www.koi.ai/blog/rss.xml" },
];

const parser = new Parser({
  timeout: 10000,
  headers: {
    "User-Agent": "SOC-News-Scout/1.0",
  },
});

const ogCache = new Map<string, string | null>();
const iocHintCache = new Map<string, boolean>();

function extractMetaImage(html: string): string | null {
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

  return null;
}

async function fetchOgImage(url: string): Promise<string | undefined> {
  if (ogCache.has(url)) {
    const cached = ogCache.get(url);
    return cached ?? undefined;
  }

  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "SOC-News-Scout/1.0" },
      signal: AbortSignal.timeout(7000),
    });

    if (!response.ok) {
      ogCache.set(url, null);
      return undefined;
    }

    const html = await response.text();
    const image = extractMetaImage(html);
    ogCache.set(url, image ?? null);
    return image ?? undefined;
  } catch {
    ogCache.set(url, null);
    return undefined;
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

function hasIocHeadingInHtml(html: string): boolean {
  const headingRegex = /<(h[1-6])[^>]*>\s*(?:<[^>]+>\s*)*(?:indicators?\s+of\s+compromise|iocs?)\s*(?:<[^>]+>\s*)*<\/\1>/i;
  return headingRegex.test(html);
}

async function detectIocSectionFromArticle(url: string): Promise<boolean> {
  if (iocHintCache.has(url)) return iocHintCache.get(url) ?? false;

  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "SOC-News-Scout/1.0" },
      signal: AbortSignal.timeout(8000),
    });

    if (!response.ok) {
      return false;
    }

    const html = await response.text();
    const found = hasIocHeadingInHtml(html);
    if (found) iocHintCache.set(url, true);
    return found;
  } catch {
    return false;
  }
}

function isNewsLikeItem(item: Parser.Item): boolean {
  const title = (item.title ?? "").toLowerCase();
  const link = (item.link ?? "").toLowerCase();

  const blockedLinkPatterns = ["/events/", "/webinar", "/summit", "/conference", "/register"];
  const blockedTitlePatterns = ["webinar", "summit", "conference", "register now", "live at"];

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
      const ogImage = item.thumbnail ? undefined : await fetchOgImage(item.link);
      const verifiedIocHint = await detectIocSectionFromArticle(item.link);

      return {
        ...item,
        thumbnail: ogImage ?? item.thumbnail,
        hasIocSectionHint: verifiedIocHint,
      };
    })
  );

  return enriched;
}
