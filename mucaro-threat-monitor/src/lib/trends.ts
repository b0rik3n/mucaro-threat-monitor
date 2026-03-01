import { fetchCyberNews, getSourceWeight, type LookbackOption, type NewsItem, parseLookbackToMs } from "@/lib/news";

export type TrendStage = "emerging" | "rising" | "hot" | "cooling";

export type TrendItem = {
  id: string;
  label: string;
  score: number;
  stage: TrendStage;
  mentions24h: number;
  weightedMentions24h: number;
  mentionsPrev24h: number;
  uniqueSources24h: number;
  velocityDeltaPct: number;
  latestSeenAt: string;
  evidence: {
    cveCount: number;
    exploitSignalCount: number;
    kevSignalCount: number;
  };
  sources: string[];
};

type TopicDefinition = {
  id: string;
  label: string;
  keywords: string[];
};

const STATIC_TOPICS: TopicDefinition[] = [
  { id: "ransomware", label: "Ransomware", keywords: ["ransomware", "locker", "extortion"] },
  { id: "phishing", label: "Phishing", keywords: ["phishing", "smishing", "vishing", "social engineering"] },
  { id: "zero-day", label: "Zero-Day Exploits", keywords: ["zero-day", "0-day", "in-the-wild", "weaponized"] },
  { id: "supply-chain", label: "Supply Chain Attacks", keywords: ["supply chain", "dependency", "third-party"] },
  { id: "cloud", label: "Cloud Security", keywords: ["aws", "azure", "gcp", "cloud", "kubernetes"] },
  { id: "identity", label: "Identity & Access", keywords: ["identity", "iam", "sso", "oauth", "mfa", "entra", "okta"] },
  { id: "malware", label: "Malware Campaigns", keywords: ["malware", "trojan", "botnet", "backdoor", "loader"] },
  { id: "apt", label: "Threat Actors / APT", keywords: ["apt", "threat actor", "campaign", "nation-state"] },
];

const EXPLOIT_SIGNAL_KEYWORDS = ["exploit", "weaponized", "in-the-wild", "actively exploited", "rce"];
const KEV_SIGNAL_KEYWORDS = ["known exploited", "kev", "cisa advisory", "cisa adds", "catalog"];

const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;

function extractCves(text: string): string[] {
  const matches = text.match(CVE_REGEX) ?? [];
  return Array.from(new Set(matches.map((v) => v.toUpperCase())));
}

function getText(item: NewsItem): string {
  return `${item.title} ${item.summary}`.toLowerCase();
}

function classifyStage(score: number, mentions24h: number, mentionsPrev24h: number): TrendStage {
  if (mentions24h <= 0) return "cooling";
  if (score >= 16 || (mentions24h >= 5 && mentions24h >= mentionsPrev24h * 1.4)) return "hot";
  if (score >= 10) return "rising";
  if (mentionsPrev24h > mentions24h) return "cooling";
  return "emerging";
}

function buildDynamicCveTopics(items: NewsItem[]): TopicDefinition[] {
  const counts = new Map<string, number>();

  for (const item of items) {
    const cves = extractCves(`${item.title} ${item.summary}`);
    for (const cve of cves) {
      counts.set(cve, (counts.get(cve) ?? 0) + 1);
    }
  }

  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([cve]) => ({
      id: cve.toLowerCase(),
      label: cve,
      keywords: [cve.toLowerCase()],
    }));
}

export async function buildTrendingTopics(lookback: LookbackOption = "7d"): Promise<TrendItem[]> {
  const items = await fetchCyberNews(lookback);
  const now = Date.now();
  const window24hMs = parseLookbackToMs("24h");

  const topicDefs = [...STATIC_TOPICS, ...buildDynamicCveTopics(items)];

  const topicMap = new Map<string, TrendItem>();

  for (const topic of topicDefs) {
    topicMap.set(topic.id, {
      id: topic.id,
      label: topic.label,
      score: 0,
      stage: "emerging",
      mentions24h: 0,
      weightedMentions24h: 0,
      mentionsPrev24h: 0,
      uniqueSources24h: 0,
      velocityDeltaPct: 0,
      latestSeenAt: new Date(0).toISOString(),
      evidence: {
        cveCount: 0,
        exploitSignalCount: 0,
        kevSignalCount: 0,
      },
      sources: [],
    });
  }

  const sourcesByTopic = new Map<string, Set<string>>();

  for (const item of items) {
    const text = getText(item);
    const itemTime = new Date(item.publishedAt).getTime();
    const age = now - itemTime;
    const isInLast24h = age <= window24hMs;
    const isInPrev24h = age > window24hMs && age <= 2 * window24hMs;

    for (const topic of topicDefs) {
      if (!topic.keywords.some((kw) => text.includes(kw))) continue;

      const trend = topicMap.get(topic.id);
      if (!trend) continue;

      const sourceWeight = getSourceWeight(item.source);

      if (item.publishedAt > trend.latestSeenAt) {
        trend.latestSeenAt = item.publishedAt;
      }

      if (isInLast24h) {
        trend.mentions24h += 1;
        trend.weightedMentions24h += sourceWeight;
        if (!sourcesByTopic.has(topic.id)) sourcesByTopic.set(topic.id, new Set<string>());
        sourcesByTopic.get(topic.id)?.add(item.source);
      } else if (isInPrev24h) {
        trend.mentionsPrev24h += 1;
      }

      const cveCount = extractCves(`${item.title} ${item.summary}`).length;
      trend.evidence.cveCount += cveCount;

      if (EXPLOIT_SIGNAL_KEYWORDS.some((kw) => text.includes(kw))) {
        trend.evidence.exploitSignalCount += 1;
      }

      const hasKevSignal = KEV_SIGNAL_KEYWORDS.some((kw) => text.includes(kw));
      if (item.source === "CISA Alerts" || hasKevSignal) {
        trend.evidence.kevSignalCount += 1;
      }
    }
  }

  const trends = Array.from(topicMap.values())
    .map((trend) => {
      trend.uniqueSources24h = sourcesByTopic.get(trend.id)?.size ?? 0;
      const baseline = Math.max(trend.mentionsPrev24h, 1);
      trend.velocityDeltaPct = Math.round(((trend.mentions24h - trend.mentionsPrev24h) / baseline) * 100);

      trend.score =
        trend.uniqueSources24h * 2 +
        Math.round(trend.weightedMentions24h) +
        trend.evidence.exploitSignalCount * 5 +
        trend.evidence.kevSignalCount * 6;

      trend.stage = classifyStage(trend.score, trend.mentions24h, trend.mentionsPrev24h);
      trend.sources = Array.from(sourcesByTopic.get(trend.id) ?? []).slice(0, 5);
      return trend;
    })
    .filter((trend) => trend.mentions24h > 0 || trend.mentionsPrev24h > 0)
    .sort((a, b) => b.score - a.score || b.mentions24h - a.mentions24h)
    .slice(0, 12);

  return trends;
}
