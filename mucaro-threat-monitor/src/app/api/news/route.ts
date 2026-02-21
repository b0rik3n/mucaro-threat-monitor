import { NextRequest, NextResponse } from "next/server";
import { fetchCyberNews, type LookbackOption } from "@/lib/news";
import { enforceRateLimit } from "@/lib/api-guards";

const VALID_LOOKBACKS = new Set<LookbackOption>(["1h", "6h", "12h", "24h", "3d", "7d"]);
const NEWS_CACHE_TTL_MS = 3 * 60 * 1000;
const newsCache = new Map<LookbackOption, { expiresAt: number; payload: unknown }>();

export async function GET(req: NextRequest) {
  const lookbackParam = req.nextUrl.searchParams.get("lookback") ?? "24h";
  const lookback = VALID_LOOKBACKS.has(lookbackParam as LookbackOption)
    ? (lookbackParam as LookbackOption)
    : "24h";

  const limit = enforceRateLimit({ req, keyPrefix: "news", max: 60, windowMs: 60_000 });
  if (!limit.ok) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } }
    );
  }

  const cached = newsCache.get(lookback);
  const now = Date.now();
  if (cached && now < cached.expiresAt) {
    return NextResponse.json(cached.payload, {
      headers: { "Cache-Control": "public, max-age=30" },
    });
  }

  try {
    const items = await fetchCyberNews(lookback);

    const payload = {
      lookback,
      count: items.length,
      items,
    };

    newsCache.set(lookback, { expiresAt: now + NEWS_CACHE_TTL_MS, payload });

    return NextResponse.json(payload, {
      headers: { "Cache-Control": "public, max-age=30" },
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to fetch cybersecurity news.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}
