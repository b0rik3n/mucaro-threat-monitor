import { NextRequest, NextResponse } from "next/server";
import { enforceRateLimit } from "@/lib/api-guards";
import { buildTrendingTopics } from "@/lib/trends";
import type { LookbackOption } from "@/lib/news";

const VALID_LOOKBACKS = new Set<LookbackOption>(["24h", "3d", "7d", "30d"]);
const TRENDS_CACHE_TTL_MS = 5 * 60 * 1000;

const trendsCache = new Map<LookbackOption, { expiresAt: number; payload: unknown }>();

export async function GET(req: NextRequest) {
  const lookbackParam = req.nextUrl.searchParams.get("lookback") ?? "7d";
  const lookback = VALID_LOOKBACKS.has(lookbackParam as LookbackOption)
    ? (lookbackParam as LookbackOption)
    : "7d";

  const limit = enforceRateLimit({ req, keyPrefix: "trends", max: 30, windowMs: 60_000 });
  if (!limit.ok) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } }
    );
  }

  const now = Date.now();
  const cached = trendsCache.get(lookback);
  if (cached && now < cached.expiresAt) {
    return NextResponse.json(cached.payload, {
      headers: { "Cache-Control": "public, max-age=60" },
    });
  }

  try {
    const trends = await buildTrendingTopics(lookback);

    const payload = {
      lookback,
      generatedAt: new Date().toISOString(),
      count: trends.length,
      trends,
    };

    trendsCache.set(lookback, {
      expiresAt: now + TRENDS_CACHE_TTL_MS,
      payload,
    });

    return NextResponse.json(payload, {
      headers: { "Cache-Control": "public, max-age=60" },
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Failed to build trend data.",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}
