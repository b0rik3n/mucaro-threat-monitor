import { NextRequest, NextResponse } from "next/server";
import { fetchCyberNews, type LookbackOption } from "@/lib/news";

const VALID_LOOKBACKS = new Set<LookbackOption>(["1h", "6h", "12h", "24h", "3d", "7d"]);

export async function GET(req: NextRequest) {
  const lookbackParam = req.nextUrl.searchParams.get("lookback") ?? "24h";
  const lookback = VALID_LOOKBACKS.has(lookbackParam as LookbackOption)
    ? (lookbackParam as LookbackOption)
    : "24h";

  try {
    const items = await fetchCyberNews(lookback);

    return NextResponse.json({
      lookback,
      count: items.length,
      items,
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
