import { NextRequest, NextResponse } from "next/server";
import { extractIocsFromArticle } from "@/lib/ioc";
import { enforceRateLimit } from "@/lib/api-guards";

export async function POST(req: NextRequest) {
  const limit = enforceRateLimit({ req, keyPrefix: "iocs", max: 20, windowMs: 60_000 });
  if (!limit.ok) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again shortly." },
      { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } }
    );
  }

  try {
    const body = (await req.json()) as { url?: string };
    const url = body?.url;

    if (!url) {
      return NextResponse.json({ error: "Missing url" }, { status: 400 });
    }

    const result = await extractIocsFromArticle(url);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      {
        error: "IOC extraction failed",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}
