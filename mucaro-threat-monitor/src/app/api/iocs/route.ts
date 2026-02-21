import { NextRequest, NextResponse } from "next/server";
import { extractIocsFromArticle } from "@/lib/ioc";

export async function POST(req: NextRequest) {
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
