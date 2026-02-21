import { NextRequest } from "next/server";

type RateEntry = { count: number; resetAt: number };
const rateStore = new Map<string, RateEntry>();

export function getClientIp(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "unknown";
}

export function enforceRateLimit(params: {
  req: NextRequest;
  keyPrefix: string;
  max: number;
  windowMs: number;
}): { ok: true } | { ok: false; retryAfterSec: number } {
  const ip = getClientIp(params.req);
  const key = `${params.keyPrefix}:${ip}`;
  const now = Date.now();
  const current = rateStore.get(key);

  if (!current || now >= current.resetAt) {
    rateStore.set(key, { count: 1, resetAt: now + params.windowMs });
    return { ok: true };
  }

  if (current.count >= params.max) {
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
  }

  current.count += 1;
  rateStore.set(key, current);
  return { ok: true };
}
