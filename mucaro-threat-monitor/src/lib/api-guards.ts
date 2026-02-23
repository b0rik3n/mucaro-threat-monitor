import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { NextRequest } from "next/server";

type RateEntry = { count: number; resetAt: number };
const rateStore = new Map<string, RateEntry>();

const TRUSTED_IOC_HOST_SUFFIXES = [
  "thehackernews.com",
  "bleepingcomputer.com",
  "krebsonsecurity.com",
  "cisa.gov",
  "darkreading.com",
  "cybersecuritydive.com",
  "securityweek.com",
  "thedfirreport.com",
  "paloaltonetworks.com",
  "koi.ai",
] as const;

const IOC_EXTRA_ALLOWED_HOSTS = (process.env.IOC_EXTRA_ALLOWED_HOSTS ?? "")
  .split(",")
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);

const DNS_LOOKUP_TIMEOUT_MS = 2000;

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

function isAllowedIocHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  const allowlist = [...TRUSTED_IOC_HOST_SUFFIXES, ...IOC_EXTRA_ALLOWED_HOSTS];
  return allowlist.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;

  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;

  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true; // ULA fc00::/7
  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true; // fe80::/10
  return false;
}

function isPrivateOrLocalIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true;
}

async function lookupWithTimeout(hostname: string): Promise<{ address: string }[]> {
  const lookupPromise = lookup(hostname, { all: true, verbatim: true });
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error("DNS lookup timed out")), DNS_LOOKUP_TIMEOUT_MS);
  });

  return (await Promise.race([lookupPromise, timeoutPromise])) as { address: string }[];
}

export async function validateIocArticleUrl(rawUrl: string): Promise<{ ok: true; url: URL } | { ok: false; reason: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "Invalid url" };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, reason: "Only http/https URLs are allowed" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (["localhost", "127.0.0.1", "::1"].includes(hostname) || hostname.endsWith(".local")) {
    return { ok: false, reason: "Local/internal hosts are not allowed" };
  }

  if (!isAllowedIocHost(hostname)) {
    return { ok: false, reason: "URL host is not in the IOC allowlist" };
  }

  try {
    const answers = await lookupWithTimeout(hostname);
    if (!answers.length) {
      return { ok: false, reason: "Unable to resolve URL host" };
    }

    for (const record of answers) {
      if (isPrivateOrLocalIp(record.address)) {
        return { ok: false, reason: "Resolved host points to a private/internal IP" };
      }
    }
  } catch {
    return { ok: false, reason: "Unable to resolve URL host" };
  }

  return { ok: true, url: parsed };
}
