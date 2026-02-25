import { NextRequest, NextResponse } from "next/server";

function buildProdCsp(nonce: string): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' https: data:",
    "font-src 'self' https: data:",
    "connect-src 'self' https:",
    "upgrade-insecure-requests",
  ].join("; ");
}

function buildDevCsp(): string {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' https: data:",
    "font-src 'self' https: data:",
    "connect-src 'self' https: ws: wss:",
  ].join("; ");
}

export function proxy(request: NextRequest) {
  const isProd = process.env.NODE_ENV === "production";
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  const csp = isProd ? buildProdCsp(nonce) : buildDevCsp();
  response.headers.set("Content-Security-Policy", csp);

  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
