import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === "production";

const strictCsp = "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; connect-src 'self' https:; font-src 'self' https: data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const devCsp = "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' https: ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const enforcedCsp = isProd ? strictCsp : devCsp;
const reportOnlyCsp = strictCsp;

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Content-Security-Policy", value: enforcedCsp },
  { key: "Content-Security-Policy-Report-Only", value: reportOnlyCsp },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
