import type { NextConfig } from "next";

const enforcedCsp = "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; connect-src 'self' https:; font-src 'self' https: data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

const reportOnlyCsp = enforcedCsp;

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
