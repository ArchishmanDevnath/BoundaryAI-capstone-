import type { NextConfig } from "next";

const apiUrl = process.env.BG_API_URL ?? "http://127.0.0.1:8000";

const config: NextConfig = {
  // The browser only talks to this origin, and Next forwards API calls to the local backend.
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${apiUrl}/api/v1/:path*` }];
  },
};

export default config;
