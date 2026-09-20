/** @type {import('next').NextConfig} */
// STATIC_EXPORT=1 produces a fully static build (frontend/out) for the
// Cloudflare Workers static-assets deployment; `next dev` / `next start`
// keep the /api rewrite proxy to the local FastAPI backend. The production
// proxy lives in frontend/worker.js and mirrors this rewrite exactly.
const isStaticExport = process.env.STATIC_EXPORT === "1";

const nextConfig = isStaticExport
  ? { output: "export" }
  : {
      async rewrites() {
        // Proxy API calls to the FastAPI backend so the browser talks to one
        // origin during the demo; override with BACKEND_URL if needed.
        const backend = process.env.BACKEND_URL || "http://127.0.0.1:8000";
        return [{ source: "/api/:path*", destination: `${backend}/:path*` }];
      },
    };

export default nextConfig;
