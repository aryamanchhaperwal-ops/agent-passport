// Cloudflare Worker for the AgentPassport dashboard (production only).
// Serves the static Next.js export from the ASSETS binding and forwards
// /api/* to the FastAPI backend Worker via a service binding — mirroring
// next.config.mjs's dev rewrite so the browser keeps talking to a single
// origin. This proxy adds no security logic: every request still hits the
// backend Security Gateway.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      if (!env.API) {
        return new Response("API service binding is not configured", {
          status: 500,
        });
      }
      const target = new URL(
        url.pathname.replace(/^\/api/, "") + url.search,
        "https://agentpassport.internal",
      );
      return env.API.fetch(new Request(target, request));
    }
    return env.ASSETS.fetch(request);
  },
};
