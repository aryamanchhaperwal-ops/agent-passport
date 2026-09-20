"""Cloudflare Workers entrypoint for the AgentPassport backend.

This is a deployment adapter only: it wraps the EXISTING FastAPI application
(`app.main.app`) in the Workers ASGI runtime SDK. No security logic lives
here — the Phase 1 verifier and the Phase 2 SecurityGateway remain the single
authoritative authorization path, unchanged, on Cloudflare the same as locally.
"""

from workers import asgi

from app.main import app

Default = asgi.entrypoint(app)
