"""Security gateway (Phase 2) — the single enforcement boundary."""

from app.gateway.security_gateway import GatewayRequest, GatewayResult, SecurityGateway

__all__ = ["GatewayRequest", "GatewayResult", "SecurityGateway"]
