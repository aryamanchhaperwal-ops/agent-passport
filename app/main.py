"""FastAPI application: Phase 1 security core + Phase 2 agent runtime.

This is a LOCAL PROTOTYPE: no authentication, no persistence, no TLS. It
binds to localhost in all demo instructions and must not be exposed to
untrusted networks.

Phase 1 endpoints (unchanged contract):
  GET  /health   -> liveness + build info.
  POST /verify   -> run the deterministic verifier over a submitted chain.

Phase 2 endpoints:
  POST /agents/run       -> planner plans a task, executor proposes, the
                            SecurityGateway authorizes/executes.
  POST /tools/execute    -> request a tool call. ALWAYS passes through the
                            SecurityGateway; there is no direct execution
                            endpoint anywhere in this application.
  GET  /audit            -> the in-memory audit event log.
  GET  /agents           -> public descriptions of the three agents.
  GET  /security/status  -> composition and enforcement status.

PROTOTYPE CAVEAT: /verify accepts a client-supplied `now`; a real
deployment must use its own clock. API-key material, if any LLM provider
needs it, is read from environment variables only.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.agents.runtime import AgentRuntime
from app.audit import AuditStore, tool_request_event
from app.core.delegation import InMemoryRevocationRegistry, RevocationRegistry
from app.core.identity import AgentIdentity
from app.core.models import VerifyRequest
from app.core.policy import TrustAnchor
from app.core.verifier import VerificationOutcome, verify_chain
from app.demo_state import DemoState
from app.gateway.security_gateway import SecurityGateway
from app.tools.registry import ToolRegistry, default_registry


# Request models live at module level so FastAPI can resolve their
# annotations (nested classes inside the factory are not visible to
# get_type_hints and would be misread as query parameters).
class AgentRunRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4000)


class ToolExecuteRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict = Field(default_factory=dict)


def create_app(
    anchor: TrustAnchor,
    revocation_registry: RevocationRegistry,
    *,
    runtime: AgentRuntime | None = None,
    registry: ToolRegistry | None = None,
    audit_store: AuditStore | None = None,
) -> FastAPI:
    """Build the app bound to ONE trust anchor and ONE enforcement state.

    `anchor` and `revocation_registry` keep their Phase 1 positional
    signature for backwards compatibility. The Phase 2 runtime shares the
    same anchor/revocation/audit objects, so there is exactly one
    authority and one authorization path across every endpoint.
    """
    app = FastAPI(
        title="AgentPassport Security Core",
        version="0.2.0",
        description=(
            "Local reference implementation of deterministic cryptographic "
            "authorization for AI-agent delegation. Local testbed only — "
            "no authentication, no persistence."
        ),
    )

    registry = registry or default_registry()
    audit_store = audit_store or AuditStore()
    runtime = runtime or AgentRuntime.bootstrap(
        anchor=anchor, revocations=revocation_registry, audit=audit_store,
        registry=registry,
    )
    if runtime.anchor is not anchor or runtime.revocations is not revocation_registry:
        raise ValueError(
            "runtime must share the app's anchor and revocation registry — "
            "there must be exactly one authority"
        )
    gateway = runtime.gateway

    # ------------------------------------------------------------------
    # Phase 1 surface (unchanged)
    # ------------------------------------------------------------------
    class HealthResponse(BaseModel):
        status: str
        version: str
        anchor_agent_id: str

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        """Liveness probe. Exposes no security-relevant information."""
        return HealthResponse(
            status="ok", version=app.version, anchor_agent_id=anchor.agent_id
        )

    @app.post("/verify")
    def verify(request: VerifyRequest) -> dict:
        """Run the deterministic verifier over a delegation chain.

        The response is always a structured decision — ALLOW with effective
        scopes, or DENY with a machine-readable reason. This endpoint decides
        nothing itself; it only fronts `core.verifier.verify_chain`.
        """
        outcome: VerificationOutcome = verify_chain(
            anchor=anchor,
            chain=request.chain,
            requested_scope=request.requested_scope,
            requesting_agent_id=request.requesting_agent_id,
            revocation_registry=revocation_registry,
            now=request.now,
        )
        return {
            "decision": outcome.decision,
            "reason": outcome.reason,
            "detail": outcome.detail,
            "agent": outcome.agent,
            "requested_scope": outcome.requested_scope,
            "effective_scopes": outcome.effective_scopes,
        }

    # ------------------------------------------------------------------
    # Phase 2 surface
    # ------------------------------------------------------------------
    @app.post("/agents/run")
    def agents_run(request: AgentRunRequest) -> dict:
        """Plan a task with the LLM and submit the executor's proposal to
        the SecurityGateway. The LLM only proposes; the gateway decides."""
        return runtime.run_planned_task(request.task)

    @app.post("/tools/execute")
    def tools_execute(request: ToolExecuteRequest) -> dict:
        """Request a tool execution. ALWAYS via the SecurityGateway.

        The chain is supplied by the runtime's credential custodian for the
        named agent; the caller cannot present an arbitrary chain here.
        """
        try:
            chain = runtime.chain_for(request.agent_id)
        except KeyError:
            audit_store.record(tool_request_event(
                agent=request.agent_id, tool=request.tool_name,
                requested_scope=None, decision="DENY",
                reason="UNKNOWN_AGENT", executed=False, detail=None,
            ))
            raise HTTPException(status_code=404, detail="unknown agent")
        result = gateway.authorize_and_execute(
            agent_id=request.agent_id,
            chain=chain,
            tool_name=request.tool_name,
            arguments=request.arguments,
        )
        return result.model_dump()

    @app.get("/audit")
    def get_audit() -> dict:
        """The in-memory audit event log (newest last)."""
        return {
            "count": audit_store.count(),
            "events": [e.model_dump(mode="json") for e in audit_store.all_events()],
        }

    @app.get("/agents")
    def get_agents() -> dict:
        """Public (non-secret) descriptions of the agents."""
        return {"agents": runtime.agents_info()}

    @app.get("/security/status")
    def security_status() -> dict:
        """Composition and enforcement status. No secrets are exposed."""
        return {
            "anchor_agent_id": anchor.agent_id,
            "llm_provider": runtime.provider.name,
            "llm_provider_is_mock": runtime.provider.name == "mock",
            "tools": registry.names(),
            "agents": [a["agent_id"] for a in runtime.agents_info()],
            "revocation_registry": type(revocation_registry).__name__,
            "gateway_decisions": gateway.decision_count,
            "audit_events": audit_store.count(),
            "authorization_path": (
                "request -> SecurityGateway -> core.verifier.verify_chain "
                "-> ALLOW ? tool : never"
            ),
        }

    # ------------------------------------------------------------------
    # Phase 3 demo surface (dashboard). Every button in the UI hits one of
    # these; each one routes through the SAME runtime/gateway/verifier as
    # the endpoints above. The UI renders results; it never computes them.
    # ------------------------------------------------------------------
    demo_holder = {"state": DemoState()}

    def _demo() -> DemoState:
        return demo_holder["state"]

    @app.get("/demo/state")
    def demo_state() -> dict:
        """Full dashboard state snapshot (agents, links, stats, events)."""
        return _demo().snapshot()

    @app.post("/demo/legitimate")
    def demo_legitimate() -> dict:
        """Agent C -> calendar.read through the real gateway."""
        return _demo().run_legitimate()

    @app.post("/demo/attack/scope-escalation")
    def demo_scope_escalation() -> dict:
        """Agent C -> payments.transfer through the real gateway."""
        return _demo().run_scope_escalation()

    @app.post("/demo/attack/signature-tampering")
    def demo_signature_tampering() -> dict:
        """Tamper with C's signed credential, submit through the real
        gateway; the Phase 1 verifier detects the modification."""
        return _demo().run_signature_tampering()

    @app.post("/demo/revoke-specialist")
    def demo_revoke_specialist() -> dict:
        """Revoke Agent B's delegation via the existing registry."""
        return _demo().revoke_specialist()

    @app.post("/demo/reset")
    def demo_reset() -> dict:
        """Rebuild the entire demo world (fresh anchor/chain/audit)."""
        demo_holder["state"] = DemoState()
        return demo_holder["state"].snapshot()

    return app


# ---------------------------------------------------------------------------
# Local testbed singletons.
#
# The anchor key is generated at process start (never committed, never
# logged); revocations and audit events are in-memory and die with the
# process — exactly right for a local testbed.
#
# Creation is deferred to the first ASGI call instead of module import:
# the Cloudflare Workers Python runtime rejects Ed25519 key generation
# during deploy-time validation (which imports this module) but supports
# it at request time. Locally this behaves identically.
# ---------------------------------------------------------------------------
ANCHOR: TrustAnchor | None = None
REVOCATION_REGISTRY: InMemoryRevocationRegistry | None = None


def _bootstrap_singletons() -> tuple[TrustAnchor, InMemoryRevocationRegistry]:
    """Create THE one trust anchor + revocation registry, idempotently."""
    global ANCHOR, REVOCATION_REGISTRY
    if ANCHOR is None or REVOCATION_REGISTRY is None:
        ANCHOR = TrustAnchor(AgentIdentity.generate(agent_id="human:root"))
        REVOCATION_REGISTRY = InMemoryRevocationRegistry()
    return ANCHOR, REVOCATION_REGISTRY


class _LazyApp:
    """ASGI wrapper that builds the real app on the first request.

    Keeps `from app.main import app` and `uvicorn app.main:app` working
    while moving trust-anchor key generation (and everything constructed
    with it) out of module import. The single-threaded event loop makes
    the lazy build race-free.
    """

    def __init__(self) -> None:
        self._inner: FastAPI | None = None

    def _build(self) -> FastAPI:
        if self._inner is None:
            anchor, revocations = _bootstrap_singletons()
            self._inner = create_app(anchor, revocations)
        return self._inner

    async def __call__(self, scope, receive, send) -> None:
        await self._build()(scope, receive, send)


app = _LazyApp()

__all__ = ["app", "create_app", "ANCHOR", "REVOCATION_REGISTRY"]
