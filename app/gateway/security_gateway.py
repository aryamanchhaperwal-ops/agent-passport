"""The SecurityGateway — the single enforcement boundary of Phase 2.

There is exactly ONE authorization path in this system:

    request -> gateway -> app.core.verifier.verify_chain (Phase 1)
            -> ALLOW ? registry.execute() : never execute

The gateway adds no cryptographic logic of its own. It:

  1. validates the request shape,
  2. resolves the tool and its REQUIRED scope from the tool registry —
     the requesting agent's (or the LLM's) claimed scope is advisory and
     NEVER consulted for authorization,
  3. hands the presented delegation chain to the Phase 1 verifier,
  4. executes the tool ONLY on ALLOW, and
  5. records one audit event per request, then returns a structured result.

Unknown tools, unknown agents, and malformed requests fail closed: DENY,
no execution. Every `authorize_and_execute` call touches the verifier
exactly once.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.audit import AuditStore, tool_request_event
from app.core.models import Delegation, Scope, utc_now
from app.core.verifier import VerificationOutcome, verify_chain
from app.tools.registry import ToolRegistry
from app.tools.base import ToolResult
from app.core.policy import TrustAnchor

MAX_ARGUMENTS_BYTES = 16_384


class GatewayRequest(BaseModel):
    """A proposed tool call. Everything here is a CLAIM; none of it is
    trusted for authorization — the chain + verifier decide."""

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    chain: list[Delegation]
    arguments: dict = Field(default_factory=dict)
    requested_scope: str | None = None  # advisory only; registry scope rules


class GatewayResult(BaseModel):
    """Structured, machine-readable outcome of one gateway round-trip."""

    model_config = ConfigDict(frozen=True)

    decision: str            # "ALLOW" | "DENY"
    agent: str | None
    tool: str | None
    scope: str | None
    reason: str | None
    detail: str | None
    executed: bool
    tool_result: ToolResult | None = None
    effective_scopes: list[str] = Field(default_factory=list)

    def audit_fields(self) -> dict:
        return {
            "agent": self.agent,
            "tool": self.tool,
            "requested_scope": self.scope,
            "decision": self.decision,
            "reason": self.reason,
            "executed": self.executed,
        }


class SecurityGateway:
    """Front door for every protected tool call. Fail closed by design."""

    def __init__(
        self,
        anchor: TrustAnchor,
        registry: ToolRegistry,
        audit_store: AuditStore,
        revocation_registry=None,
        max_clock_skew=None,
    ) -> None:
        from datetime import timedelta

        self._anchor = anchor
        self._registry = registry
        self._audit = audit_store
        self._revocation = revocation_registry
        self._max_clock_skew = max_clock_skew or timedelta(minutes=5)
        self._decision_count = 0

    @property
    def decision_count(self) -> int:
        return self._decision_count

    def authorize_and_execute(
        self,
        agent_id: str,
        chain: list[Delegation],
        tool_name: str,
        arguments: dict | None = None,
        requested_scope: str | None = None,
        now=None,
    ) -> GatewayResult:
        """Authorize (deterministically) then — only on ALLOW — execute."""
        import json

        from pydantic import ValidationError

        if arguments is None:
            arguments = {}  # documented default; not a malformed request
        outcome: VerificationOutcome | None = None
        scope_str: str | None = requested_scope
        tool_exists = self._registry.get(tool_name) is not None
        required_scope = self._registry.required_scope(tool_name)

        try:
            # ---- 1. shape validation (fail closed on anything odd) ----
            if not isinstance(agent_id, str) or not agent_id:
                return self._deny_no_audit(
                    "INVALID_REQUEST", "agent_id must be a non-empty string",
                    agent=None, tool=tool_name, scope=required_scope,
                )
            if not isinstance(arguments, dict):
                return self._deny_no_audit(
                    "INVALID_REQUEST", "arguments must be an object",
                    agent=agent_id, tool=tool_name, scope=required_scope,
                )
            try:
                args_json = json.dumps(arguments, allow_nan=False)
            except (TypeError, ValueError):
                return self._deny_no_audit(
                    "INVALID_REQUEST", "arguments are not JSON-serializable",
                    agent=agent_id, tool=tool_name, scope=required_scope,
                )
            if len(args_json.encode("utf-8")) > MAX_ARGUMENTS_BYTES:
                return self._deny_no_audit(
                    "INVALID_REQUEST", "arguments exceed size limit",
                    agent=agent_id, tool=tool_name, scope=required_scope,
                )

            # ---- 2. tool must exist; REQUIRED scope comes from the registry ----
            if not tool_exists:
                return self._deny_and_audit(
                    reason="UNKNOWN_TOOL", detail=f"no registered tool {tool_name!r}",
                    agent=agent_id, tool=tool_name, scope=None,
                    delegation_id=None,
                )
            assert required_scope is not None
            scope_str = required_scope

            # ---- 3. THE authorization decision (Phase 1 verifier, once) ----
            outcome = verify_chain(
                self._anchor,
                chain,
                Scope.parse(required_scope),
                agent_id,
                revocation_registry=self._revocation,
                now=now,
                max_clock_skew=self._max_clock_skew,
            )
            self._decision_count += 1

            if outcome.decision != "ALLOW":
                return self._deny_and_audit(
                    reason=outcome.reason or "DENIED",
                    detail=outcome.detail,
                    agent=agent_id, tool=tool_name, scope=required_scope,
                    delegation_id=chain[-1].delegation_id if chain else None,
                )

            # ---- 4. ALLOW -> and ONLY now, execute ----
            tool_result = self._registry.execute(tool_name, arguments)
            result = GatewayResult(
                decision="ALLOW", agent=agent_id, tool=tool_name,
                scope=required_scope, reason="AUTHORIZED", detail=None,
                executed=True, tool_result=tool_result,
                effective_scopes=outcome.effective_scopes,
            )
            self._audit.record(tool_request_event(
                agent=agent_id, tool=tool_name, requested_scope=required_scope,
                decision="ALLOW", reason="AUTHORIZED", executed=True,
                delegation_id=chain[-1].delegation_id if chain else None,
                detail=None,
            ))
            return result

        except (ValueError, ValidationError) as exc:
            # e.g. Scope.parse failure, malformed chain elements
            return self._deny_and_audit(
                reason="INVALID_REQUEST",
                detail=f"request rejected during validation: {exc}",
                agent=agent_id if isinstance(agent_id, str) else None,
                tool=tool_name, scope=scope_str,
                delegation_id=None,
            )

    # ------------------------------------------------------------------
    def _deny_no_audit(self, reason: str, detail: str, *, agent, tool, scope) -> GatewayResult:
        """Deny for requests so malformed that no meaningful event exists."""
        return GatewayResult(
            decision="DENY", agent=agent, tool=tool, scope=scope,
            reason=reason, detail=detail, executed=False,
        )

    def _deny_and_audit(
        self, *, reason: str, detail: str | None, agent, tool, scope, delegation_id,
    ) -> GatewayResult:
        """Deny + record the event. Tool code is never reached."""
        self._decision_count += 1
        self._audit.record(tool_request_event(
            agent=agent, tool=tool, requested_scope=scope,
            decision="DENY", reason=reason, executed=False,
            delegation_id=delegation_id, detail=detail,
        ))
        return GatewayResult(
            decision="DENY", agent=agent, tool=tool, scope=scope,
            reason=reason, detail=detail, executed=False,
        )

    def __init_subclass__(cls, **kwargs):  # pragma: no cover
        raise TypeError("SecurityGateway must not be subclassed to avoid bypasses")
