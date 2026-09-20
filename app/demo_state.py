"""Demo orchestration for the Phase 3 dashboard.

This module adds NO security logic of its own. It wires the existing
Phase 2 `AgentRuntime` / `SecurityGateway` (and therefore the Phase 1
verifier) into repeatable demo scenarios and derives *presentation* facts
(checkbox states, scenario labels) from the verifier's own machine-readable
`DenyReason` taxonomy. The frontend renders these facts; it never computes
them.

A `DemoState` owns one isolated runtime (its own anchor, chain, tools,
audit log), so `reset()` simply rebuilds it — the hackathon demo can be
replayed infinitely without cross-contamination.
"""

from __future__ import annotations

import datetime as _dt

from app.agents.runtime import AgentRuntime
from app.audit import AuditEvent
from app.core.delegation import Delegation
from app.core.models import Scope
from app.gateway.security_gateway import GatewayResult
from app.llm.mock import MockProvider

# Reasons grouped by which verification stage failed. This mapping is a
# presentation aid over the existing DenyReason taxonomy — the authoritative
# decision always remains the GatewayResult/verifier reason itself.
_CHAIN_STAGE_REASONS = {
    "INVALID_CHAIN", "PARENT_NOT_FOUND", "SUBJECT_MISMATCH",
    "MALFORMED_CREDENTIAL", "DELEGATION_DEPTH_EXCEEDED", "INVALID_REQUEST",
}


def decision_checks(reason: str | None) -> dict[str, bool]:
    """Derive per-stage check marks from the verifier's denial reason.

    The UI MUST NOT re-derive these; a single mapping here keeps the panel
    consistent with the actual verifier semantics.
    """
    reason = reason or ""
    return {
        "identity": reason != "UNKNOWN_ISSUER",
        "chain": reason not in _CHAIN_STAGE_REASONS,
        "signature": reason != "INVALID_SIGNATURE",
        "revocation": reason != "REVOKED_DELEGATION",
        "expiry": reason not in {"EXPIRED_DELEGATION", "NOT_YET_VALID"},
        "scope": reason not in {"SCOPE_ESCALATION", "UNAUTHORIZED_SCOPE"},
    }


class DemoState:
    """One replayable, isolated demo world over the existing runtime."""

    def __init__(self) -> None:
        self._runtime: AgentRuntime | None = None
        self._last: GatewayResult | None = None
        self._last_tamper: dict | None = None
        self.reset()

    # ------------------------------------------------------------------
    def reset(self) -> dict:
        """Rebuild the world: fresh anchor, chain, tools, audit, revocations."""
        self._runtime = AgentRuntime.bootstrap(provider=MockProvider())
        self._last = None
        self._last_tamper = None
        rt = self._runtime
        # Record the delegations that actually happened at bootstrap so the
        # audit feed tells the true story of how authority flowed.
        root, ab, bc = rt.chain
        for event_from, cred in (("human", root), ("planner", ab), ("specialist", bc)):
            rt.audit.record(AuditEvent(
                event="DELEGATION",
                timestamp=cred.issued_at,
                agent=cred.issuer.agent_id,
                tool=None,
                requested_scope=None,
                decision="ISSUED",
                reason="DELEGATION_ISSUED",
                executed=False,
                delegation_id=cred.delegation_id,
                detail=f"{cred.issuer.agent_id} -> {cred.subject.agent_id}: "
                       f"{[str(s) for s in cred.scopes]}",
            ))
        return self.snapshot()

    # ------------------------------------------------------------------
    @property
    def runtime(self) -> AgentRuntime:
        assert self._runtime is not None
        return self._runtime

    def _run(self, tool_name: str, arguments: dict, scenario: str) -> dict:
        rt = self.runtime
        result = rt.gateway.authorize_and_execute(
            agent_id=rt.executor.agent_id,
            chain=rt.full_chain(),
            tool_name=tool_name,
            arguments=arguments,
        )
        self._last = result
        snapshot = self.snapshot(scenario=scenario)
        return {"result": result.model_dump(), "state": snapshot}

    def run_legitimate(self) -> dict:
        return self._run("calendar.read", {"days": 7}, "legitimate")

    def run_scope_escalation(self) -> dict:
        return self._run("payments.transfer", {"amount": 250000, "currency": "USD"},
                         "scope_escalation")

    def run_signature_tampering(self) -> dict:
        """Tamper with C's credential AFTER signing, then submit the chain
        through the real gateway. The verifier does the rest."""
        rt = self.runtime
        chain = rt.full_chain()
        original = chain[2]
        forged = original.model_copy(
            update={"scopes": [Scope.parse("payments.transfer")]}
        )
        self._last_tamper = {
            "credential_id": original.delegation_id,
            "modified_field": "scopes",
            "original_scopes": [str(s) for s in original.scopes],
            "tampered_scopes": [str(s) for s in forged.scopes],
            "note": "scopes edited after signing; Ed25519 signature no longer matches",
        }
        result = rt.gateway.authorize_and_execute(
            agent_id=rt.executor.agent_id,
            chain=[chain[0], chain[1], forged],
            tool_name="calendar.read",
            arguments={"days": 7},
        )
        self._last = result
        return {"result": result.model_dump(), "tamper": self._last_tamper,
                "state": self.snapshot(scenario="signature_tampering")}

    def revoke_specialist(self) -> dict:
        """Revoke Agent B's delegation, then immediately re-attempt C's
        previously-authorized request through the real gateway.

        The two steps are deliberately compound in ONE request: stateless
        multi-isolate deployments (Cloudflare Workers) give no guarantee
        that cross-request in-memory state is visible to the next request,
        so the downstream effect of revocation must be demonstrated
        atomically to stay deterministic. The decision comes from the same
        gateway/verifier as every other request — no new security logic.
        """
        did = self.runtime.revoke_specialist()
        response = self._run("calendar.read", {"days": 7}, "revoked")
        return {"revoked_delegation_id": did, **response}

    # ------------------------------------------------------------------
    def _agent_status(self, agent_id: str) -> str:
        """Executor BLOCKED, others REVOKED-or-ACTIVE — derived from the
        current revocation/verifier state, not stored flags."""
        rt = self.runtime
        try:
            chain = rt.chain_for(agent_id)
        except KeyError:
            return "UNKNOWN"
        outcome = _verify_chain_quiet(rt, chain, agent_id)
        if outcome.decision != "ALLOW":
            if outcome.reason == "REVOKED_DELEGATION":
                return "BLOCKED" if agent_id == rt.executor.agent_id else "REVOKED"
            return "BLOCKED"
        return "ACTIVE"

    def _chain_links(self) -> list[dict]:
        rt = self.runtime
        links = []
        pairs = [
            ("human", rt.chain[0]),
            (rt.chain[0].subject.agent_id, rt.chain[1]),
            (rt.chain[1].subject.agent_id, rt.chain[2]),
        ]
        for from_label, cred in pairs:
            single = [cred] if cred.parent_delegation_id is None else None
            if single is not None:
                valid = _verify_chain_quiet(rt, single, cred.subject.agent_id).decision == "ALLOW"
            else:
                prefix = rt.chain[: rt.chain.index(cred) + 1]
                valid = _verify_chain_quiet(rt, prefix, cred.subject.agent_id).decision == "ALLOW"
            links.append({
                "from": from_label,
                "to": cred.subject.agent_id,
                "scopes": [str(s) for s in cred.scopes],
                "delegation_id": cred.delegation_id,
                "valid": valid,
                "revoked": rt.revocations.is_revoked(cred.delegation_id),
            })
        return links

    def snapshot(self, scenario: str = "clean") -> dict:
        rt = self.runtime
        root, _ab, bc = rt.chain
        executor_status = self._agent_status(rt.executor.agent_id)

        authorized_scopes = [str(s) for s in bc.scopes]
        last_payload = None
        if self._last is not None:
            result = self._last
            requested_tool = result.tool or ""
            last_payload = {
                "request": {
                    "agent": result.agent,
                    "tool": requested_tool,
                    "authorized_scopes": authorized_scopes,
                },
                "checks": decision_checks(result.reason if result.decision == "DENY" else None),
                "decision": result.decision,
                "reason": result.reason,
                "detail": result.detail,
                "executed": result.executed,
                "effective_scopes": result.effective_scopes,
                "tool_result": (
                    result.tool_result.model_dump() if result.tool_result else None
                ),
            }
            if self._last_tamper is not None and scenario == "signature_tampering":
                last_payload["tamper"] = self._last_tamper

        events = [e.model_dump(mode="json") for e in rt.audit.all_events()]
        decisions = [e for e in rt.audit.all_events() if e.event == "TOOL_REQUEST"]
        allowed = sum(1 for e in decisions if e.decision == "ALLOW")
        return {
            "scenario": scenario,
            "anchor_id": rt.anchor.agent_id,
            "llm_provider": rt.provider.name,
            "gateway_online": True,
            "agents": [
                {
                    "agent_id": a["agent_id"],
                    "role": a["role"],
                    "effective_scopes": a["effective_scopes"],
                    "delegation_id": a["delegation_id"],
                    "status": self._agent_status(a["agent_id"]),
                }
                for a in rt.agents_info()
            ],
            "links": self._chain_links(),
            "chain_summary": {
                "human_scopes": [str(s) for s in root.scopes],
                "executor_scopes": authorized_scopes,
                "executor_status": executor_status,
            },
            "last": last_payload,
            "stats": {
                "total_decisions": len(decisions),
                "allowed": allowed,
                "denied": len(decisions) - allowed,
                "blocked_actions": len(decisions) - allowed,
                "audit_events": len(events),
            },
            "events": events[-60:],
        }


def _verify_chain_quiet(rt: AgentRuntime, chain: list[Delegation], agent_id: str):
    """Re-run the authoritative verifier for status display. Same single
    authorization path as the gateway; a read-only consistency check."""
    from app.core.models import Scope as _Scope
    from app.core.verifier import verify_chain

    scopes = [str(s) for s in chain[-1].scopes]
    return verify_chain(
        rt.anchor, chain, _Scope.parse(scopes[0]), agent_id,
        revocation_registry=rt.revocations,
    )


__all__ = ["DemoState", "decision_checks"]
