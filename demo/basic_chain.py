"""AgentPassport Phase 1 demo: Human -> Agent A -> Agent B -> Agent C.

Run from the project root:

    python demo/basic_chain.py

Scenarios:
  1. Valid delegation chain authorizes calendar.read for Agent C  -> ALLOW
  2. Agent C requests payments.transfer                            -> DENY (UNAUTHORIZED_SCOPE)
  3. A signed credential is modified after signing                 -> DENY (INVALID_SIGNATURE)
  4. Agent B's delegation is revoked                               -> DENY (REVOKED_DELEGATION)

Everything here is local and in-memory. No network calls, no real systems.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running this demo directly from the project root without installing
# the package (`python demo/basic_chain.py`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.delegation import (
    Delegation,
    InMemoryRevocationRegistry,
    verify_delegation_signature,
)
from app.core.identity import AgentIdentity
from app.core.models import Scope
from app.core.policy import TrustAnchor
from app.core.verifier import VerificationOutcome, verify_chain

LINE = "=" * 72


def banner(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def report(title: str, outcome: VerificationOutcome) -> None:
    print(f"\n  Scenario: {title}")
    print(f"  Decision: {outcome.decision}")
    print(f"  Reason:   {outcome.reason}")
    if outcome.detail:
        print(f"  Detail:   {outcome.detail}")
    print(f"  Agent:    {outcome.agent}")
    print(f"  Request:  {outcome.requested_scope}")
    if outcome.effective_scopes:
        print(f"  Effective scopes: {', '.join(outcome.effective_scopes)}")


def build_chain() -> tuple[TrustAnchor, list[AgentIdentity], list[Delegation]]:
    """Human -> A -> B -> C with calendar.write at the root, narrowed to
    calendar.read by each hop."""
    human = AgentIdentity.generate("human:root")
    anchor = TrustAnchor(human)
    a, b, c = (AgentIdentity.generate(f"agent:{name}") for name in ("A", "B", "C"))

    from app.core.delegation import DelegationBuilder

    builder = DelegationBuilder(anchor)

    root = builder.issue_root(a, ["calendar.read", "calendar.write"])
    ab = builder.issue_child(a, b, ["calendar.read"], root)
    bc = builder.issue_child(b, c, ["calendar.read"], ab)
    return anchor, [human, a, b, c], [root, ab, bc]


def main() -> None:
    print("AgentPassport Phase 1 demo - local cryptographic delegation testbed")
    print("No LLM participates in any decision below; every result is "
          "deterministically computed from signatures and scope rules.")

    anchor, identities, chain = build_chain()
    human, a, b, c = identities
    revocations = InMemoryRevocationRegistry()

    banner("Chain: Human -> A -> B -> C  (calendar.write narrowed to calendar.read)")
    for i, cred in enumerate(chain):
        signer = "human" if i == 0 else f"agent:{'ABC'[i - 1]}"
        print(
            f"  [{i}] {cred.issuer.agent_id} -> {cred.subject.agent_id}  "
            f"scopes={[str(s) for s in cred.scopes]}  "
            f"id={cred.delegation_id}  signature_ok={verify_delegation_signature(cred)}"
        )

    # ------------------------------------------------------------------
    banner("SCENARIO 1 - valid chain: Agent C acts within its authority")
    outcome = verify_chain(
        anchor, chain, Scope.parse("calendar.read"), c.agent_id,
        revocation_registry=revocations,
    )
    report("C requests calendar.read", outcome)
    assert outcome.decision == "ALLOW", "demo consistency failure"

    # ------------------------------------------------------------------
    banner("SCENARIO 2 - privilege escalation: Agent C requests payments.transfer")
    outcome = verify_chain(
        anchor, chain, Scope.parse("payments.transfer"), c.agent_id,
        revocation_registry=revocations,
    )
    report("C requests payments.transfer", outcome)
    assert outcome.decision == "DENY", "demo consistency failure"

    # ------------------------------------------------------------------
    banner("SCENARIO 3 - tampered credential: modify a signed delegation")
    tampered = chain[0].model_copy(
        update={"scopes": [Scope.parse("calendar.read"), Scope.parse("email.send")]}
    )
    print("\n  Modified Agent A's root credential after signing "
          "(added email.send).")
    outcome = verify_chain(
        anchor, [tampered, *chain[1:]], Scope.parse("calendar.read"), c.agent_id,
        revocation_registry=revocations,
    )
    report("C requests calendar.read over a tampered chain", outcome)
    assert outcome.decision == "DENY", "demo consistency failure"

    # ------------------------------------------------------------------
    banner("SCENARIO 4 - revocation: revoke Agent B's delegation")
    ab_id = chain[1].delegation_id
    revocations.revoke(ab_id)
    print(f"\n  Revoked delegation {ab_id} (B's credential).")
    outcome = verify_chain(
        anchor, chain, Scope.parse("calendar.read"), c.agent_id,
        revocation_registry=revocations,
    )
    report("C requests calendar.read after B's revocation", outcome)
    assert outcome.decision == "DENY", "demo consistency failure"

    banner("SUMMARY")
    print(
        """
  1. Valid chain (C: calendar.read)        -> ALLOW   AUTHORIZED
  2. Escalation (C: payments.transfer)     -> DENY    UNAUTHORIZED_SCOPE
  3. Tampered credential in chain          -> DENY    INVALID_SIGNATURE
  4. Revoked intermediary (B)              -> DENY    REVOKED_DELEGATION

The LLM may propose actions; only this verifier decides. Phase 1 complete.
"""
    )


if __name__ == "__main__":
    main()
