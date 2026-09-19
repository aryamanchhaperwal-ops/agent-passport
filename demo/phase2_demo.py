"""AgentPassport Phase 2 demo: agents, gateway, and enforcement boundary.

Run from the project root:

    python demo/phase2_demo.py

Shows the complete flow Human -> A -> B -> C -> SecurityGateway -> tool
with four scenarios. Every scenario prints both the DECISION and whether
the tool actually executed — the enforcement boundary made visible.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents import AgentRuntime
from app.llm.mock import MockProvider

LINE = "=" * 72


def banner(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def show(label: str, result) -> None:
    executed = "YES" if result.executed else "NO"
    print(f"\n  {label}")
    print(f"  DECISION: {result.decision}   reason: {result.reason}")
    print(f"  Tool executed: {executed}")
    if result.tool_result is not None:
        data = result.tool_result.data
        preview = {k: data[k] for k in list(data)[:3]}
        print(f"  Tool output: {preview}")


def main() -> None:
    print("AGENTPASSPORT PHASE 2 DEMO")
    print("local runtime - deterministic authorization - simulated tools only")

    runtime = AgentRuntime.bootstrap(provider=MockProvider())
    registry = runtime.registry
    gateway = runtime.gateway

    banner("[1] HUMAN AUTHORITY\nroot anchor signs Agent A's credential")
    print(f"  anchor: {runtime.anchor.agent_id}")
    print(f"  A holds: {runtime.planner.effective_scopes}")

    banner("[2] AGENT A - PLANNER\nplans the task, delegates a narrowed subset to B")
    plan = runtime.planner.plan("Find the user's calendar availability.")
    print(f"  task: 'Find the user's calendar availability.'")
    print(f"  plan: tool={plan.tool_name} args={plan.arguments}")
    print(f"  A delegates to B: {runtime.specialist.effective_scopes}")

    banner("[3] AGENT B - SPECIALIST\nrefines the subtask, delegates to C")
    print(f"  B holds: {runtime.specialist.effective_scopes}")
    print(f"  B delegates to C: {runtime.executor.effective_scopes}")
    print("  C MUST NOT hold: email.send, payments.transfer, files.write")

    banner("[4] AGENT C - EXECUTOR\nproposes tool calls through the SecurityGateway only")
    print(f"  C holds: {runtime.executor.effective_scopes}")

    banner("[5] SECURITY GATEWAY\none authorization path: verify_chain -> ALLOW ? execute")
    print(f"  authorization path: request -> gateway -> verifier -> tool/never")

    # ------------------------------------------------------------------
    banner("SCENARIO 1 - VALID ACTION: Agent C -> calendar.read")
    result = gateway.authorize_and_execute(
        runtime.executor.agent_id, runtime.full_chain(),
        "calendar.read", {"days": 7},
    )
    print("\n  checks: signature valid / chain valid / scope valid / "
          "not expired / not revoked")
    show("C requests calendar.read", result)

    # ------------------------------------------------------------------
    banner("SCENARIO 2 - PRIVILEGE ESCALATION: Agent C -> payments.transfer")
    result = gateway.authorize_and_execute(
        runtime.executor.agent_id, runtime.full_chain(),
        "payments.transfer", {"amount": 500, "currency": "USD"},
    )
    print("\n  checks: identity valid / chain valid / scope NOT authorized")
    show("C requests payments.transfer", result)

    # ------------------------------------------------------------------
    banner("SCENARIO 3 - FORGED DELEGATION")
    chain = runtime.full_chain()
    forged = chain[2].model_copy(update={"signature": "ee" * 32})
    result = gateway.authorize_and_execute(
        runtime.executor.agent_id, [chain[0], chain[1], forged],
        "calendar.read", {},
    )
    print("\n  checks: signature check FAILS on the forged credential")
    show("C presents a forged credential for calendar.read", result)

    # ------------------------------------------------------------------
    banner("SCENARIO 4 - REVOCATION: revoke Agent B's delegation")
    revoked_id = runtime.revoke_specialist()
    print(f"\n  revoked: {revoked_id}")
    result = gateway.authorize_and_execute(
        runtime.executor.agent_id, runtime.full_chain(),
        "calendar.read", {},
    )
    show("C requests calendar.read after B's revocation", result)

    # ------------------------------------------------------------------
    banner("ENFORCEMENT PROOF (tool execute counters)")
    counts = {name: registry.get(name).execute_count for name in registry.names()}
    for name, count in counts.items():
        print(f"  {name:20s} executions: {count}")
    assert counts["calendar.read"] == 1, "calendar should have executed once"
    assert counts["payments.transfer"] == 0, "payments must NEVER execute"

    banner("SUMMARY")
    print(
        """
  1. valid action        ALLOW   AUTHORIZED          executed: YES
  2. escalation          DENY    UNAUTHORIZED_SCOPE  executed: NO
  3. forged delegation   DENY    INVALID_SIGNATURE   executed: NO
  4. revocation          DENY    REVOKED_DELEGATION  executed: NO

The LLM proposed; only the cryptographic chain decided.
Audit events recorded: """ + str(runtime.audit.count()),
    )


if __name__ == "__main__":
    main()
