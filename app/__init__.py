"""AgentPassport — local reference implementation for cryptographic agent delegation.

This package is a SECURITY TESTBED, not production software. It exists to
demonstrate deterministic, cryptographic runtime authorization of delegated
agent capabilities:

    AI proposes an action
        -> AgentPassport verifies authorization (no LLM involvement)
        -> ALLOW / DENY
        -> (only then) tool execution

The LLM never makes the authorization decision; it can only propose actions.
"""
