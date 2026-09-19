"""Execution entry point for the gateway.

This module exists to make the execution boundary explicit: the ONLY
caller of `ToolRegistry.execute` in the codebase is
`SecurityGateway.authorize_and_execute`, and only after
`app.core.verifier.verify_chain` returned ALLOW. Do not import this from
agents; agents receive tool names, never tool objects or executors.
"""

from app.tools.registry import ToolRegistry

__all__ = ["ToolRegistry"]
