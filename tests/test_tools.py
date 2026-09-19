"""Phase 2 tool tests: registry, permission mapping, execution counting."""

from __future__ import annotations

import pytest

from app.tools.base import PaymentsTransferTool
from app.tools.registry import ToolRegistry, default_registry


class TestRegistry:
    def test_all_six_tools_registered(self):
        assert default_registry().names() == [
            "calendar.read",
            "email.read",
            "email.send",
            "files.read",
            "files.write",
            "payments.transfer",
        ]

    def test_permission_mapping(self):
        registry = default_registry()
        for name in registry.names():
            assert registry.required_scope(name) == name

    def test_unknown_tool_has_no_scope(self):
        assert default_registry().required_scope("nonexistent.tool") is None

    def test_duplicate_tool_names_rejected(self):
        with pytest.raises(ValueError):
            ToolRegistry([default_registry().get("calendar.read"),
                          default_registry().get("calendar.read")])

    def test_unknown_tool_execution_raises(self):
        with pytest.raises(KeyError):
            default_registry().execute("nonexistent.tool", {})


class TestSimulatedTools:
    def test_calendar_read_is_local_simulation(self):
        tool = ToolRegistry().get("calendar.read")
        result = tool.execute({"days": 3})
        assert result.simulated is True
        assert result.ok is True
        assert tool.execute_count == 1

    def test_payments_transfer_is_simulation_only(self):
        tool = ToolRegistry().get("payments.transfer")
        result = tool.execute({"amount": 100, "currency": "USD"})
        data = result.data
        assert result.simulated is True  # the ToolResult marks it simulated
        assert data["transaction_id"].startswith("SIM-")
        assert "no real funds" in data["note"]

    def test_execute_count_increments(self):
        tool = PaymentsTransferTool()
        assert tool.execute_count == 0
        tool.execute({})
        tool.execute({})
        assert tool.execute_count == 2
