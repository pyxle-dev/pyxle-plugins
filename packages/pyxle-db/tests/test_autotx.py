"""Tests for the @no_auto_transaction opt-out decorator."""

from __future__ import annotations

from types import SimpleNamespace

from pyxle_db import no_auto_transaction
from pyxle_db.autotx import MANUAL_FLAG, OPT_OUT_ATTR


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace())


async def test_decorator_sets_manual_flag_and_forwards_result() -> None:
    @no_auto_transaction
    async def action(request, value):
        return {"ok": True, "value": value}

    request = _request()
    result = await action(request, 42)

    assert getattr(request.state, MANUAL_FLAG) is True
    assert result == {"ok": True, "value": 42}  # args + return value untouched


async def test_decorator_marks_function() -> None:
    @no_auto_transaction
    async def action(request):
        return {}

    assert getattr(action, OPT_OUT_ATTR) is True


async def test_decorator_preserves_action_metadata() -> None:
    # @action sets __pyxle_action__ in the function's __dict__; the opt-out
    # wrapper must keep it (functools.wraps copies __dict__) so the dispatcher
    # still recognises the action.
    async def action(request):
        return {}

    action.__pyxle_action__ = True  # type: ignore[attr-defined]
    wrapped = no_auto_transaction(action)

    assert getattr(wrapped, "__pyxle_action__", False) is True
    assert wrapped.__name__ == "action"
