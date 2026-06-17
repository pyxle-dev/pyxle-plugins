"""Opt out of pyxle-db's automatic per-request transaction.

By default, an ``@action`` that writes through ``request.state.db`` runs inside
a single request-scoped transaction that the :class:`~pyxle_db.middleware.PyxleDbMiddleware`
commits when the action succeeds (a 2xx response) and rolls back otherwise.

Apply :func:`no_auto_transaction` when an action needs to manage its own
transaction boundaries — for example, several independent commits, an explicit
``async with request.state.db.transaction()`` block, or a long-running read that
must not hold a write transaction open.
"""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable, TypeVar

#: Per-request flag (on ``request.state``) read by the middleware to skip
#: auto-commit. Set by the :func:`no_auto_transaction` wrapper when the action
#: runs, so the middleware sees the opt-out without resolving the action itself.
MANUAL_FLAG = "__pyxle_db_manual_tx__"

#: Marker on the wrapped function (for introspection/tests).
OPT_OUT_ATTR = "__pyxle_db_no_autotx__"

_ActionFn = TypeVar("_ActionFn", bound=Callable[..., Awaitable[Any]])


def no_auto_transaction(action: _ActionFn) -> _ActionFn:
    """Mark an ``@action`` to opt out of automatic transaction management.

    The wrapper only sets a per-request flag the middleware reads; it does not
    change the action's arguments or return value, and it preserves the
    ``@action`` metadata so the dispatcher still recognises it.

    Usage (the opt-out sits below ``@action`` so the action wraps it)::

        @action
        @no_auto_transaction
        async def transfer(request):
            async with request.state.db.transaction() as tx:
                ...
    """

    @functools.wraps(action)
    async def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
        # ``request.state`` is a Starlette ``State``; setting an attribute here
        # is what the middleware checks after the handler returns.
        setattr(request.state, MANUAL_FLAG, True)
        return await action(request, *args, **kwargs)

    setattr(wrapper, OPT_OUT_ATTR, True)
    return wrapper  # type: ignore[return-value]


__all__ = ["no_auto_transaction", "MANUAL_FLAG", "OPT_OUT_ATTR"]
