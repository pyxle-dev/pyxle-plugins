"""A minimal fake ``httpx.AsyncClient`` so OAuth tests run fully offline."""

from __future__ import annotations

from typing import Any


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None) -> None:
        self.status_code = status_code
        self._json = json_data

    def json(self) -> Any:
        if isinstance(self._json, Exception):
            raise self._json
        return self._json


class FakeClient:
    """Routes ``post``/``get`` by URL to canned :class:`FakeResponse` objects.

    Records every call for assertions. An unexpected URL raises, so a test can't
    silently pass against a request it didn't intend to make.
    """

    def __init__(
        self,
        *,
        post: dict[str, FakeResponse] | None = None,
        get: dict[str, FakeResponse] | None = None,
    ) -> None:
        self._post = post or {}
        self._get = get or {}
        self.posts: list[tuple[str, Any, Any]] = []
        self.gets: list[tuple[str, Any]] = []

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def post(self, url: str, data: Any = None, headers: Any = None) -> FakeResponse:
        self.posts.append((url, data, headers))
        if url not in self._post:
            raise AssertionError(f"unexpected POST to {url}")
        return self._post[url]

    async def get(self, url: str, headers: Any = None) -> FakeResponse:
        self.gets.append((url, headers))
        if url not in self._get:
            raise AssertionError(f"unexpected GET to {url}")
        return self._get[url]


def factory_for(client: FakeClient):
    """A ``http_client_factory`` that always hands back ``client``."""
    return lambda: client
