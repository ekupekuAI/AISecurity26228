"""Transport-level controls for the engine's HTTP surface.

The engine is an internal service: only the Node gateway should reach it. Two controls
enforce that, and both are on by default in the shape that suits an air-gapped node.

* **Client address allowlist.** Loopback only unless the operator widens it. This is the
  control that actually matters on a single-node deployment, because a bearer token in a
  config file on the same host protects very little.
* **Shared service token**, compared in constant time. This is what protects the hop when
  the engine and the gateway run on different hosts on an intranet.

Both are skipped for ``/health`` so a supervisor can probe liveness without credentials.
"""

from __future__ import annotations

import ipaddress
import secrets
from typing import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from core.config import SETTINGS

PUBLIC_PATHS = frozenset({"/health", "/healthz", "/docs", "/openapi.json", "/redoc"})


def _client_allowed(host: str | None) -> bool:
    if host is None:
        return False
    allowed = SETTINGS.trusted_clients
    if not allowed or "*" in allowed:
        return True
    if host in allowed:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in allowed:
        try:
            if "/" in entry:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            elif address == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return address.is_loopback and any(
        entry in {"127.0.0.1", "::1", "localhost"} for entry in allowed
    )


async def service_auth_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]
):
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    client_host = request.client.host if request.client else None
    if not _client_allowed(client_host):
        return JSONResponse(
            status_code=403,
            content={
                "error": "Client address is not authorised to reach the assurance engine.",
                "code": "CLIENT_NOT_TRUSTED",
            },
        )

    expected = SETTINGS.service_token
    if SETTINGS.require_service_token or expected:
        presented = request.headers.get("x-aia-service-token", "")
        if not expected:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service token authentication is required but no token is configured.",
                    "code": "SERVICE_TOKEN_MISCONFIGURED",
                },
            )
        if not secrets.compare_digest(presented, expected):
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or missing service token.", "code": "SERVICE_TOKEN_INVALID"},
            )

    return await call_next(request)


async def body_size_guard(request: Request, max_bytes: int) -> bytes | None:
    """Read a request body while refusing anything over `max_bytes`.

    A declared Content-Length is checked first so an oversized upload is rejected before
    it is buffered, and the streamed read is checked again because the header can lie.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                return None
        except ValueError:
            return None

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


__all__ = ["PUBLIC_PATHS", "body_size_guard", "service_auth_middleware"]
