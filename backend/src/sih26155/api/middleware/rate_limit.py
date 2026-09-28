"""
Sliding-Window In-Memory Rate Limiting Middleware.

Protects against denial-of-service, automated credential brute forcing,
and unauthorized scanning against device targets.
"""

from __future__ import annotations

from collections import defaultdict
import logging
import os
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter(BaseHTTPMiddleware):
    """
    Tracks client request timestamps within a sliding window (default 60 seconds).
    """

    def __init__(
        self,
        app,
        max_requests_per_minute: int = 240,
        scan_max_requests_per_minute: int = 60,
    ) -> None:
        super().__init__(app)
        self.max_rpm = max_requests_per_minute
        self.scan_max_rpm = scan_max_requests_per_minute
        self.window_seconds = 60
        self.request_history: dict[str, list[float]] = defaultdict(list)

    def is_enabled(self) -> bool:
        if os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("false", "0", "no"):
            return False
        if os.getenv("TESTING", "false").lower() in ("true", "1"):
            return False
        return True

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.is_enabled():
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        cutoff = now - self.window_seconds

        # Determine threshold based on endpoint sensitivity
        path = request.url.path
        is_heavy_endpoint = any(
            frag in path for frag in ("/discover", "/live-fetch", "/live/apply")
        )
        allowed_limit = self.scan_max_rpm if is_heavy_endpoint else self.max_rpm

        # Prune old timestamps
        timestamps = [ts for ts in self.request_history[client_ip] if ts > cutoff]
        self.request_history[client_ip] = timestamps

        if len(timestamps) >= allowed_limit:
            logger.warning(
                "Rate limit exceeded for client %s on endpoint %s (%d requests in 60s)",
                client_ip,
                path,
                len(timestamps),
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please wait before executing further scans or queries.",
                    "retry_after_seconds": 60,
                },
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(allowed_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        self.request_history[client_ip].append(now)
        response = await call_next(request)
        remaining = max(0, allowed_limit - len(self.request_history[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(allowed_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
