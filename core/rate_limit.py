import time
from collections import defaultdict, deque
from flask import request

class RateLimiter:
    def __init__(self, per_min: int):
        self.per_min = per_min
        self._hits = defaultdict(lambda: deque())

    def _client_ip(self) -> str:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.remote_addr or "unknown"

    def ok(self) -> bool:
        ip = self._client_ip()
        now = time.time()
        q = self._hits[ip]
        while q and (now - q[0]) > 60:
            q.popleft()
        if len(q) >= self.per_min:
            return False
        q.append(now)
        return True
