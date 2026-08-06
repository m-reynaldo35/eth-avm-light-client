"""§5.1: the one retried-endpoint-pool primitive, extracted from the two
copies this project had grown independently (`service/x402_endpoint/
eth_rpc.py::rpc` and `service/x402_endpoint/eth_beacon_rpc.py::_get_json`
-- the latter's own docstring already said "same retry/fallback shape").

Preserved behaviours, each learned the hard way and load-bearing (design
doc §5.1): the `User-Agent: curl/8.0` header (several public endpoints 403
urllib's default UA); accumulating every real error across the whole pool
rather than swallowing them; treating a JSON-RPC `result: null` response as
a failure and moving on to the next endpoint, not as success; never
silently degrading to a single endpoint (§10.3) -- exhausting the whole
pool raises `PoolExhausted` carrying every attempt.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

DEFAULT_HEADERS = {"User-Agent": "curl/8.0"}


@dataclass
class PoolExhausted(Exception):
    """§10.3, §8.5: every endpoint in the pool failed, on every attempt.
    Carries every real error so a human/log can see exactly what happened,
    never just the last one."""

    path: str
    attempts: int
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"all endpoints failed for {self.path} after {self.attempts} attempt(s): {self.errors}"


class EndpointPool:
    """A small pool of HTTP endpoints serving (nominally) the same data,
    retried per §5.1's exact recipe: walk the whole pool once per attempt,
    a short sleep between endpoints, a longer sleep between full-pool
    passes."""

    def __init__(
        self,
        urls: list[str],
        *,
        headers: dict[str, str] | None = None,
        tries: int = 4,
        timeout: int = 20,
        inter_endpoint_sleep: float = 0.15,
        inter_pass_sleep: float = 1.0,
    ) -> None:
        assert urls, "EndpointPool needs at least one URL"
        self.urls = list(urls)
        self.headers = dict(headers) if headers else dict(DEFAULT_HEADERS)
        self.tries = tries
        self.timeout = timeout
        self.inter_endpoint_sleep = inter_endpoint_sleep
        self.inter_pass_sleep = inter_pass_sleep

    def request(self, make_request: Callable[[str], Any], accept: Callable[[Any], bool],
                *, path_for_errors: str = "") -> Any:
        """Walks the whole pool once per attempt. `make_request(url)` must
        perform one real HTTP call and return a parsed value (or raise).
        `accept(value)` decides whether that value counts as success (e.g.
        a JSON-RPC response with a non-null `result`) -- a value that fails
        `accept` is treated exactly like a raised exception: recorded, and
        the pool moves on. Raises `PoolExhausted` with every real error if
        the whole pool fails on every attempt; never returns a value
        `accept` rejected."""
        errors: list[str] = []
        for _attempt in range(self.tries):
            for url in self.urls:
                try:
                    value = make_request(url)
                except Exception as e:  # noqa: BLE001 - real network call, real fallback
                    errors.append(f"{url}: {e}")
                    time.sleep(self.inter_endpoint_sleep)
                    continue
                if accept(value):
                    return value
                errors.append(f"{url}: response rejected by accept()")
                time.sleep(self.inter_endpoint_sleep)
            time.sleep(self.inter_pass_sleep)
        raise PoolExhausted(path_for_errors, self.tries, errors)

    def get_json(self, path_or_url_fn: Callable[[str], str], *, path_for_errors: str = "") -> dict | list:
        """Convenience for a plain `GET` returning JSON, used by the beacon
        light-client REST endpoints. `path_or_url_fn(base)` builds the full
        URL for one pool member. A real beacon-API response may be a dict
        (`finality_update`, `bootstrap`) OR a list (`updates`) -- any value
        that decodes without raising counts as success (matching the
        original `_get_json`'s unconditional-accept behaviour exactly);
        only a real request/parse failure is treated as a failed attempt."""

        def make(url: str):
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)

        def do(base: str):
            return make(path_or_url_fn(base))

        return self.request(do, lambda v: True, path_for_errors=path_for_errors)

    def post_json_rpc(self, method: str, params: list, *, id_: int = 1) -> Any:
        """Convenience for the execution-layer JSON-RPC POST shape shared
        by every `eth_*` call."""
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": id_}).encode()
        headers = dict(self.headers)
        headers["content-type"] = "application/json"

        def make(url: str):
            req = urllib.request.Request(url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)

        def accept(d):
            # A JSON-RPC response with `result: null` (or missing) is a
            # failure, not a success -- never treated as "the answer is
            # null" (§5.1).
            return isinstance(d, dict) and d.get("result") is not None

        d = self.request(make, accept, path_for_errors=method)
        return d["result"]
