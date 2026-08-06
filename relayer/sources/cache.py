"""Content-addressed on-disk cache (design doc §5.5). `tests/state_anchor/
.cache/` already existed for exactly this purpose (added to `.gitignore` in
`83b4fb8`, because a ~956 MB `BeaconState` fetch is not something to
repeat) -- this formalises it as a small, reusable helper rather than each
test/driver rolling its own `Path.exists()`/`json.dump` pair.

Policy (§5.5): immutable-by-construction responses (a state at a finalized
slot, a block's receipts) are cached indefinitely; a response that
represents "the current head" (`finality_update`) must NEVER be cached --
callers simply never call `get_or_fetch` for those, since caching the
*current* anything is a correctness bug waiting to happen, not a
convenience.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

DEFAULT_CACHE_DIR = Path("tests/state_anchor/.cache")


class DiskCache:
    def __init__(self, cache_dir: Path | None = None, *, enabled: bool = True) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.enabled = enabled

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe}.json"

    def get_or_fetch(self, key: str, fetch: Callable[[], dict]) -> dict:
        """`key` should encode `(endpoint_kind, path, slot_or_block)` so
        two different real objects never collide (§5.5)."""
        if not self.enabled:
            return fetch()
        p = self._path(key)
        if p.exists():
            with open(p) as f:
                return json.load(f)
        value = fetch()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump(value, f)
        return value
