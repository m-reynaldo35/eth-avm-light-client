"""`tests/harness/` -- the one home for availability probes, network
constants, the funded-account/`account` fixture, and thin delegating
wrappers over `deploy.*`/`relayer.*` (docs/design/011-test-harness-ci.md
§6). This package DELEGATES; it must never itself invoke `puyapy`, call
`/v2/teal/compile`, import `algopy`, or build a transaction group -- every
one of those already exists, live-proven, in `deploy/` or `relayer/`
(§6.2, enforced mechanically by `tests/harness/test_harness_layering.py`,
Suite H, G7-M11).
"""
from __future__ import annotations
