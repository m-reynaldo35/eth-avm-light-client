#!/usr/bin/env bash
# Records the real go-algorand build under test (docs/design/
# 011-test-harness-ci.md §8.1) -- uploaded as a CI artifact so any live
# number cited in a ROADMAP row can name the exact build it came from
# (§1.3 rule 5, §18 item 14).
set -euo pipefail

TOK="$(printf 'a%.0s' {1..64})"
curl -sS -f -H "X-Algo-API-Token: $TOK" http://localhost:4051/versions
