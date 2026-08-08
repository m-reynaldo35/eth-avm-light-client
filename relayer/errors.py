"""The error taxonomy (design doc §8.5). Distinguishes the on-chain
verdict from the transport outcome -- most important for M7, where
`R_ABSENT`/`R_NO_SUCH_LOG`/`R_ZERO_LOGS` are legitimate verdicts delivered
by a SUCCESSFUL transaction, never exceptions (§6.3/§8.5)."""
from __future__ import annotations

from enum import Enum, auto


class Retryability(Enum):
    RETRY_NOW = auto()  # transient: endpoint 5xx, pool exhaustion, algod timeout
    RETRY_REPLANNED = auto()  # chain moved: M4 advanced (N6), fin_slot changed, group stale
    FATAL = auto()  # will never succeed as-is: outside window, T3 tier, no fork row
    PAGE_A_HUMAN = auto()  # N20 -- M8's equivocation latch


class RelayerError(Exception):
    retryability: Retryability = Retryability.FATAL


class PoolExhaustedError(RelayerError):
    retryability = Retryability.RETRY_NOW


class RetryReplanned(RelayerError):
    """The chain moved between plan and submission (§10.1) -- e.g. M8's
    N6 (fin header changed, "normal, not exceptional" per 008 §12.4), or
    N12 (absent -- re-anchor)."""

    retryability = Retryability.RETRY_REPLANNED


class NotAnchorable(RelayerError):
    """§6.5, §8.5: `fin_slot - t_slot > 8192` -- a PERMANENT property of a
    block, not a transient failure. Never retried automatically."""

    retryability = Retryability.FATAL


class TierUnsupported(RelayerError):
    """§6.3: a receipt's leaf is > 4,096 B (T3/ZK, out of v1 scope, §1.2).
    Surfaced, never swallowed (007 §8.2)."""

    retryability = Retryability.FATAL


class RevokedAnchor(RelayerError):
    """§8.5: M8's N13. FATAL -- 008 §15.3 item 6: N12 and N13 are NOT the
    same thing; MUST NEVER auto-re-anchor on N13 (§18 item 10)."""

    retryability = Retryability.FATAL


class ConflictLatch(RelayerError):
    """§8.5: M8's N20, the equivocation latch. PAGE_A_HUMAN, never
    retried automatically (§18 item 10)."""

    retryability = Retryability.PAGE_A_HUMAN


class RelayerBug(RelayerError):
    """M7's `R_INCOMPLETE` -- the walk never reached a terminal node. §6.3:
    always a relayer bug (withheld nodes), never a receipt fact."""

    retryability = Retryability.FATAL


class MissingContractsSource(RelayerError):
    """012 §4.2/§9 item 5/§17 item 19: raised, NEVER a bare
    `FileNotFoundError`, when `prove_receipt(against_anchor=True)` or
    `deploy_donor_pair` is reached from an installed wheel that has no
    `contracts/` source tree next to it. This is a structural limit of the
    published `eth-avm-relayer` distribution (only `relayer/` ships, §4.2) --
    not a bug to retry. `docs/quickstart.md` documents the checkout path
    that avoids it."""

    retryability = Retryability.FATAL
