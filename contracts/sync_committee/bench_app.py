"""contracts/sync_committee/bench_app.py -- measurement/test-only donor
infrastructure for M4's live end-to-end proof (tests/sync_committee/
test_live_e2e_finality.py). NEVER deploy to mainnet: mirrors
contracts/mpt/bench_app.py's `MptBenchBaselineBare` / donor-issuer pattern
exactly (docs/design/004-sync-committee.md §2.4/§9, "M1 §9.1 / M4 §16's
pattern" -- measured there via a standalone `M4Probe.issue_donors` probe,
never wired into the real `SyncCommitteeVerifier` contract itself).

`SyncCommitteeVerifier.install_chunk`/`submit_update` (contracts/sync_committee/
verifier.py) are real ARC4 methods whose real, on-chain opcode cost
(measured live, not projected: ~1,966/point for `g1_bind` alone, up to
~157,509 worst-case for `submit_update`, design doc §9.1) vastly exceeds a
single app call's 700 base budget. §9.3's own recommended group ("8
top-level app calls + 256 donor inner calls") requires SOMETHING to issue
those 256 inner calls -- but neither `verifier.py` nor `install.py` do this
themselves (by design: `verifier.py`'s `donor()` docstring calls it an
"inner-call target," not a self-issuer, and the AVM forbids an app from
inner-calling itself -- "attempt to self-call", the same restriction
`contracts/mpt/bench_app.py`'s own `MptSegmentApp` docstring documents
hitting first). The fix used everywhere else in this project
(`MptSegmentApp`/`_issue_donors`, `RlpSizeProbeBare`'s callee) is a
SEPARATE, minimal, pre-deployed pair of contracts: a trivial callee that
does nothing (so its own execution cost is negligible) and an issuer that
loops `itxn.ApplicationCall` at it purely to raise the ATOMIC GROUP's
shared opcode-budget pool (pooling is group-wide, not per-transaction or
per-app -- confirmed by this project's own existing `noop_budget()`/
`install_open_session` sibling-call pattern, tests/sync_committee/
test_install_live.py). Neither contract here touches `SyncCommitteeVerifier`
at all; the pooled budget they raise is available to WHATEVER OTHER
transaction in the same atomic group needs it, including a real,
unmodified `install_chunk`/`submit_update` call against the real deployed
verifier app.
"""

from algopy import Contract, Txn, UInt64, itxn, op, subroutine


class DonorCallee(Contract):
    """Trivial callee, `MptBenchBaselineBare`'s exact role: an inner-call
    target whose own execution cost is negligible, existing purely so
    `DonorIssuer` has something to call `n` times."""

    def approval_program(self) -> bool:
        return True

    def clear_state_program(self) -> bool:
        return True


@subroutine
def _issue_donors(n: UInt64, donor_app_id: UInt64) -> None:
    """Mirrors `contracts/mpt/bench_app.py`'s `_issue_donors` exactly:
    issue `n` no-op inner app calls to a SEPARATE, pre-deployed, minimal
    callee app, purely to raise the atomic group's pooled opcode budget by
    ~700/call (measured net 682/call after the ~18-budget issuance cost,
    design doc §2.4). `fee=0` -- the outer transaction's own fee must be
    sized to cover `n` extra minimum fees (the caller's responsibility)."""
    i = UInt64(0)
    while i < n:
        itxn.ApplicationCall(
            app_id=donor_app_id,
            fee=UInt64(0),
        ).submit()
        i += UInt64(1)


class DonorIssuer(Contract):
    """NOT a production app -- test-only budget-pool raiser for a real
    (non-simulated) `install_chunk`/`submit_update` submission against the
    real `SyncCommitteeVerifier`. Raw bare-TEAL args (no ABI decoding
    overhead to add to the group's own cost):

        arg0 = n (8B big-endian uint64) -- number of donor inner calls to issue
        arg1 = donor_app_id (8B big-endian uint64) -- `DonorCallee`'s app id,
               must be present in this transaction's `apps` foreign-app array
    """

    def approval_program(self) -> bool:
        if Txn.application_id.id == UInt64(0):
            return True
        n = op.btoi(Txn.application_args(0))
        donor_app_id = op.btoi(Txn.application_args(1))
        _issue_donors(n, donor_app_id)
        return True

    def clear_state_program(self) -> bool:
        return True
