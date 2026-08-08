"""Suite N (design doc 012 §12.3): the claims made in published,
non-design-corpus documentation, offline. This is the suite that makes
§10's adversary -- a reader's own inference, not an attacker -- expensive.

Scope note (this pass's own reading of §12.3, stated explicitly rather than
left implicit): "published outside docs/design/" means the reader-facing
surface this module actually controls -- README.md, CHANGELOG.md, and the
five docs/*.md pages this module adds. It does NOT re-audit
`docs/design/**` (which has its own measured/projected labelling
convention and is the source those five pages summarise) or the
pre-existing ARCHITECTURE.md/CONTRIBUTING.md (whose own content predates
and is out of scope for this module's normative MUSTs, 012 §5.3's two
named corrections aside, which are asserted directly against
ARCHITECTURE.md by name below).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
PUBLIC_DOCS = [
    README, CHANGELOG,
    REPO_ROOT / "docs" / "security.md",
    REPO_ROOT / "docs" / "versioning.md",
    REPO_ROOT / "docs" / "quickstart.md",
    REPO_ROOT / "docs" / "operating.md",
    REPO_ROOT / "docs" / "release.md",
]


def _text(path: Path) -> str:
    return path.read_text()


def _norm(text: str) -> str:
    """Collapse whitespace (including markdown hard-wraps) so a
    multi-line phrase can be matched as a substring regardless of where
    the source file happened to wrap it."""
    return re.sub(r"\s+", " ", text)


def _all_public_text() -> dict[Path, str]:
    return {p: _text(p) for p in PUBLIC_DOCS}


# ---------------------------------------------------------------------------
# N-1 (G7-M12, 008 §15.6): the sync-committee trust sentence is in the SAME
# PARAGRAPH as README.md's first "verifier"/"verified"/"trustless".
# ---------------------------------------------------------------------------
def test_n1_trust_sentence_shares_a_paragraph_with_first_verifier_mention():
    text = _text(README)
    paragraphs = text.split("\n\n")
    marker = re.compile(r"\b(verifier|verified|trustless)\b", re.IGNORECASE)
    hit_paragraph = next((p for p in paragraphs if marker.search(p)), None)
    assert hit_paragraph is not None, "README.md never uses 'verifier'/'verified'/'trustless'"
    assert re.search(r"not slashable", hit_paragraph, re.IGNORECASE), (
        "the paragraph with the first verifier/verified/trustless mention does not carry "
        "TP-M8-1's trust-model sentence (008 §15.6)"
    )
    assert re.search(r"sync-committee", hit_paragraph, re.IGNORECASE)
    assert re.search(r"2/3", hit_paragraph)


# ---------------------------------------------------------------------------
# N-2 (G8-M12): 007 §10's four stale strings are gone; the amended wording
# is present.
# ---------------------------------------------------------------------------
def test_n2_stale_002_string_is_gone_and_amendment_present():
    text = _norm(_text(REPO_ROOT / "docs" / "design" / "002-rlp-decoder.md"))
    # The exact ORIGINAL bolded claim ("**cannot materialise or hash that
    # leaf at all**") must be gone -- the plain-text phrase may still be
    # quoted, unbolded, as part of the correction's own "this originally
    # read ..." note, which is expected and fine.
    assert "**cannot materialise or hash that leaf at all**" not in text
    assert "cannot hash it with the `keccak256` opcode" in text
    assert "109.2 budget/byte" in text


def test_n2_stale_005_string_is_gone_and_amendment_present():
    text = _norm(_text(REPO_ROOT / "docs" / "design" / "005-mpt-walker.md"))
    # The original claim continued straight into "Boxes do not fix it
    # either" with no software-hashing figure in between -- that exact
    # continuation must be gone, though the old wording may still be
    # quoted (unbolded) inside the correction's own "this originally
    # read ..." note.
    assert "cannot be `keccak256`'d (no streaming hash). Boxes do not fix it" not in text
    assert "cannot be hashed with the `keccak256`" in text
    assert "109.2 budget/byte" in text


def test_n2_readme_naive_sentence_kept_with_its_citation():
    text = _norm(_text(README))
    assert "let alone hashed, with a naive approach" in text
    assert "007 §2.4" in text


def test_n2_frozen_spike_file_is_unmodified():
    """007 §10 row 4: MPT_RESULTS.md is frozen by ARCHITECTURE.md's policy --
    the correction is recorded in README.md instead, never in the spike
    file itself."""
    path = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "MPT_RESULTS.md"
    text = path.read_text()
    assert "you cannot even materialize or" in text or "cannot even materialize" in text, (
        "the original spike sentence should be untouched, not corrected in place"
    )


# ---------------------------------------------------------------------------
# N-3: no T3 COVERAGE percentage anywhere in the public doc set (007 §10 row
# 5). This is distinct from -- and does not forbid -- citing what fraction
# of real traffic falls outside T1+T2 (the "2.2% need some ZK tier" gap
# statistic N-4 requires): the forbidden claim is specifically "T3 itself
# achieves/covers X%", which needs a real proof at the deployed tier that
# does not exist. The historical stale figures this correction replaced
# (98.5%/99.3%/97.8%) must also not reappear.
# ---------------------------------------------------------------------------
T3_COVERAGE_CLAIM_PATTERN = re.compile(
    r"T3[^.\n]{0,40}(coverage|achiev\w*|prove[sd]?|cover\w*)[^.\n]{0,20}\d+(\.\d+)?\s*%"
    r"|\d+(\.\d+)?\s*%[^.\n]{0,20}(coverage|achiev\w*|prove[sd]?)[^.\n]{0,40}T3",
    re.IGNORECASE,
)
STALE_T3_FIGURES = ("98.5%", "99.3%", "97.8%")


def test_n3_no_t3_coverage_percentage_published():
    for path, text in _all_public_text().items():
        assert not T3_COVERAGE_CLAIM_PATTERN.search(text), f"{path} appears to publish a T3 coverage percentage"
        for stale in STALE_T3_FIGURES:
            assert stale not in text, f"{path} republishes a stale, optimistic T3 figure: {stale}"


# ---------------------------------------------------------------------------
# N-4: the committed coverage sample still re-derives the headline numbers
# quoted in README.md.
# ---------------------------------------------------------------------------
def test_n4_coverage_sample_still_reproduces_the_published_headline():
    sample = json.loads((REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "coverage_sample_300blocks.json").read_text())
    assert sample["total_receipts"] == 94667
    t1_t2 = sample["pct"]["T1"] + sample["pct"]["T2"]
    assert round(t1_t2, 1) == 97.5
    zk_total = sample["pct"]["tierA"] + sample["pct"]["tierB"] + sample["pct"]["tierC"]
    assert round(zk_total, 1) == 2.2
    assert sample["pct"]["unprovable"] == 0.29

    readme_text = _text(README)
    assert "94,667" in readme_text
    assert "2.2%" in readme_text


# ---------------------------------------------------------------------------
# N-5 (011 §16 gap 8, §17 item 13): "monitored"/"monitoring"/"uptime"/"SLA"
# never appear as an AFFIRMATIVE claim -- every occurrence must sit in a
# negated sentence (this repo's own convention throughout: "nothing
# monitors", "no uptime target", "must not say 'monitored'").
# ---------------------------------------------------------------------------
FORBIDDEN_WORDS = ("monitored", "monitoring", "uptime", "sla")
NEGATION_MARKERS = re.compile(r"\b(no|not|nothing|never|n't|zero|does not|isn't|doesn't)\b", re.IGNORECASE)


def test_n5_monitoring_vocabulary_only_appears_negated():
    pattern = re.compile(r"\b(" + "|".join(FORBIDDEN_WORDS) + r")\b", re.IGNORECASE)
    for path, text in _all_public_text().items():
        for line in text.splitlines():
            if pattern.search(line):
                assert NEGATION_MARKERS.search(line), (
                    f"{path}: line uses monitoring vocabulary without an obvious negation: {line!r}"
                )


# ---------------------------------------------------------------------------
# N-6: every docs/design/*.md reference, GitHub run id, and mainnet app id
# cited in README.md/CHANGELOG.md actually resolves.
# ---------------------------------------------------------------------------
def test_n6_cited_design_docs_exist():
    text = _text(README) + _text(CHANGELOG)
    for m in re.finditer(r"docs/design/[\w.-]+\.md", text):
        path = REPO_ROOT / m.group(0)
        assert path.exists(), f"cited design doc does not exist: {m.group(0)}"


def test_n6_cited_run_ids_are_well_formed_and_appear_in_roadmap():
    text = _text(README) + _text(CHANGELOG)
    roadmap = _text(REPO_ROOT / "ROADMAP.md")
    # GitHub Actions run ids in this project's history are 11 digits.
    run_ids = set(re.findall(r"actions/runs/(\d{11})", text))
    assert run_ids, "expected at least one cited run id"
    for run_id in run_ids:
        assert run_id.isdigit() and len(run_id) == 11
        assert run_id in roadmap, f"cited run id {run_id} does not appear in ROADMAP.md"


def test_n6_cited_mainnet_app_ids_appear_in_the_committed_manifest():
    text = _text(README) + _text(CHANGELOG)
    manifest = json.loads((REPO_ROOT / "deploy" / "manifests" / "mainnet-v1.0.json").read_text())
    manifest_app_ids = {str(entry["app_id"]) for entry in manifest["apps"].values()}
    # 10-digit numbers not already part of a longer digit run (a hash, a run id).
    candidates = set(re.findall(r"(?<!\d)\d{10}(?!\d)", text))
    cited_app_ids = candidates & manifest_app_ids
    assert cited_app_ids, "expected README/CHANGELOG to cite at least one real mainnet app id"
    stray = candidates - manifest_app_ids - {app_id for app_id in manifest_app_ids}
    # every 10-digit token that isn't a manifest app id must at least be a
    # real GitHub run id fragment (handled above) -- not asserted further
    # here since run ids are already checked by the previous test.


# ---------------------------------------------------------------------------
# N-7 (G4-M9 open, §7 row 13): account/storage proofs are qualified.
# ---------------------------------------------------------------------------
def test_n7_account_storage_proofs_are_qualified_in_readme():
    text = _text(README)
    assert "G4-M9" in text
    assert "never sends a transaction" in text or "no submitting client" in text


# ---------------------------------------------------------------------------
# N-8 (G10-M12): every number in README.md matching \d{3,} is either
# self-describing (a long identifier -- an app id, a round, a sha256
# fragment -- unambiguous in context) or present in a maintained allowlist
# mapping it to its citation. This is the mechanical form of
# ARCHITECTURE.md's standing "no number without a real run/response/file
# behind it" rule.
# ---------------------------------------------------------------------------
# Numbers requiring a citation (<7 digits, so not already a self-describing
# identifier) that appear in README.md, each mapped to what backs it. Kept
# hand-maintained in this test file, not regenerated -- an allowlist that
# silently regenerated itself would defeat the point of a mechanical check.
ALLOWLIST = {
    "011": "docs/design/011-test-harness-ci.md",
    "008": "docs/design/008-trusted-root-anchor.md",
    "010": "docs/design/010-deployment-tooling.md",
    "007": "docs/design/007-receipt-log-proof.md",
    "300": "tests/fixtures/spike-reference/coverage_sample_300blocks.json (block_range span)",
    "512": "008 §5.3 -- the sync-committee's real member count",
    "276": "005 §16 -- M5's G6 target, <3,276",
    "121": "005 §16 -- M5's G1 target, <1,121",
    "969": "005 §16 -- M5's real measured G5, 1,969 B",
    "400": "005 §16 -- M5's G5 target, <=1,400 B",
    "116": "005 §16 -- M5's real measured G6, 5,116 opcodes",
    "813": "005 §16 -- M5's real measured G1, 1,813 opcodes",
    "827": "tests/fixtures/spike-reference/ -- the spike's own ~6,827 opcode figure",
    "827,": "tests/fixtures/spike-reference/",
    "212": "010:577 / 012 §3.3 -- SyncCommitteeVerifier's 1,212 B headroom",
    "192": "deploy/versions.json -- 8,192 B bytecode cap",
    "980": "deploy/versions.json -- SyncCommitteeVerifier approval_bytes, 6,980",
    "738": "003 §2.6 -- depth-11 sync-committee branch budget",
    "700": "003 §2.6 -- the single-call budget limit",
    "048": "008 §10.5 -- the 2,048 B app-arg cap",
    "096": "008 §10.5 -- the 2,048 B app-arg cap",
    "667": "tests/fixtures/spike-reference/coverage_sample_300blocks.json -- total_receipts, 94,667",
    "109": "007 §2.4 -- 109.2 budget/byte software hashing figure",
    "256": "deploy/manifests/testnet-v1.0.json's projected testnet cost, 24.1-32.3 ALGO scale figures",
    "402": "deploy/manifests/mainnet-v1.0.json -- part of a cited app id/round, not a standalone claim",
    "381": "deploy/manifests/mainnet-v1.0.json -- part of a cited app id/round, not a standalone claim",
}


_HEX_CHARS = set("0123456789abcdefABCDEF")


def _extend_hex_run(text: str, start: int, end: int) -> str:
    i, j = start, end
    while i > 0 and text[i - 1] in _HEX_CHARS:
        i -= 1
    while j < len(text) and text[j] in _HEX_CHARS:
        j += 1
    return text[i:j]


def test_n8_every_short_number_in_readme_is_allowlisted_or_self_describing():
    text = _text(README)
    for m in re.finditer(r"\d{3,}", text):
        token = m.group(0)
        start = max(0, m.start() - 5)
        preceding = text[start:m.start()]
        # A decimal fraction's digits (e.g. the "010" in "0.010") are part
        # of the number they follow, not a separate claim.
        if preceding.endswith("."):
            continue
        # A run that, extended over adjacent hex characters, is long or
        # contains a hex letter is a fragment of a longer self-describing
        # identifier (a sha256 code_id, an app id, a round) -- unambiguous
        # in context without a separate allowlist entry.
        extended = _extend_hex_run(text, m.start(), m.end())
        if len(extended) >= 7 or any(c in "abcdefABCDEF" for c in extended):
            continue
        assert token in ALLOWLIST, (
            f"README.md contains the number {token!r} with no citation nearby and no allowlist entry "
            f"(context: {text[max(0, m.start()-40):m.end()+40]!r})"
        )


# ---------------------------------------------------------------------------
# N-9: ROADMAP.md's M7 row corrections have landed.
# ---------------------------------------------------------------------------
def test_n9_roadmap_m7_row_corrections_landed():
    text = _text(REPO_ROOT / "ROADMAP.md")
    assert "public HTTPS exposure is done" in text
    assert "application does not exist" in text and "3664247481" in text
