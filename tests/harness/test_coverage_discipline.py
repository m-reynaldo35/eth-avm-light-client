"""Suite F (docs/design/011-test-harness-ci.md §13.4) -- coverage
disciplines M11 inherits and owns, offline. F-1/F-2 freeze 008 §15.5 item
4's error-code coverage baseline (G9-M8) so growth is a reviewable,
blame-able diff rather than an unnoticed drift; F-3 re-derives 007 §14.8's
receipt-size headline from the committed sample without re-pulling 300
blocks of `eth_getBlockReceipts` on every PR; F-4 is the cheapest possible
defence of this repo's own primary artifact, ROADMAP.md's own citations;
F-5 closes the M7-row gap 011 §18 item 17 names explicitly: nothing
enforced `requirements.txt`/`pyproject.toml` staying in step before this.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "contracts"
UNCOVERED_BASELINE = Path(__file__).resolve().parent / "error_codes_uncovered.txt"
SAMPLE_JSON = REPO_ROOT / "tests" / "fixtures" / "spike-reference" / "coverage_sample_300blocks.json"
ROADMAP_MD = REPO_ROOT / "ROADMAP.md"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"
X402_REQUIREMENTS_TXT = REPO_ROOT / "service" / "x402_endpoint" / "requirements.txt"

CODE_LITERAL = re.compile(r'"N(\d+)')
CODE_MENTION = re.compile(r"(?<![A-Za-z0-9])N(\d+)(?![A-Za-z0-9])")


def all_declared_error_codes(contracts_dir: Path = CONTRACTS_DIR) -> set[str]:
    """Every distinct `N<digits>` PREFIX appearing in a quoted string
    literal under `contracts/**` -- tolerates suffixes like `"N20-shape"`/
    `"N4b"`/`"N17-sentinel"`, matching the real shapes measured in this
    codebase (§9.1)."""
    codes: set[str] = set()
    for py_file in contracts_dir.rglob("*.py"):
        for m in CODE_LITERAL.finditer(py_file.read_text()):
            codes.add(f"N{int(m.group(1))}")
    return codes


def mentioned_error_codes(*dirs: Path) -> set[str]:
    """A generous, over-counting word-boundary text match over test names,
    docstrings and string literals (§9.1's own honest caveat: "certainly
    over-counts 'exercised'"). Underscores are treated as separators (not
    word characters) so `test_N5_zero_fin_root_rejected` counts as
    mentioning N5, matching how a human reads that identifier.

    `tests/harness/` itself is excluded from the scan: it is the
    coverage-discipline MECHANISM (this file's own docstrings necessarily
    cite real code shapes like `"N17-sentinel"` as worked examples), not a
    test of any contract's error codes -- counting its own prose as
    "coverage" would be circular."""
    mentioned: set[str] = set()
    for d in dirs:
        for py_file in d.rglob("*.py"):
            if py_file.resolve().is_relative_to(Path(__file__).resolve().parent):
                continue
            normalized = py_file.read_text().replace("_", " ")
            for m in CODE_MENTION.finditer(normalized):
                mentioned.add(f"N{int(m.group(1))}")
    return mentioned


def uncovered_error_codes() -> set[str]:
    declared = all_declared_error_codes()
    mentioned = mentioned_error_codes(REPO_ROOT / "tests", REPO_ROOT / "relayer")
    return declared - mentioned


# ---------------------------------------------------------------------------
# F-1: the uncovered set equals the committed baseline exactly.
# ---------------------------------------------------------------------------
def test_f1_uncovered_error_codes_match_committed_baseline():
    declared = all_declared_error_codes()
    assert len(declared) == 22, f"expected 22 distinct declared codes (§9.1), got {len(declared)}: {sorted(declared)}"

    committed = {
        line.strip() for line in UNCOVERED_BASELINE.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    fresh = uncovered_error_codes()
    assert fresh == committed, (
        f"uncovered error-code set drifted from the committed baseline "
        f"({UNCOVERED_BASELINE.relative_to(REPO_ROOT)}):\n"
        f"  newly covered (remove from baseline): {sorted(committed - fresh)}\n"
        f"  newly uncovered (add to baseline, reviewably): {sorted(fresh - committed)}"
    )
    assert len(committed) == 13


# ---------------------------------------------------------------------------
# F-2: adding a code without a test is red, naming the code. Exercises the
# extraction/diff MECHANISM directly (not the real contracts/tests trees,
# which F-1 already covers) so this test does not need to actually edit a
# real contract to prove the mechanism works.
# ---------------------------------------------------------------------------
def test_f2_a_new_uncovered_code_is_detected_by_name(tmp_path):
    contracts_dir = tmp_path / "contracts"
    contracts_dir.mkdir()
    (contracts_dir / "fake_app.py").write_text('assert False, "N99"\n')
    tests_dir = tmp_path / "tests_empty"
    tests_dir.mkdir()

    declared = all_declared_error_codes(contracts_dir)
    assert declared == {"N99"}
    mentioned = mentioned_error_codes(tests_dir)
    assert "N99" not in mentioned
    uncovered = declared - mentioned
    assert uncovered == {"N99"}, "a freshly added, never-mentioned code must show up by name"


# ---------------------------------------------------------------------------
# F-3: the committed 300-block receipt-size sample re-derives 007 §14.8's
# published headline (97.5% T1+T2, 2.2% needing a ZK tier). Pure JSON read
# -- the sample is NOT re-pulled in CI (§9.3: 300 blocks of
# eth_getBlockReceipts against volunteer public RPC, nightly, would be
# abusive, and the numbers are a one-time population estimate, not a
# regression target).
# ---------------------------------------------------------------------------
def test_f3_receipt_size_sample_rederives_published_headline():
    data = json.loads(SAMPLE_JSON.read_text())
    assert data["blocks_requested"] == 300
    assert data["total_receipts"] == 94667
    pct = data["pct"]
    t1_t2 = pct["T1"] + pct["T2"]
    zk_tier = pct["tierA"] + pct["tierB"] + pct["tierC"]
    assert round(t1_t2, 1) == 97.5, f"T1+T2 = {t1_t2}, expected ~97.5%"
    assert round(zk_tier, 1) == 2.2, f"tierA+B+C = {zk_tier}, expected ~2.2%"
    total_pct = t1_t2 + zk_tier + pct["unprovable"]
    assert abs(total_pct - 100.0) < 0.01, f"percentages must sum to 100, got {total_pct}"


# ---------------------------------------------------------------------------
# F-4: every design doc ROADMAP.md cites exists at its stated path.
# ---------------------------------------------------------------------------
def test_f4_every_roadmap_cited_design_doc_exists():
    text = ROADMAP_MD.read_text()
    cited = set(re.findall(r"docs/design/[0-9]+-[A-Za-z0-9-]+\.md", text))
    assert cited, "expected ROADMAP.md to cite at least one docs/design/*.md path"
    missing = [p for p in cited if not (REPO_ROOT / p).exists()]
    assert not missing, f"ROADMAP.md cites design doc(s) that do not exist: {missing}"


# ---------------------------------------------------------------------------
# F-5 (011 §18 item 17, ROADMAP M7 row): requirements.txt and
# pyproject.toml's [project.dependencies] must stay in step -- nothing
# enforced this before M11.
# ---------------------------------------------------------------------------
def _normalize_requirement(req: str) -> str:
    """`fastapi` / `uvicorn[standard]` / `x402-avm[fastapi,avm]` -> a
    normalized `(name, sorted-extras)` string, so `x402-avm[avm,fastapi]`
    and `x402-avm[fastapi,avm]` compare equal, and package name casing/
    hyphen-vs-underscore differences (PEP 503) do not cause a false
    "drift"."""
    req = req.strip()
    m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?", req)
    assert m, f"unparseable requirement: {req!r}"
    name = m.group(1).lower().replace("_", "-")
    extras = m.group(2) or ""
    extras_normalized = ",".join(sorted(e.strip().lower() for e in extras.strip("[]").split(","))) if extras else ""
    return f"{name}[{extras_normalized}]" if extras_normalized else name


def test_f5_requirements_txt_matches_pyproject_dependencies():
    pyproject = tomllib.loads(PYPROJECT_TOML.read_text())
    pyproject_deps = {
        _normalize_requirement(d) for d in pyproject["project"]["dependencies"]
    }

    req_lines = []
    for line in X402_REQUIREMENTS_TXT.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-e "):
            continue
        req_lines.append(line)
    requirements_txt_deps = {_normalize_requirement(r) for r in req_lines}

    assert requirements_txt_deps == pyproject_deps, (
        f"{X402_REQUIREMENTS_TXT.relative_to(REPO_ROOT)} has drifted from "
        f"pyproject.toml's [project.dependencies] (011 §18 item 17):\n"
        f"  only in requirements.txt: {sorted(requirements_txt_deps - pyproject_deps)}\n"
        f"  only in pyproject.toml:   {sorted(pyproject_deps - requirements_txt_deps)}"
    )
