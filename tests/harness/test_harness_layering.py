"""Suite H (docs/design/011-test-harness-ci.md §6.2, §13.2) -- `tests/
harness/` delegates; it must never reimplement `deploy/`/`relayer/`'s job.
Mirrors `tests/relayer/test_security.py`'s G8-M9 and
`tests/deploy/test_security_matrix.py`'s G8-M10 AST-based import-graph
purity tests exactly (G7-M11).

All offline -- the harness's own correctness must not depend on the thing
it is deciding whether to run (§13, module docstring convention).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_DIR = REPO_ROOT / "tests" / "harness"
TESTS_DIR = REPO_ROOT / "tests"

FORBIDDEN_IMPORTS = {"algopy"}


def _harness_files() -> list[Path]:
    return sorted(
        p for p in HARNESS_DIR.rglob("*.py")
        if not p.name.startswith("test_")
    )


def _imported_top_level_modules(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return names


TRIPLE_QUOTED = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
LINE_COMMENT = re.compile(r"#.*")


def _code_only(text: str) -> str:
    """Strips triple-quoted docstrings and `#` line comments before a
    literal-text search, so prose EXPLAINING a retired pattern (this
    repo's own, extensive, "here's the real bug and how it was fixed"
    documentation convention -- every rebased live test file's docstring
    narrates the §5 bug this way) is never mistaken for the pattern still
    existing in real code. A plain grep in CI cannot make this
    distinction, but a meta-test that would otherwise fail forever on the
    project's own historical documentation is worse than one that checks
    the thing that actually matters: is the pattern present in CODE."""
    return LINE_COMMENT.sub("", TRIPLE_QUOTED.sub("", text))


def _contains_subprocess_puyapy_call(py_file: Path) -> bool:
    text = _code_only(py_file.read_text())
    return bool(re.search(r"subprocess\.[a-zA-Z_]+\([^)]*puyapy", text))


def _contains_teal_compile_literal(py_file: Path) -> bool:
    return "/v2/teal/compile" in _code_only(py_file.read_text())


# ---------------------------------------------------------------------------
# H-1: tests/harness/** imports none of {algopy}; no subprocess invocation
# of puyapy; no literal "/v2/teal/compile" anywhere.
# ---------------------------------------------------------------------------
def test_h1_harness_never_invokes_puyapy_or_raw_teal_compile():
    violations = []
    for py_file in _harness_files():
        rel = py_file.relative_to(REPO_ROOT)
        imported = _imported_top_level_modules(py_file)
        bad_imports = imported & FORBIDDEN_IMPORTS
        if bad_imports:
            violations.append(f"{rel}: imports forbidden module(s) {bad_imports}")
        if _contains_subprocess_puyapy_call(py_file):
            violations.append(f"{rel}: subprocess-invokes puyapy directly")
        if _contains_teal_compile_literal(py_file):
            violations.append(f"{rel}: contains the literal '/v2/teal/compile'")
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# H-2: the rule above isn't vacuous -- tests/harness/ genuinely imports BOTH
# deploy and relayer somewhere (mirrors test_security_matrix.py's own
# both-ways discipline for G8-M10).
# ---------------------------------------------------------------------------
def test_h2_harness_genuinely_imports_deploy_and_relayer():
    imported_anywhere: set[str] = set()
    for py_file in _harness_files():
        imported_anywhere |= _imported_top_level_modules(py_file)
    assert "deploy" in imported_anywhere, "expected tests/harness/ to import deploy.* (compile.py) somewhere"
    assert "relayer" in imported_anywhere, "expected tests/harness/ to import relayer.* (group.donors) somewhere"


# ---------------------------------------------------------------------------
# H-3: zero remaining definitions of the retired duplicates anywhere under
# tests/, and zero hardcoded ALGOD_ADDRESS literals outside tests/harness/env.py.
# ---------------------------------------------------------------------------
RETIRED_DEF_PATTERNS = [
    re.compile(r"^def _algod_reachable\s*\(", re.MULTILINE),
    re.compile(r"^def _beacon_reachable\s*\(", re.MULTILINE),
    re.compile(r"^def funded_account\s*\(", re.MULTILINE),
    re.compile(r"^def patched_repo_copy\s*\(", re.MULTILINE),
    re.compile(r"^def deploy_donor_pair\s*\(", re.MULTILINE),
]

ALGOD_ADDRESS_LITERAL = re.compile(r'ALGOD_ADDRESS\s*=\s*"http://localhost:4051"')


def _all_test_py_files() -> list[Path]:
    return sorted(
        p for p in TESTS_DIR.rglob("*.py")
        if "fixtures/spike-reference" not in str(p.relative_to(REPO_ROOT))
    )


def test_h3_no_duplicate_probe_or_helper_definitions_remain():
    """`tests/harness/` itself is these helpers' new, single, canonical
    home (§6.1: `env.py`'s probes, `chain.py`'s `funded_account`,
    `deployment.py`'s `patched_repo_copy`/`deploy_donor_pair`) -- excluded
    here for the same reason `ALGOD_ADDRESS` is excluded from the literal
    check below: the point is ZERO REMAINING DUPLICATES, not zero
    definitions anywhere."""
    violations = []
    for py_file in _all_test_py_files():
        if py_file.is_relative_to(HARNESS_DIR):
            continue
        text = py_file.read_text()
        rel = py_file.relative_to(REPO_ROOT)
        for pattern in RETIRED_DEF_PATTERNS:
            if pattern.search(text):
                violations.append(f"{rel}: still defines {pattern.pattern!r}")
    assert not violations, "\n".join(violations)


def test_h3_no_hardcoded_algod_address_literal_outside_harness_env():
    violations = []
    for py_file in _all_test_py_files():
        rel = py_file.relative_to(REPO_ROOT)
        if rel == Path("tests") / "harness" / "env.py":
            continue
        if ALGOD_ADDRESS_LITERAL.search(py_file.read_text()):
            violations.append(str(rel))
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# H-4: zero cross-package conftest dotted imports anywhere. AST-based (not
# a text/regex search) so a docstring merely DISCUSSING the retired import
# pattern (as this repo's own conftest.py docstrings do, by design) is never
# mistaken for the pattern itself.
# ---------------------------------------------------------------------------
def _has_conftest_import(py_file: Path) -> bool:
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            if parts[0] == "tests" and parts[-1] == "conftest":
                return True
    return False


def test_h4_no_conftest_dotted_imports_anywhere():
    violations = []
    for py_file in _all_test_py_files():
        if _has_conftest_import(py_file):
            violations.append(str(py_file.relative_to(REPO_ROOT)))
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# H-5: `_choose_mode_and_boxes` no longer exists anywhere (the §5 fix,
# asserted as a permanent property, G4-M11).
# ---------------------------------------------------------------------------
_THIS_FILE = Path(__file__).resolve()


def test_h5_choose_mode_and_boxes_does_not_exist():
    violations = []
    for py_file in list(_all_test_py_files()) + sorted((REPO_ROOT / "relayer").rglob("*.py")):
        if py_file.resolve() == _THIS_FILE:
            continue  # this test's own name/search-string necessarily contains it
        if "_choose_mode_and_boxes" in _code_only(py_file.read_text()):
            violations.append(str(py_file.relative_to(REPO_ROOT)))
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# H-6: zero hand-rolled box-reference padding expressions remain.
# ---------------------------------------------------------------------------
PADDING_PATTERNS = [
    re.compile(r"box_refs\s*\+\s*box_refs\[:\d+\]"),
    re.compile(r"\(box_refs\s*\+\s*box_refs\)\[:\d+\]"),
]


def test_h6_no_hand_rolled_box_ref_padding_remains():
    violations = []
    for py_file in _all_test_py_files():
        if py_file.resolve() == _THIS_FILE:
            continue
        text = _code_only(py_file.read_text())
        for pattern in PADDING_PATTERNS:
            if pattern.search(text):
                violations.append(f"{py_file.relative_to(REPO_ROOT)}: {pattern.pattern}")
    assert not violations, "\n".join(violations)
