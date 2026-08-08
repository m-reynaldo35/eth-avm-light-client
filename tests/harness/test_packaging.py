"""Suite W (design doc 012 §12.2): packaging, offline (plus one real build
step -- `python -m build` itself needs no network, it just invokes
setuptools against the committed pyproject.toml/source tree).

W-2 and W-6 are the exception: a genuinely clean venv's `pip install`
resolves against the real PyPI index even when every wheel it needs is
already cache-warm (pip's default resolver always makes an index round
trip unless told `--no-index`), so it needs real network -- caught live,
ci-offline.yml's own dead-proxy env vars on its "Offline tier" step exist
precisely to make this kind of accidental network dependency loud rather
than silent, and it worked (`ProxyError` on `/simple/py-algorand-sdk/`, run
31247882265). Marked `needs_network` rather than forced through the dead
proxy or given a `--no-index --find-links` workaround, because the thing
under test IS "does a real `pip install` of the published wheel actually
work", which is not a question `--no-index` can honestly answer.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover -- requires-python >=3.12 guarantees this exists
    import tomli as tomllib  # type: ignore[no-redef]


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("wheel_out")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(out_dir), str(REPO_ROOT)],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, f"python -m build failed:\n{result.stdout}\n{result.stderr}"
    wheels = list(out_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"
    return wheels[0]


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())


# ---------------------------------------------------------------------------
# W-1: the wheel contains relayer/** only.
# ---------------------------------------------------------------------------
def test_w1_wheel_contains_only_relayer(built_wheel):
    with zipfile.ZipFile(built_wheel) as zf:
        names = zf.namelist()
    non_relayer_code = [
        n for n in names
        if not n.startswith("relayer/") and not n.split("/")[0].endswith(".dist-info") and n != "relayer"
    ]
    assert non_relayer_code == [], f"wheel contains non-relayer files: {non_relayer_code}"
    for forbidden_pkg in ("deploy", "contracts", "service", "tests", "bench"):
        assert not any(n.startswith(f"{forbidden_pkg}/") for n in names), f"wheel leaked {forbidden_pkg}/"


# ---------------------------------------------------------------------------
# W-2 (G5-M12): dependency closure of the built wheel, in a genuinely clean
# venv (not the ambient interpreter, whose site-packages already satisfy
# everything and would silently under-count -- 012 §4.1's own measurement
# methodology).
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
def test_w2_clean_venv_dependency_closure_is_at_most_20_packages(built_wheel, tmp_path):
    venv_dir = tmp_path / "clean_venv"
    venv.EnvBuilder(with_pip=True).create(venv_dir)
    venv_python = venv_dir / "bin" / "python"
    report_path = tmp_path / "report.json"
    result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--dry-run", "--report", str(report_path), str(built_wheel)],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, f"pip --dry-run failed:\n{result.stdout}\n{result.stderr}"
    report = json.loads(report_path.read_text())
    n = len(report["install"])
    assert n <= 20, f"clean-venv install would pull {n} packages (baseline before 012: 59; target: <=20)"
    names = {p["metadata"]["name"].lower() for p in report["install"]}
    for forbidden in ("sentry-sdk", "fastapi-cloud-cli", "fastapi", "uvicorn", "x402-avm"):
        assert forbidden not in names, f"{forbidden} leaked into relayer's own dependency closure"


# ---------------------------------------------------------------------------
# W-3: METADATA has a Description, Requires-Python, a Project-URL, and a
# licence classifier.
# ---------------------------------------------------------------------------
def test_w3_metadata_has_description_project_url_and_license(built_wheel):
    with zipfile.ZipFile(built_wheel) as zf:
        metadata_name = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = zf.read(metadata_name).decode()
    assert "Requires-Python: >=3.12" in metadata
    assert "Project-URL:" in metadata
    assert "License ::" in metadata or "License-Expression:" in metadata or "License: MIT" in metadata
    # A real long description needs BOTH a readme key in pyproject.toml AND
    # the description-content-type header this produces.
    assert "Description-Content-Type:" in metadata


# ---------------------------------------------------------------------------
# W-4 (011 §18 item 17, did not land there): the dependency sets declared in
# pyproject.toml and service/x402_endpoint/requirements.txt agree.
# ---------------------------------------------------------------------------
def test_w4_pyproject_and_requirements_txt_declare_the_same_service_deps():
    data = _pyproject()
    from tests.harness.test_coverage_discipline import _normalize_requirement

    core = data["project"]["dependencies"]
    service = data["project"]["optional-dependencies"]["service"]
    pyproject_all = {_normalize_requirement(d) for d in (*core, *service)}

    req_text = (REPO_ROOT / "service" / "x402_endpoint" / "requirements.txt").read_text()
    req_lines = [
        line.strip() for line in req_text.splitlines()
        if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("-e ")
    ]
    requirements_txt_deps = {_normalize_requirement(r) for r in req_lines}
    assert requirements_txt_deps == pyproject_all, (
        f"requirements.txt and pyproject.toml disagree: "
        f"only in requirements.txt={requirements_txt_deps - pyproject_all}, "
        f"only in pyproject.toml={pyproject_all - requirements_txt_deps}"
    )


# ---------------------------------------------------------------------------
# W-5: relayer.__version__ vs [project] version.
# ---------------------------------------------------------------------------
def test_w5_relayer_dunder_version_matches_pyproject_version():
    import relayer

    data = _pyproject()
    assert relayer.__version__ == data["project"]["version"]


# ---------------------------------------------------------------------------
# W-6 (G6-M12): a clean venv, real install, real invocations.
# ---------------------------------------------------------------------------
@pytest.mark.needs_network
def test_w6_clean_venv_install_and_both_cli_forms_work(built_wheel, tmp_path):
    venv_dir = tmp_path / "clean_venv_install"
    venv.EnvBuilder(with_pip=True).create(venv_dir)
    venv_python = venv_dir / "bin" / "python"
    venv_script = venv_dir / "bin" / "eth-avm-relayer"

    install = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(built_wheel)],
        capture_output=True, text=True, timeout=300,
    )
    assert install.returncode == 0, f"pip install failed:\n{install.stdout}\n{install.stderr}"

    imp = subprocess.run([str(venv_python), "-c", "import relayer; print(relayer.__version__)"],
                          capture_output=True, text=True, timeout=30)
    assert imp.returncode == 0, imp.stderr

    script_help = subprocess.run([str(venv_script), "--help"], capture_output=True, text=True, timeout=30)
    assert script_help.returncode == 0, script_help.stderr
    assert "usage" in script_help.stdout.lower()

    module_help = subprocess.run([str(venv_python), "-m", "relayer", "--help"],
                                  capture_output=True, text=True, timeout=30)
    assert module_help.returncode == 0, (
        f"`python -m relayer --help` failed -- this is the exact command 009 §15.4 nominated as "
        f"this project's quickstart:\n{module_help.stdout}\n{module_help.stderr}"
    )
    assert "usage" in module_help.stdout.lower()


# ---------------------------------------------------------------------------
# W-7 (G6-M12): every documented `python -m relayer ...` invocation parses.
# ---------------------------------------------------------------------------
KNOWN_VERBS = ("status", "sync", "anchor", "prove", "plan")


def _extract_relayer_invocations(text: str) -> list[str]:
    """Only real, fully-spelled invocations -- excludes illustrative
    ellipsis references like "`python -m relayer ...`" that some prose
    uses to refer to the CLI in the abstract, not to demonstrate a verb."""
    candidates = re.findall(r"python -m relayer ([^\n`]+)", text)
    return [c for c in candidates if c.split()[0] in KNOWN_VERBS]


def test_w7_every_documented_invocation_parses():
    from relayer.cli import build_parser

    module_doc = Path(REPO_ROOT / "relayer" / "cli.py").read_text()
    init_doc = Path(REPO_ROOT / "relayer" / "__init__.py").read_text()
    invocations = _extract_relayer_invocations(module_doc) + _extract_relayer_invocations(init_doc)
    assert invocations, "expected at least one documented `python -m relayer ...` invocation"

    parser = build_parser()
    for raw in invocations:
        # Strip bracketed optionals ([--foo], [--bar N]) and placeholder
        # tokens (block N|latest, 0x..., I, L) down to something parseable
        # with real values substituted -- these are docstring EXAMPLES, not
        # literal shell text.
        tokens = raw.replace("[", "").replace("]", "").split()
        cleaned = []
        for tok in tokens:
            if tok in ("latest|N", "N", "0x...", "I", "L", "auto|direct|historical"):
                cleaned.append("1" if tok in ("N", "I", "L") else "latest" if "latest" in tok else "auto")
            else:
                cleaned.append(tok)
        args = parser.parse_args(cleaned)
        assert args.verb, f"failed to parse documented invocation: {raw!r}"


# ---------------------------------------------------------------------------
# W-8 (§9 item 5 / §17 item 19): a named error, not a bare FileNotFoundError.
# ---------------------------------------------------------------------------
def test_w8_missing_contracts_source_raises_named_error_not_bare_filenotfound(tmp_path):
    from relayer.drivers.m7_receipt import patched_probe_source
    from relayer.errors import MissingContractsSource
    from relayer.group.donors import deploy_donor_pair

    fake_root = tmp_path / "no_contracts_here"
    fake_root.mkdir()

    with pytest.raises(MissingContractsSource) as exc_info:
        patched_probe_source(fake_root, 12345)
    assert "docs/quickstart.md" in str(exc_info.value)

    with pytest.raises(MissingContractsSource):
        deploy_donor_pair(None, "sender", "sk", repo_root=fake_root)
