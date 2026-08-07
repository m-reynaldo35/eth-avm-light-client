"""Compiling and pinning (design doc §16: `compile.py`, "promotes 5 copies").
Promotes `tests/sync_committee/conftest.py::SyncCommitteeLiveHarness._compile`,
`tests/state_anchor/conftest.py::puya_compile`/`compile_teal`/
`patched_repo_copy`, and `relayer/group/donors.py::puya_compile_contracts`
into one home. Per §17 item 1, this module (and everything else in
`deploy/`) is free to import `algopy`-touching contract sources and shell
out to `puyapy` -- the thing `relayer/` is forbidden to do (G8-M9).

Two compilation paths, because the two contract shapes genuinely differ
(§3.1, verified this pass against real `puyapy` 5.9.0 output):

  * **ARC4Contract** (`SyncCommitteeVerifier`, `TrustedRootAnchor`): `puyapy`
    itself emits the real, final assembled bytecode inline in the compiled
    ARC-56 artifact's `byteCode.approval`/`byteCode.clear` fields -- NO algod
    round-trip needed to learn `approval_bytes`/`clear_bytes`/the SHA-256 pin.
    Verified (this pass): `TrustedRootAnchor`'s own committed ARC-56 artifact
    decodes to exactly 3,027/4 bytes, matching every prior citation in this
    repo.
  * **bare `Contract`** (`Mpt6ComposerApp`, `Mpt7ReceiptApp`, `MptSegmentApp`,
    the donor pair): `puyapy` does NOT emit an ARC-56 artifact at all for a
    class that is not an `ARC4Contract` (verified this pass: `puya_compile`
    on `contracts/composer/bench_app.py` / `contracts/receipt/bench_app.py`
    produces only `.approval.teal`/`.clear.teal`, no `.arc56.json`), so the
    real assembled byte length can only be learned from algod's own
    `/v2/teal/compile` -- there is no offline TEAL assembler anywhere in
    this project's toolchain. This is an honest, load-bearing asymmetry
    (recorded in the implementation report and ROADMAP.md's M10 row): the
    schema *artifact* is fully offline once generated (§3.4's CI gate reads
    the committed compiled-cache files under `deploy/schema/_compiled/`),
    but *regenerating that cache from scratch* for a bare-`Contract` needs a
    reachable algod, exactly the network dependency §3.1 claims the
    generator itself does not have. `deploy schema --check` (the CI gate)
    never regenerates the cache; it only re-derives the schema JSON from the
    cache plus `contracts/**/constants.py`, which needs neither algod nor
    `puyapy`.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPILED_CACHE_DIR = Path(__file__).resolve().parent / "schema" / "_compiled"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def puya_compile(src_path: Path, *, extra_pythonpath: Path | None = None) -> dict[str, dict]:
    """Runs `puyapy` against `src_path`. Returns `{class_name: {"approval":
    teal_str, "clear": teal_str, "arc56": dict | None}}` for every contract
    defined directly in that file. No network, no algod -- `puyapy` alone.
    """
    out_dir = Path(tempfile.mkdtemp(prefix="deploy_puya_"))
    env = None
    if extra_pythonpath is not None:
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(extra_pythonpath) + ":" + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "puyapy", str(src_path), "--out-dir", str(out_dir)],
        capture_output=True, text=True, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"puyapy failed for {src_path}:\n{result.stdout}\n{result.stderr}")
    contracts: dict[str, dict] = {}
    for approval_file in out_dir.glob("*.approval.teal"):
        name = approval_file.name[: -len(".approval.teal")]
        clear_file = out_dir / f"{name}.clear.teal"
        arc56_file = out_dir / f"{name}.arc56.json"
        contracts[name] = {
            "approval": approval_file.read_text(),
            "clear": clear_file.read_text(),
            "arc56": json.loads(arc56_file.read_text()) if arc56_file.exists() else None,
        }
    return contracts


def compile_teal_via_algod(algod_client, teal_src: str) -> bytes:
    """The one step that genuinely needs algod (bare-`Contract` assembled
    size -- see module docstring). `algod_client` is a real
    `algosdk.v2client.algod.AlgodClient`."""
    compiled = algod_client.compile(teal_src)
    return base64.b64decode(compiled["result"])


def compile_teal_raw(algod_url: str, token: str, teal_src: str) -> bytes:
    """Same as `compile_teal_via_algod` but with no `algosdk` client object
    needed -- used by the offline-friendly call sites that otherwise have no
    reason to construct one."""
    req = urllib.request.Request(
        algod_url + "/v2/teal/compile",
        data=teal_src.encode(),
        headers={"X-Algo-API-Token": token, "Content-Type": "text/plain"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        body = json.load(r)
    return base64.b64decode(body["result"])


def patched_repo_copy(anchor_app_id: int) -> Path:
    """TP-M8-4's compile-time binding (§5.7): stage a full temp copy of
    `contracts/` with `contracts/state_anchor/handoff.py`'s `ANCHOR_APP_ID`
    placeholder replaced by the real, already-deployed `TrustedRootAnchor`
    app id. Promoted verbatim from `tests/state_anchor/conftest.py::
    patched_repo_copy`. Never edits a file under the real `contracts/` tree
    (§17 item 17) -- the temp copy is the only thing modified."""
    tmp_root = Path(tempfile.mkdtemp(prefix="deploy_patched_"))
    shutil.copytree(REPO_ROOT / "contracts", tmp_root / "contracts")
    handoff_path = tmp_root / "contracts" / "state_anchor" / "handoff.py"
    text = handoff_path.read_text()
    needle = "ANCHOR_APP_ID: int = 0"
    assert needle in text, "handoff.py's ANCHOR_APP_ID placeholder line changed shape"
    handoff_path.write_text(text.replace(needle, f"ANCHOR_APP_ID: int = {anchor_app_id}"))
    return tmp_root


# ---------------------------------------------------------------------------
# Bare-`Contract` compiled-artifact cache (§3.1's honest asymmetry, above).
# ---------------------------------------------------------------------------
BARE_CONTRACT_SOURCES = {
    "Mpt6ComposerApp": REPO_ROOT / "contracts" / "composer" / "bench_app.py",
    "Mpt7ReceiptApp": REPO_ROOT / "contracts" / "receipt" / "bench_app.py",
}


def refresh_bare_contract_cache(algod_client, *, names: list[str] | None = None) -> dict[str, dict]:
    """Regenerates `deploy/schema/_compiled/<Name>.compiled.json` for the
    bare-`Contract` deployables by actually running `puyapy` then algod's
    `/v2/teal/compile`. NEEDS a reachable algod (module docstring). Returns
    the refreshed cache entries. Call this whenever
    `contracts/composer/bench_app.py` / `contracts/receipt/bench_app.py`
    change; `deploy schema --check`/`generate` otherwise reads the committed
    cache files, which is what keeps THOSE commands network-free."""
    names = names or list(BARE_CONTRACT_SOURCES)
    out = {}
    for name in names:
        src = BARE_CONTRACT_SOURCES[name]
        contracts = puya_compile(src)
        entry = contracts[name]
        appr_teal, clear_teal = entry["approval"], entry["clear"]
        appr_bytes = compile_teal_via_algod(algod_client, appr_teal)
        clear_bytes = compile_teal_via_algod(algod_client, clear_teal)
        on_completion_gate = "NoOp only" if appr_teal.count("OnCompletion") > 0 else "unrestricted"
        cache = {
            "contract": name,
            "source": str(src.relative_to(REPO_ROOT)),
            "puyapy_version": "5.9.0",
            "approval_teal_sha256": sha256_hex(appr_teal.encode()),
            "clear_teal_sha256": sha256_hex(clear_teal.encode()),
            "approval_bytes_b64": base64.b64encode(appr_bytes).decode(),
            "clear_bytes_b64": base64.b64encode(clear_bytes).decode(),
            "approval_bytes": len(appr_bytes),
            "clear_bytes": len(clear_bytes),
            "approval_sha256": sha256_hex(appr_bytes),
            "clear_sha256": sha256_hex(clear_bytes),
            "on_completion_gate": on_completion_gate,
            "avm_version": 10,
        }
        COMPILED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = COMPILED_CACHE_DIR / f"{name}.compiled.json"
        with open(path, "w") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
            f.write("\n")
        out[name] = cache
    return out


def load_bare_contract_cache(name: str) -> dict:
    path = COMPILED_CACHE_DIR / f"{name}.compiled.json"
    return json.loads(path.read_text())
