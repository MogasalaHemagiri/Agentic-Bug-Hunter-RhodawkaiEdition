"""Tests for the RhodawkAI Edition reconFTW delegation layer.

Covers capability_registry.py (boot-time tool binding) and rtw_adapter.py
(deterministic six-step delegation), including the acceptance criteria from
the build brief + the three structural fixes:

- capabilities.json reports RTW_AVAILABLE only when RTW_HOME/reconftw.sh is
  executable AND the capability's backing binaries are present (Fix 1/§3).
- Fail-closed scope: no scope patterns → no reconFTW subprocess, block audited
  (Fix 2); --no-scope-check / allow_unscoped is the explicit demo opt-out.
- Out-of-scope target: zero subprocess spawned, block logged to audit.jsonl.
- Dedup: second call inside the 7-day TTL short-circuits with zero subprocess.
- Split phases: Phase 1.5 group vs Phase 5.5 group (Fix 1).
- Standardized merge outputs rtw_subdomains.txt / rtw_urls.txt (Fix 1b).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_ROOT = REPO_ROOT / "bughunter"
for path in (str(PKG_ROOT), str(PKG_ROOT / "tools")):
    if path not in sys.path:
        sys.path.insert(0, path)

from tools import capability_registry as reg  # noqa: E402
from tools import rtw_adapter as adp  # noqa: E402
from tools.scope_checker import ScopeChecker  # noqa: E402

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"


@pytest.fixture(autouse=True)
def isolated_homes(tmp_path, monkeypatch):
    """Point every home/path knob the two modules read at a tmp sandbox."""
    home = tmp_path / "bughunter-home"
    home.mkdir()
    monkeypatch.setenv("BUGHUNTER_HOME", str(home))
    monkeypatch.setenv("BUGHUNTER_CAPABILITIES_FILE", str(home / "capabilities.json"))
    monkeypatch.setenv("RTW_HOME", str(tmp_path / "rtw"))
    # Keep the developer's real config.json out of scope-gate results.
    monkeypatch.setenv("HOME", str(tmp_path))
    return home


@pytest.fixture
def rtw_repo(tmp_path):
    """A stub reconFTW checkout: executable reconftw.sh that parses -o and
    emits one in-scope finding so runs complete with findings."""
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(
        "#!/bin/bash\n"
        "# test stub — records invocation, writes one finding, exits 0\n"
        'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done\n'
        'mkdir -p "$out/subdomains"\n'
        'echo "found.goodscope.example" > "$out/subdomains/rtw_stub.txt"\n'
        "exit 0\n"
    )
    script.chmod(0o755)
    return repo


@pytest.fixture
def full_state():
    """capabilities.json marking every capability RTW_AVAILABLE."""
    state = {cap: "RTW_AVAILABLE" for cap in reg.CAPABILITIES}
    Path(os.environ["BUGHUNTER_CAPABILITIES_FILE"]).write_text(json.dumps(state) + "\n")
    return state


class NoSubprocess:
    """Guard asserting ZERO subprocess spawn in tests that must not execute."""

    def __init__(self):
        self.calls = 0

    def run(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("subprocess spawned in a no-spawn test path")


# ── capability_registry ───────────────────────────────────────────────────────

class TestRegistry:
    def test_seven_canonical_capabilities_exist(self):
        assert len(reg.CAPABILITIES) == 7
        for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                    "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                    "CAP_FAVICON"):
            assert cap in reg.CAPABILITIES
            assert reg.CAPABILITIES[cap].rtw_function

    def test_phase_groups_cover_all_seven(self):
        all_ids = set(reg.CAPABILITIES)
        assert set(adp.PHASE_1_5_CAPABILITIES) | set(adp.PHASE_5_5_CAPABILITIES) == all_ids
        assert not set(adp.PHASE_1_5_CAPABILITIES) & set(adp.PHASE_5_5_CAPABILITIES)
        # Phase 1.5 = subdomain/infra gap-fill, runs BEFORE httpx (Phase 2).
        assert adp.PHASE_1_5_CAPABILITIES == ("CAP_ASN_ENUM", "CAP_DNS_PERMUT",
                                              "CAP_CDN_ISOLATE")
        # Phase 5.5 = web/JS/TLS gap-fill, runs BEFORE ffuf (Phase 6).
        assert adp.PHASE_5_5_CAPABILITIES == ("CAP_JS_SOURCEMAPS", "CAP_VHOSTS",
                                              "CAP_TLS_PIVOTS", "CAP_FAVICON")

    def test_missing_deps_state_without_rtw(self):
        """No reconftw checkout → every capability RTW_MISSING_DEPS (never a
        blanket available flag)."""
        mapping = reg.rebuild(write=True)
        assert set(mapping.values()) == {"RTW_MISSING_DEPS"}
        on_disk = json.loads(Path(os.environ["BUGHUNTER_CAPABILITIES_FILE"]).read_text())
        assert on_disk == mapping

    def test_available_requires_executable_script_and_binaries(self, rtw_repo, monkeypatch):
        """Acceptance: RTW_AVAILABLE only when reconftw.sh is executable AND
        the specific capability's binaries are on PATH."""
        monkeypatch.setattr(reg, "which_tool", lambda t: "/usr/bin/fake")
        # Script absent → missing deps.
        assert reg.evaluate_capability("CAP_ASN_ENUM")["state"] == "RTW_MISSING_DEPS"
        # Script present but no PDCP_API_KEY → still missing deps (sub_asn
        # hard-requires it upstream).
        (rtw_repo / "reconftw.sh").chmod(0o755)
        ev = reg.evaluate_capability("CAP_ASN_ENUM")
        assert ev["state"] == "RTW_MISSING_DEPS"
        assert "PDCP_API_KEY" in ev["missing_env"]
        # Key set → available.
        monkeypatch.setenv("PDCP_API_KEY", "test-key")
        assert reg.evaluate_capability("CAP_ASN_ENUM")["state"] == "RTW_AVAILABLE"
        # Drop one backing binary → back to missing deps, per-capability.
        monkeypatch.setattr(reg, "which_tool",
                            lambda t: None if t == "asnmap" else "/usr/bin/fake")
        ev = reg.evaluate_capability("CAP_ASN_ENUM")
        assert ev["state"] == "RTW_MISSING_DEPS"
        assert ev["missing_tools"] == ["asnmap"]
        # A different capability without that binary stays available.
        assert reg.evaluate_capability("CAP_CDN_ISOLATE")["state"] == "RTW_AVAILABLE"

    def test_pinned_install_commands(self, monkeypatch):
        """Install routing: pinned go-install per capability — never reconFTW's
        own installer, never brew floats."""
        monkeypatch.setattr(reg, "which_tool", lambda t: None)
        monkeypatch.setattr(reg.shutil, "which", lambda t: "/usr/bin/go" if t == "go" else None)
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        monkeypatch.setattr(reg.subprocess, "run", fake_run)
        rc = reg.install_capability("CAP_ASN_ENUM")
        assert rc == 0
        installs = [c[-1] for c in captured if c[:2] == ["go", "install"]]
        assert installs, "expected go install commands"
        for pin in installs:
            assert "@" in pin, f"unpinned install: {pin}"
            assert pin.startswith(("github.com/", "cramppet/")), pin
        assert reg.RTW_TOOL_PINS.get("puredns") == "github.com/d3mondev/puredns/v2@v2.1.1"
        assert reg.RTW_TOOL_PINS.get("tlsx") == "github.com/projectdiscovery/tlsx/cmd/tlsx@v1.1.7"

    def test_banner_lists_required_and_optional_keys(self, capsys):
        reg.print_banner(reg.rebuild(write=False))
        out = capsys.readouterr().out
        assert "PDCP_API_KEY" in out
        assert "chaos_api_key" in out
        assert "h1_api_token" in out
        assert "[Req]" in out and "[Opt]" in out
        for cap in reg.CAPABILITIES:
            assert cap in out


# ── rtw_adapter: acceptance criteria ──────────────────────────────────────────

class TestAdapterAcceptance:
    def test_fail_closed_without_scope(self, full_state, rtw_repo):
        """Fix 2: no scope patterns → fail closed. No reconFTW subprocess, the
        block is audited, and the caller can continue."""
        guard = NoSubprocess()
        original = adp.subprocess.run
        adp.subprocess.run = guard.run
        try:
            result = adp.run_capability("CAP_ASN_ENUM", TARGET)
        finally:
            adp.subprocess.run = original
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True
        assert "fail-closed" in result["reason"]
        assert guard.calls == 0
        audit_file = Path(os.environ["BUGHUNTER_HOME"]) / "hunt-memory" / "audit.jsonl"
        assert audit_file.is_file(), "fail-closed block not audited"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"

    def test_allow_unscoped_opt_out_runs(self, full_state, rtw_repo):
        """--no-scope-check (allow_unscoped) is the explicit demo opt-out: it
        runs without any scope configuration."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, allow_unscoped=True)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"

    def test_rtw_home_unset_with_scope_skips_cleanly(self, full_state):
        """Acceptance: RTW_HOME unset → SKIPPED with a clean reason, no crash,
        nothing blocks the pipeline (with scope configured so the gate passes)."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert result["status"] == "SKIPPED"
        assert "reconftw.sh" in result["reason"]

    def test_missing_deps_skips_without_blocking(self, full_state):
        """Acceptance §4: RTW_MISSING_DEPS → SKIPPED(reason) and continue
        (availability is checked before the scope gate)."""
        state = {cap: "RTW_MISSING_DEPS" for cap in reg.CAPABILITIES}
        Path(os.environ["BUGHUNTER_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        result = adp.run_capability("CAP_CDN_ISOLATE", TARGET)
        assert result["status"] == "SKIPPED"
        assert "RTW_MISSING_DEPS" in result["reason"]

    def test_scope_violation_zero_subprocess_and_audited(self, full_state, rtw_repo):
        """Acceptance: out-of-scope target → zero reconFTW subprocess spawned
        and the block logged to audit.jsonl."""
        guard = NoSubprocess()
        original = adp.subprocess.run
        adp.subprocess.run = guard.run
        try:
            checker = ScopeChecker(SCOPE)
            result = adp.run_capability("CAP_ASN_ENUM", "evil.example", checker=checker)
        finally:
            adp.subprocess.run = original
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True
        assert guard.calls == 0
        audit_file = Path(os.environ["BUGHUNTER_HOME"]) / "hunt-memory" / "audit.jsonl"
        assert audit_file.is_file(), "scope block not audited"
        entry = json.loads(audit_file.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"
        assert "evil.example" in entry["url"]
        assert "rtw_adapter" in entry["error"]

    def test_scope_fail_closed_on_ambiguous_target(self, full_state, rtw_repo):
        """With scope configured via CLI args, a target not matching the
        allowlist fails closed."""
        result = adp.run_capability("CAP_ASN_ENUM", "not-on-allowlist.example",
                                    scope_domains=SCOPE)
        assert result["status"] == "SKIPPED"
        assert result["blocked"] is True

    def test_dedup_second_call_zero_subprocess(self, full_state, rtw_repo, monkeypatch):
        """Acceptance: same capability twice inside the 7-day TTL → the second
        call short-circuits to cache with zero subprocess spawn."""
        real_run = adp.subprocess.run
        calls = []

        def counting_run(argv, **kwargs):
            calls.append(argv)
            return real_run(argv, **kwargs)

        monkeypatch.setattr(adp.subprocess, "run", counting_run)
        first = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert first["status"] == "COMPLETED_WITH_FINDINGS"
        assert first["cached"] is False
        assert len(calls) == 1
        second = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert second["status"] == "COMPLETED_WITH_FINDINGS"
        assert second["cached"] is True
        assert len(calls) == 1, "dedup must spawn zero subprocesses"

    def test_stale_cache_reruns(self, full_state, rtw_repo):
        """Older than the 7-day TTL → not fresh."""
        manifest = adp.load_manifest(TARGET)
        manifest["entries"].append({
            "capability_id": "CAP_ASN_ENUM", "rtw_function": "sub_asn",
            "target": adp.host_key(TARGET), "input_hash": "stale",
            "status": "COMPLETED_EMPTY",
            "started": "2026-01-01T00:00:00Z", "finished": "2026-01-01T00:00:00Z",
        })
        assert adp.fresh_entry(manifest, "CAP_ASN_ENUM", TARGET, "stale") is None

    def test_native_capability_never_delegates(self):
        state = {"CAP_ASN_ENUM": "NATIVE"}
        Path(os.environ["BUGHUNTER_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        result = adp.run_capability("CAP_ASN_ENUM", TARGET)
        assert result["status"] == "SKIPPED"
        assert "NATIVE" in result["reason"]

    def test_unknown_capability_rejected(self):
        result = adp.run_capability("CAP_MAKE_COFFEE", TARGET)
        assert result["status"] == "SKIPPED"
        assert "unknown capability_id" in result["reason"]


# ── rtw_adapter: manifest + command construction + split phases ───────────────

class TestManifestShape:
    REQUIRED_KEYS = {"capability_id", "rtw_function", "target", "input_hash",
                     "status", "started", "finished"}

    def test_manifest_entry_shape_and_json_safe(self, full_state, rtw_repo):
        """All 4 runtimes funnel through run_capability → identical shape, and
        the manifest must be JSON-serializable without default=str."""
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, scope_domains=SCOPE)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        entry = result["entry"]
        assert self.REQUIRED_KEYS <= set(entry)
        manifest = adp.load_manifest(TARGET)
        assert manifest["version"] == 1
        assert manifest["ttl_days"] == 7
        assert manifest["entries"] and manifest["entries"][-1] == entry
        # Re-serialize strictly (no default=str) — catches Path leakage.
        round_trip = json.loads(json.dumps(manifest))
        assert round_trip["entries"][0]["workdir"] == entry["workdir"]
        path = adp.manifest_path(TARGET)
        assert path == (Path(os.environ["BUGHUNTER_HOME"]) / "recon"
                        / "target.goodscope.example" / "rtw_manifest.json")

    def test_output_published_and_scope_filtered(self, full_state, rtw_repo, tmp_path):
        recon_dir = tmp_path / "recon-out" / "t.goodscope.example"
        recon_dir.mkdir(parents=True)
        checker = ScopeChecker(SCOPE)
        # Stub emits an in-scope host → published + filtered file count >= 1.
        result = adp.run_capability("CAP_ASN_ENUM", TARGET,
                                    recon_dir=recon_dir, checker=checker)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        assert result["entry"]["filter"]["files_filtered"] >= 1
        # A file whose contents are entirely out-of-scope → emptied.
        workdir = recon_dir / "rtw" / ".work" / "oos"
        workdir.mkdir(parents=True)
        (workdir / "hits.txt").write_text("https://evil.example/x\n")
        stats = adp.filter_outputs_to_scope(workdir, checker, TARGET)
        assert stats["lines_kept"] == 0
        assert (workdir / "hits.txt").read_text().strip() == ""

    def test_standardized_outputs_written(self, full_state, rtw_repo, tmp_path):
        """Fix 1b: the bash-merge buckets land at
        <recon_dir>/rtw/<function>/rtw_subdomains.txt and rtw_urls.txt."""
        recon_dir = tmp_path / "recon-std" / "t.goodscope.example"
        result = adp.run_capability("CAP_ASN_ENUM", TARGET, recon_dir=recon_dir,
                                    scope_domains=SCOPE)
        assert result["status"] == "COMPLETED_WITH_FINDINGS"
        out_dir = recon_dir / "rtw" / "sub_asn"
        subs = (out_dir / "rtw_subdomains.txt").read_text().splitlines()
        assert subs == ["found.goodscope.example"]
        assert result["entry"]["standard_outputs"]["subdomains"] == 1

    def test_classify_lines_buckets(self, tmp_path):
        workdir = tmp_path / "wd"
        workdir.mkdir()
        (workdir / "mixed.txt").write_text(
            "https://app.goodscope.example/login\n"
            "sub.goodscope.example\n"
            "not-a-host\n"
            "https://cdn.goodscope.example/app.js [200]\n"
            "https://x.goodscope.example/sitemap.xml\n"
        )
        buckets = adp.classify_lines(workdir, ["mixed.txt"])
        assert buckets["subdomains"] == ["sub.goodscope.example"]
        # httpx-style suffix lines: first token is the bare URL.
        assert buckets["urls"] == ["https://app.goodscope.example/login",
                                   "https://cdn.goodscope.example/app.js",
                                   "https://x.goodscope.example/sitemap.xml"]

    def test_seed_prepopulation(self, full_state, tmp_path):
        recon_dir = tmp_path / "recon-seed" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        (recon_dir / "live").mkdir()
        (recon_dir / "subdomains" / "all.txt").write_text("a.t.example\nb.t.example\n")
        (recon_dir / "live" / "urls.txt").write_text("https://a.t.example\n")
        spec = reg.CAPABILITIES["CAP_DNS_PERMUT"]
        workdir = tmp_path / "wd"
        workdir.mkdir()
        seeded = adp.seed_files(spec, recon_dir, workdir)
        assert "subdomains/subdomains.txt" in seeded
        assert (workdir / "subdomains" / "subdomains.txt").read_text() == \
            "a.t.example\nb.t.example\n"
        assert adp.seed_files(reg.CAPABILITIES["CAP_ASN_ENUM"],
                              recon_dir, workdir) == []

    def test_override_cfg_always_safe(self, tmp_path):
        cfg = adp.write_override_cfg(tmp_path)
        text = cfg.read_text()
        assert "VULNS_GENERAL=false" in text
        assert "CDN_BYPASS=false" in text
        assert "NOTIFICATION=false" in text
        assert "TLSX_THREADS=25" in text  # reconFTW default is 1000 — capped
        assert "ASN_ENUM=true" in text and "VIRTUALHOSTS=true" in text

    def test_cli_command_shape(self, tmp_path):
        spec = reg.CAPABILITIES["CAP_ASN_ENUM"]
        workdir = tmp_path / "wd"
        cfg = adp.write_override_cfg(workdir)
        argv = adp.build_cli_command(spec, TARGET, workdir, cfg)
        assert argv[:2] == ["bash", str(adp.rtw_script())]
        for flag, val in (("-d", TARGET), ("-c", "sub_asn"),
                          ("-f", str(cfg)), ("-o", str(workdir))):
            i = argv.index(flag)
            assert argv[i + 1] == val
        # Never sourced into our process — always a subprocess of bash.
        assert "source" not in " ".join(argv)

    def test_source_only_script_shape(self, tmp_path):
        spec = reg.CAPABILITIES["CAP_JS_SOURCEMAPS"]
        workdir = tmp_path / "wd"
        cfg = adp.write_override_cfg(workdir)
        script = adp.build_source_script(spec, TARGET, workdir, cfg)
        assert "--source-only" in script
        assert script.strip().splitlines()[-1] == spec.rtw_function
        assert f"cd {workdir}" in script
        assert "VULNS_GENERAL=false" in script

    def test_input_hash_changes_with_seeds(self, full_state, tmp_path):
        recon_dir = tmp_path / "recon-hash" / "t.goodscope.example"
        (recon_dir / "subdomains").mkdir(parents=True)
        spec = reg.CAPABILITIES["CAP_DNS_PERMUT"]
        h1 = adp.input_hash(spec, TARGET, recon_dir)
        (recon_dir / "subdomains" / "all.txt").write_text("new.t.example\n")
        h2 = adp.input_hash(spec, TARGET, recon_dir)
        assert h1 != h2

    def test_phase_split(self, rtw_repo, full_state, monkeypatch):
        """Fix 1: run_phase('1.5') touches only the 3 infra capabilities,
        run_phase('5.5') only the 4 web/JS/TLS ones."""
        calls = []

        def fake_run_cap(cap_id, target, **kwargs):
            calls.append(cap_id)
            return adp._result(adp.RESULT_COMPLETED_EMPTY, cap_id, target)

        monkeypatch.setattr(adp, "run_capability", fake_run_cap)
        p15 = adp.run_phase("1.5", TARGET)
        assert calls == ["CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE"]
        assert len(p15) == 3
        calls.clear()
        p55 = adp.run_phase("5.5", TARGET)
        assert calls == ["CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                         "CAP_FAVICON"]
        assert len(p55) == 4
        with pytest.raises(ValueError):
            adp.run_phase("10.5", TARGET)

    def test_run_all_only_touches_available(self, rtw_repo, full_state, monkeypatch):
        calls = []

        def fake_run_cap(cap_id, target, **kwargs):
            calls.append(cap_id)
            return adp._result(adp.RESULT_COMPLETED_EMPTY, cap_id, target)

        monkeypatch.setattr(adp, "run_capability", fake_run_cap)
        state = {cap: "RTW_MISSING_DEPS" for cap in reg.CAPABILITIES}
        state["CAP_ASN_ENUM"] = "RTW_AVAILABLE"
        Path(os.environ["BUGHUNTER_CAPABILITIES_FILE"]).write_text(json.dumps(state))
        results = adp.run_all(TARGET)
        assert calls == ["CAP_ASN_ENUM"]
        assert len(results) == 7
        for r in results:
            if r["capability_id"] != "CAP_ASN_ENUM":
                assert r["status"] == "SKIPPED"

    def test_host_key_normalization(self):
        assert adp.host_key("https://Sub.Example.com:8443/path?q=1") == "sub.example.com"
        assert adp.host_key("10.0.0.5") == "10.0.0.5"
        assert adp.host_key("EXAMPLE.com.") == "example.com"
