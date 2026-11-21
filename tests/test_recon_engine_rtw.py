"""End-to-end tests for recon_engine.sh RhodawkAI Edition gap-fill (Fixes 1+2).

Acceptance checks verified here at the engine level, with a stub reconFTW
checkout (no network, no real scanners needed):

1. Pipeline order: Phase 1.5 exists and runs BEFORE Phase 2 (httpx); Phase 5.5
   runs BEFORE Phase 6 (ffuf). Checked by bash -n + grep ordering + live runs.
2. CLI scope gate:
   - --scope-domain passes scope to rtw_adapter.py; in-scope stub findings are
     merged into subdomains/all.txt (Phase 1.5) before httpx probes them.
   - an out-of-scope target blocks with ZERO reconFTW subprocesses (stub
     marker never touched) and the block is audited.
   - no scope flags at all → fail closed (adapter blocks; engine continues).
   - --no-scope-check is the explicit demo opt-out (stub runs unscoped).
3. RTW_HOME unset → engine behaves as upstream (gap-fill skipped, no crash).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENGINE = REPO_ROOT / "bughunter" / "tools" / "recon_engine.sh"
ADAPTER = REPO_ROOT / "bughunter" / "tools" / "rtw_adapter.py"

SCOPE = ["*.goodscope.example"]
TARGET = "target.goodscope.example"

STUB_RECONFTW = r"""#!/bin/bash
# Stub reconFTW checkout for engine-level tests. Handles BOTH invocation
# modes the adapter uses:
#   cli:          bash reconftw.sh -d T -c FN -f CFG -o WORKDIR --no-banner
#   source-only:  source reconftw.sh --source-only; then call FN (cwd=workdir)
RTW_STUB_MARKER="${RTW_STUB_MARKER:-}"
rtw_stub_emit() {
    local out="${1:-$PWD}"
    mkdir -p "$out/subdomains" "$out/webs"
    echo "stub-found.goodscope.example" > "$out/subdomains/rtw_stub.txt"
    echo "https://stub-found.goodscope.example/js/app.js" > "$out/webs/rtw_stub_urls.txt"
}
if [[ "${1:-}" == "--source-only" ]]; then
    sub_asn()        { rtw_stub_emit "$PWD"; }
    sub_permut()     { rtw_stub_emit "$PWD"; }
    cdnprovider()    { rtw_stub_emit "$PWD"; }
    jschecks()       { rtw_stub_emit "$PWD"; }
    virtualhosts()   { rtw_stub_emit "$PWD"; }
    tls_ip_pivots()  { rtw_stub_emit "$PWD"; }
    favirecon_tech() { rtw_stub_emit "$PWD"; }
    return 0 2>/dev/null || exit 0
fi
out=""
while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; esac; shift; done
[[ -n "$RTW_STUB_MARKER" ]] && touch "$RTW_STUB_MARKER"
rtw_stub_emit "$out"
exit 0
"""


@pytest.fixture
def rtw_env(tmp_path, monkeypatch):
    """Stub RTW checkout + isolated homes + capabilities all RTW_AVAILABLE.

    A stub `curl` (instant connection-refused) is prepended to PATH so the
    engine's crt.sh / web.archive.org calls fail fast — hermetic, no network,
    and the engine treats them exactly like an offline box (empty results)."""
    repo = tmp_path / "rtw"
    repo.mkdir()
    script = repo / "reconftw.sh"
    script.write_text(STUB_RECONFTW)
    script.chmod(0o755)

    stub_bin = tmp_path / "stub-bin"
    stub_bin.mkdir()
    curl_stub = stub_bin / "curl"
    curl_stub.write_text("#!/bin/bash\nexit 7\n")
    curl_stub.chmod(0o755)
    # Live-run fix: stub every scanner the engine's `command -v` guards for,
    # so a fully-provisioned host (real subfinder/nmap/dig on PATH, as on a
    # root VPS) can never turn these unit tests into live network runs or
    # hangs. The engine treats them exactly like absent/empty tools.
    for _tool in ("subfinder", "amass", "httpx", "nmap", "dig", "katana",
                  "gau", "ffuf", "nuclei"):
        _stub = stub_bin / _tool
        _stub.write_text("#!/bin/bash\nexit 0\n")
        _stub.chmod(0o755)
    # Step 2A: the PD httpx stub emits one live line per probed host so the
    # pipeline has live hosts. Hosts whose name contains "cdn." carry a
    # cloudflare tech tag (CDN_EDGE classification); everything else is plain
    # nginx (FIRST_PARTY_ORIGIN).
    httpx_stub = stub_bin / "httpx"
    httpx_stub.write_text(
        "#!/bin/bash\n"
        '# _resolve_pd_httpx probes `-version` and greps for "projectdiscovery"\n'
        '# — answering it routes the engine to THIS stub via an absolute path.\n'
        'if [[ "$1" == "-version" ]]; then echo "httpx 1.3.5 projectdiscovery"; exit 0; fi\n'
        'out=""; list=""\n'
        'while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2";; -l) list="$2";; esac; shift; done\n'
        '[[ -n "$out" && -n "$list" ]] || exit 0\n'
        'while IFS= read -r h; do\n'
        '  [[ -z "$h" ]] && continue\n'
        '  case "$h" in\n'
        '    *cdn.*) echo "$h [200] [Welcome] [cloudflare,nginx] [1234]" ;;\n'
        '    *)     echo "$h [200] [Welcome] [nginx] [2048]" ;;\n'
        '  esac\n'
        'done < "$list" > "$out"\n'
        "exit 0\n"
    )
    httpx_stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub_bin}:{os.environ.get('PATH', '')}")

    home = tmp_path / "bughunter-home"
    home.mkdir()
    marker = tmp_path / "rtw_stub_marker"
    recon_out = tmp_path / "recon-out"
    recon_out.mkdir()

    monkeypatch.setenv("RTW_HOME", str(repo))
    monkeypatch.setenv("BUGHUNTER_HOME", str(home))
    monkeypatch.setenv("BUGHUNTER_CAPABILITIES_FILE",
                       str(home / "capabilities.json"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("RECON_OUT_DIR", str(recon_out))
    monkeypatch.setenv("RTW_STUB_MARKER", str(marker))
    (home / "capabilities.json").write_text(
        json.dumps({cap: "RTW_AVAILABLE"
                    for cap in ("CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE",
                                "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS",
                                "CAP_FAVICON")}))
    return {"home": home, "marker": marker, "recon_out": recon_out,
            "capabilities": home / "capabilities.json", "stub_bin": stub_bin}


def run_engine(args, cwd=REPO_ROOT, timeout=300):
    env = os.environ.copy()
    env["BBHUNT_SKIP_DEPS"] = "1"
    return subprocess.run(
        ["bash", str(ENGINE), *args],
        cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout,
    )


class TestPipelineOrder:
    def test_syntax_ok(self):
        proc = subprocess.run(["bash", "-n", str(ENGINE)], capture_output=True)
        assert proc.returncode == 0, proc.stderr

    def test_phase_1_5_before_phase_2_and_after_phase_1(self):
        text = ENGINE.read_text()
        p1 = text.index("# Phase 1: Subdomain Enumeration")
        p15 = text.index("# Phase 1.5: reconFTW Subdomain/Infra Gap-Fill")
        p2 = text.index("# Phase 2: HTTP Probing")
        assert p1 < p15 < p2, "Phase 1.5 must run between Phase 1 and httpx"

    def test_phase_5_5_before_phase_6_and_after_phase_5(self):
        text = ENGINE.read_text()
        p5 = text.index("# Phase 5: JS Analysis")
        p55 = text.index("# Phase 5.5: reconFTW Web/JS/TLS Gap-Fill")
        p6 = text.index("# Phase 6: Directory Fuzzing")
        assert p5 < p55 < p6, "Phase 5.5 must run between Phase 5 and ffuf"

    def test_no_phase_10_5_left(self):
        assert "Phase 10.5" not in ENGINE.read_text()

    def test_phase_1_enum_calls_are_time_bounded(self):
        """Live-run fix: Phase 1 subfinder and the crt.sh/wayback curls are
        wrapped in bounded `timeout` so passive enumeration can never hang."""
        text = ENGINE.read_text()
        assert "timeout 180 subfinder" in text
        p1 = text.index("# Phase 1: Subdomain Enumeration")
        p15 = text.index("# Phase 1.5: reconFTW Subdomain/Infra Gap-Fill")
        phase1 = text[p1:p15]
        assert phase1.count("timeout 60 curl") == 2

    def test_adapter_phase_groups_match_engine(self):
        sys.path.insert(0, str(REPO_ROOT / "bughunter"))
        from tools import rtw_adapter as adp
        assert set(adp.PHASE_1_5_CAPABILITIES) == {
            "CAP_ASN_ENUM", "CAP_DNS_PERMUT", "CAP_CDN_ISOLATE"}
        assert set(adp.PHASE_5_5_CAPABILITIES) == {
            "CAP_JS_SOURCEMAPS", "CAP_VHOSTS", "CAP_TLS_PIVOTS", "CAP_FAVICON"}


class TestCliScopeGate:
    def test_scope_forwarded_and_findings_merged(self, rtw_env):
        """--scope-domain passes through to the adapter; in-scope stub
        subdomains land in subdomains/all.txt BEFORE httpx runs."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0],
                           "--scope-exclude", "excluded.goodscope.example"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Phase 1.5" in out, "Phase 1.5 did not run"
        assert "merged subdomains" in out, "gap-fill subdomains not merged"
        all_txt = (rtw_env["recon_out"] / "subdomains" / "all.txt").read_text()
        assert "stub-found.goodscope.example" in all_txt
        # Dedup: stub appears exactly once despite seed re-add + sort -u.
        assert all_txt.count("stub-found.goodscope.example") == 1
        # The reconFTW subprocess actually ran.
        assert rtw_env["marker"].is_file(), "reconFTW stub never executed"
        # Phase 5.5 merged the stub URL into the URL corpus.
        assert "Phase 5.5" in out
        urls = (rtw_env["recon_out"] / "urls" / "all.txt").read_text()
        assert "https://stub-found.goodscope.example/js/app.js" in urls
        # Manifest written in the shared schema.
        manifest = json.loads((rtw_env["home"] / "recon" / TARGET /
                               "rtw_manifest.json").read_text())
        assert manifest["version"] == 1 and manifest["ttl_days"] == 7
        fn_names = {e["rtw_function"] for e in manifest["entries"]}
        assert {"sub_asn", "sub_permut", "cdnprovider"} <= fn_names

    def test_out_of_scope_blocks_preflight(self, rtw_env):
        """Live-run fix: an out-of-scope domain target is blocked by the
        PRE-FLIGHT gate — non-zero exit before any phase runs, zero tools
        executed, zero packets sent, block audited."""
        proc = run_engine(["evil.example", "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out[-3000:]
        assert "SCOPE BLOCK" in out
        assert "Phase 1" not in out, "a phase started after the pre-flight block"
        assert not rtw_env["marker"].is_file(), \
            "reconFTW subprocess spawned for an out-of-scope target!"
        audit = (rtw_env["home"] / "hunt-memory" / "audit.jsonl")
        assert audit.is_file(), "scope block not audited"
        entry = json.loads(audit.read_text().splitlines()[-1])
        assert entry["scope_check"] == "fail"
        assert "evil.example" in entry["url"]

    def test_no_scope_flags_blocks_preflight(self, rtw_env):
        """Neither --scope-domain nor --no-scope-check → the whole engine run
        fails closed at the pre-flight gate (not just delegation)."""
        proc = run_engine([TARGET])
        out = proc.stdout + proc.stderr
        assert proc.returncode != 0, out[-3000:]
        assert "SCOPE BLOCK" in out and "no --scope-domain" in out
        assert "Phase 1" not in out
        assert not rtw_env["marker"].is_file()
        audit = (rtw_env["home"] / "hunt-memory" / "audit.jsonl")
        assert audit.is_file(), "scope block not audited"

    def test_normalize_only_unaffected_by_gate(self, rtw_env):
        """Upstream contract preserved: --normalize-only prints the parsed
        target and exits 0 with no scope flags — the gate sits after it."""
        proc = run_engine([TARGET, "--normalize-only"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "host=target.goodscope.example" in out
        assert "SCOPE BLOCK" not in out

    def test_no_scope_check_opt_out_runs_unscoped(self, rtw_env):
        """--no-scope-check is the explicit demo opt-out: stub executes."""
        proc = run_engine([TARGET, "--no-scope-check"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert rtw_env["marker"].is_file(), \
            "--no-scope-check must allow the delegation to run"
        assert "UNSCOPED" in out

    def test_rtw_home_unset_is_upstream_behavior(self, rtw_env, monkeypatch):
        """RTW_HOME unset → gap-fill skipped with upstream behavior; native
        pipeline still runs and no capabilities work happens."""
        monkeypatch.delenv("RTW_HOME", raising=False)
        monkeypatch.setenv("RTW_STUB_MARKER", str(rtw_env["marker"]) + ".absent")
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "gap-fill not configured" in out
        assert "Phase 1.5" in out  # the (skipped) phase header still prints
        assert not rtw_env["marker"].is_file()

    def test_comma_separated_scope_patterns(self, rtw_env):
        """Repeatable + comma-separated patterns both work."""
        proc = run_engine([TARGET,
                           "--scope-domain", "*.goodscope.example,other.example",
                           "--scope-domain", "extra.goodscope.example"])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert rtw_env["marker"].is_file()


class TestShorthandAndHonestRecon:
    """Step 1A shorthand CLI + Step 1B health table + Step 2A origin-only
    nmap + Step 2B/2C truth & delta, verified at the engine level."""

    def test_shorthand_argv_rewrite(self):
        """Unit: engine._normalize_cli_argv rewrites `<target> -recon[...]`
        into the canonical `recon <target> ...` argv; known commands and
        flag-first invocations are untouched."""
        sys.path.insert(0, str(REPO_ROOT / "bughunter"))
        import engine
        assert engine._normalize_cli_argv(
            ["evil.example", "-recon"]) == ["recon", "evil.example"]
        assert engine._normalize_cli_argv(
            ["t.example", "--recon", "--scope-domain", "*.s.example"]) == \
            ["recon", "t.example", "--scope-domain", "*.s.example"]
        assert engine._normalize_cli_argv(
            ["t.example", "-recon", "--provider", "groq", "--model", "m1"]) == \
            ["recon", "t.example", "--provider", "groq", "--model", "m1"]
        assert engine._normalize_cli_argv(["recon", "t.example"]) == \
            ["recon", "t.example"]
        assert engine._normalize_cli_argv(["status"]) == ["status"]
        assert engine._normalize_cli_argv(["-recon", "t.example"]) == \
            ["-recon", "t.example"]

    def test_shorthand_target_recon_blocks_out_of_scope(self, rtw_env):
        """`bughunter <target> -recon` == `bughunter recon <target>`: an
        out-of-scope shorthand run hits the same pre-flight scope gate —
        exit 3, 0 packets sent, 0 tools executed."""
        env = os.environ.copy()
        env["BUGHUNTER_HOME"] = str(rtw_env["home"])
        env["BUGHUNTER_CAPABILITIES_FILE"] = str(rtw_env["capabilities"])
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "bughunter" / "engine.py"),
             "evil.example", "-recon", "--scope-domain", SCOPE[0]],
            cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
            timeout=120,
        )
        out = proc.stdout + proc.stderr
        assert proc.returncode == 3, out[-3000:]
        assert "SCOPE BLOCK" in out
        assert not rtw_env["marker"].is_file()

    def test_nmap_runs_on_first_party_origins_only(self, rtw_env):
        """Step 2A: with classification evidence, Phase 3 nmaps only
        FIRST_PARTY_ORIGIN targets and says so."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Phase 2.5" in out
        assert "FIRST_PARTY_ORIGIN target(s) only" in out
        assert "origin IPs only" in out
        classes = (rtw_env["recon_out"] / "hosts" / "host_classes.txt").read_text()
        assert "FIRST_PARTY_ORIGIN" in classes
        truth = json.loads((rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth["counts"]["cdn_edges"] == 0
        # The stub dig resolves no A records, so counts.origin_ips (which
        # counts resolved IPs) is 0 — the first-party classification itself
        # is what drives the origin-only nmap here.
        assert sum(1 for h in truth["hosts"]
                   if h["asset_class"] == "FIRST_PARTY_ORIGIN") >= 1

    def test_origin_only_nmap_skips_cdn_edges(self, rtw_env):
        """Step 2A: a host whose CNAME resolves into a CDN suffix is
        classified CDN_EDGE and skipped by Phase 3 — no nmap on edges."""
        dig_stub = rtw_env["stub_bin"] / "dig"
        dig_stub.write_text(
            "#!/bin/bash\n"
            'if [[ "${5:-}" == "CNAME" ]]; then echo "edge.cloudflare.net."; fi\n'
            "exit 0\n"
        )
        dig_stub.chmod(0o755)
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out = proc.stdout + proc.stderr
        assert proc.returncode == 0, out[-3000:]
        assert "Skipping nmap on CDN_EDGE host/IP" in out
        assert "No FIRST_PARTY_ORIGIN targets classified" in out
        classes = (rtw_env["recon_out"] / "hosts" / "host_classes.txt").read_text()
        assert "CDN_EDGE" in classes and "Cloudflare" in classes
        truth = json.loads((rtw_env["recon_out"] / "recon_truth.json").read_text())
        assert truth["counts"]["cdn_edges"] >= 1
        assert truth["counts"]["origin_ips"] == 0

    def test_recon_truth_delta_and_health_table(self, rtw_env):
        """Step 2B/2C + Step 1B fix 4: recon_truth.json (schema, provenance,
        tool_health), delta.json (first run → has_previous_run false; second
        run → archived prev + delta summary), and the health table in the
        Recon Summary."""
        proc = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        assert proc.returncode == 0
        recon_out = rtw_env["recon_out"]
        truth = json.loads((recon_out / "recon_truth.json").read_text())
        assert truth["schema_version"] == "1.0"
        assert truth["counts"]["live_hosts"] >= 1
        assert truth["hosts"][0]["cluster_id"]
        assert "live/httpx_full.txt" in truth["hosts"][0]["discovered_by"]
        assert truth["tool_health"], "tool_health must ingest rtw_manifest.json"
        delta = json.loads((recon_out / "delta.json").read_text())
        assert delta["has_previous_run"] is False

        proc2 = run_engine([TARGET, "--scope-domain", SCOPE[0]])
        out2 = proc2.stdout + proc2.stderr
        assert proc2.returncode == 0, out2[-3000:]
        assert (recon_out / "recon_truth.prev.json").is_file()
        delta2 = json.loads((recon_out / "delta.json").read_text())
        assert delta2["has_previous_run"] is True
        assert "Delta vs previous run" in out2
        # Step 1B fix 4: the 7-row recon health table prints at the end.
        assert "Capability" in out2 and "Net-New" in out2
