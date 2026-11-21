
<p align="center">
  <b>Agentic-Bug-Hunter — RhodawkAI Edition</b>
  <br/>
  A standalone fork of Agentic-Bug-Hunter with one addition: deterministic reconFTW
  capability delegation for the recon phase. Standalone release — no external stack ties;
  secrets stay entirely within this fork's own <code>config.json</code> / reconFTW's own
  <code>secrets.cfg</code>.
</p>

## RhodawkAI Edition — what's different

Wherever ABH's own recon pipeline hits a capability it doesn't have, it transparently
delegates to reconFTW's equivalent function — in all four runtimes (CLI engine, ReAct
agent, interactive harness, MCP server) — with zero confusion for whichever of ABH's 16+
LLM providers is configured, because the routing decision is **deterministic code, not an
LLM judgment call**. The LLM reads `~/.bughunter/capabilities.json` and follows an explicit
rule worded identically across every prompt layer; `tools/rtw_adapter.py` decides what
actually runs.

| Capability | reconFTW function | Runs in |
|---|---|---|
| ASN/CIDR enum (`CAP_ASN_ENUM`) | `sub_asn` | Phase 1.5 (before httpx) |
| DNS brute/permutation (`CAP_DNS_PERMUT`) | `sub_permut` | Phase 1.5 (before httpx) |
| CDN/origin isolation (`CAP_CDN_ISOLATE`) | `cdnprovider` | Phase 1.5 (before httpx) |
| JS source-map/AST secrets (`CAP_JS_SOURCEMAPS`) | `jschecks` | Phase 5.5 (before ffuf) |
| Virtual-host discovery (`CAP_VHOSTS`) | `virtualhosts` | Phase 5.5 (before ffuf) |
| TLS IP pivots (`CAP_TLS_PIVOTS`) | `tls_ip_pivots` | Phase 5.5 (before ffuf) |
| Favicon fingerprint (`CAP_FAVICON`) | `favirecon_tech` | Phase 5.5 (before ffuf) |

Guardrails: scope is fail-closed (`--scope-domain` required, or explicit
`--no-scope-check` for local demo testing); every output file is scope-filtered post-call;
`modules/vulns.sh` is never delegated — ABH's verifier spine remains the only thing allowed
to promote a finding; nothing ABH owns at parity is ever routed to reconFTW. With
`RTW_HOME` unset, everything behaves exactly as upstream ABH. Results are traced in
`~/.bughunter/recon/<host>/rtw_manifest.json` with an identical schema across all four
runtimes, deduplicated on a 7-day TTL.

Setup: `./install.sh` clones reconFTW at a pinned commit into `RTW_HOME`
(default `~/Tools/reconftw`) and builds `capabilities.json`; `bash install_tools.sh --rtw-deps`
installs only the 7 capabilities' backing binaries via pinned go-install. See
`docs/CAPABILITY-GAPS.md` and `CHANGELOG.md` for the full map.

---

<p align="center">
  <b>AI-powered bug bounty hunting — recon to report, in your terminal.</b>
  <br/>
  <a href="#what-is-this">What Is This</a>
  ·
  <a href="#standalone-mode-no-subscription-required">Free Setup</a>
  ·
  <a href="#quick-start">Quick Start</a>
  ·
  <a href="#commands">Commands</a>
  ·
  <a href="#what-it-finds">What It Finds</a>
  ·
  <a href="#more-from-rhodawkai">AXguard</a>
  ·
  <a href="#support-this-project">Support</a>
  ·
  <a href="FAQ.md">FAQ</a>
</p>


<p align="center">
  Built and maintained by <b>RhodawkAI</b> · <a href="https://rhodawkai.com">Website</a> · <a href="https://x.com/rhodawkai">X</a> · <a href="https://github.com/Rhodawk-AI">GitHub</a>
</p>


---

## Get started (30 seconds)

```bash
uv tool install agentic-bug-hunter   # install the CLI (or: pipx install agentic-bug-hunter)
bughunter setup                      # connect a free AI provider
```

Then hunt — straight from your terminal:

```bash
bughunter hunt target.com            # recon → find → validate → report
```

…or drive it from inside Claude Code:

```text
/hunt target.com
```

<sub>The CLI and AI hunting work on their own. Full recon also uses external tools
(subfinder · httpx · nuclei · katana · ffuf · nmap) — install them with
<code>install_tools.sh</code> from the repo. Output lands in <code>~/.bughunter/</code>.</sub>

---

## What Is This?

Agentic Bug Hunter finds real, reportable bugs, not theoretical ones. Point it at a target and it runs recon, tests for vulnerabilities, validates findings against a strict gate, and writes a submission-ready report for HackerOne, Bugcrowd, Intigriti, or Immunefi.

It remembers everything: patterns found on one target inform the next, and sessions pick up where they left off.

Works as a [Claude Code](https://claude.ai/claude-code) plugin, or as a fully standalone CLI (`bughunter`) with no subscription required.

---

## Standalone Mode: No Subscription Required

**You no longer need Claude Code, Claude Pro, or any paid AI subscription.**

Install once, use the `bughunter` command from any terminal on your machine:

```bash
git clone https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition.git
cd Agentic-Bug-Hunter
./install.sh --agent standalone
```

Rerun the same command after pulling updates. The installer detects and
refreshes the active managed `bughunter` command, including older installations
under `/usr/local/bin` or `~/.local/bin`, while preserving your saved provider
configuration in `~/.bughunter/config.json`.

To uninstall the standalone command while keeping its configuration:

```bash
./uninstall.sh --agent standalone
```

Use `--purge-config` to also delete `~/.bughunter/config.json`. The uninstaller
also supports `claude`, `antigravity`, `opencode`, `pi`, `codex`, `agents`, and `all` targets.

```
bughunter help               # show every command
bughunter setup              # choose your AI provider (Ollama is free + offline)
bughunter login              # login with Google OAuth (Antigravity / Gemini AI Pro — no API key)
bughunter recon target.com   # map the attack surface
bughunter hunt  target.com   # hunt for vulnerabilities
bughunter validate "finding" # 7-Question Gate on your finding
bughunter report             # write a submission-ready report
bughunter chat               # interactive AI hunting shell
bughunter providers          # list all available AI providers
bughunter models             # list models and show the selected one
bughunter status             # check which provider is active
bughunter h target.com       # short alias for hunt
bughunter r target.com       # short alias for recon
bughunter v "finding"        # short alias for validate
```

### Free AI Providers (auto-detected, free-first priority)

| Provider | Cost | Privacy | Speed | Get Started |
|:---|:---|:---|:---|:---|
| **Ollama** | 100% free · runs locally | Full - stays on your machine | Fast | `ollama pull qwen2.5:14b` |
| **Antigravity / Gemini** | Included with Gemini AI Pro (Google OAuth — no API key) | Cloud | Fast | `bughunter login` → `gemini-4-argon-high` / `claude-opus-5-5-high` |
| **Groq** | Free tier available | Cloud | Very fast | [console.groq.com](https://console.groq.com) → get API key |
| **DeepSeek** | Very cheap (v4-flash / v4-pro) | Cloud | Fast | [platform.deepseek.com](https://platform.deepseek.com) |
| Claude API | Paid | Cloud | Fast | [console.anthropic.com](https://console.anthropic.com) |
| OpenAI | Paid | Cloud | Fast | [platform.openai.com](https://platform.openai.com) |
| **Grok (xAI)** | Paid | Cloud | Fast | [console.x.ai](https://console.x.ai) → `grok-4.5` |
| **OpenRouter** | Subscription / pay-as-you-go | Cloud | Fast | [openrouter.ai/keys](https://openrouter.ai/keys) → get API key |
| **OrcaRouter** | Subscription / pay-as-you-go | Cloud | Fast | [orcarouter.ai](https://www.orcarouter.ai) → get API key |
| **LiteLLM** | Uses your existing provider keys | Cloud / self-hosted proxy | Fast | [docs.litellm.ai](https://docs.litellm.ai) → one gateway for 100+ models |
| **Requesty** | Pay-as-you-go | Cloud | Fast | [app.requesty.ai/api-keys](https://app.requesty.ai/api-keys) → get API key · [docs](https://docs.requesty.ai) |

BugHunter auto-detects providers in this order: **Ollama → Groq → DeepSeek → … → OrcaRouter → OpenRouter → Claude → OpenAI**. LiteLLM is opt-in (selected explicitly or when `LITELLM_API_KEY` is set) so it never preempts a provider you already configured. Requesty is opt-in the same way (selected explicitly or when `REQUESTY_API_KEY` is set); set `REQUESTY_BASE_URL=https://router.eu.requesty.ai/v1` to route through the EU region.

Switch providers or choose an installed Ollama model anytime: `bughunter setup`.
The setup can also be fully non-interactive:

```bash
bughunter setup --provider ollama --model qwen2.5:14b
```

For a one-off override, put the option before the command:

```bash
bughunter --provider ollama --model qwen3:14b hunt target.com
```

### Zero-cost fully offline setup

```bash
# 1. Install Ollama (runs AI locally, no internet needed after download)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:14b          # ~9 GB, one-time download

# 2. Install BugHunter
git clone https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition.git
cd Agentic-Bug-Hunter
./install.sh --agent standalone   # creates system-wide 'bughunter' command

# 3. Hunt
bughunter setup       # choose Ollama, then choose one of its installed models
bughunter recon target.com
```

### Groq setup (free cloud, fastest option)

```bash
export GROQ_API_KEY="your-key-here"     # free at console.groq.com
./install.sh --agent standalone
bughunter setup       # choose Groq
bughunter hunt target.com
```

---

## Quick Start

**Fastest - install from PyPI**

```bash
pip install agentic-bug-hunter
bughunter setup                   # pick a free AI provider
bughunter recon target.com
bughunter hunt  target.com
```

> Installs the `bughunter` and `bughunter-agent` commands. The AI hunting works out
> of the box; full recon also uses external CLIs (subfinder, httpx, nuclei, katana,
> ffuf, nmap). Get them with `install_tools.sh` from the repo, or your package
> manager. Output is written to `~/.bughunter/` (override with `BUGHUNTER_HOME`).

**Option A - standalone (no subscription, works for everyone)**

```bash
git clone https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition.git
cd Agentic-Bug-Hunter
./install.sh --agent standalone   # creates system-wide 'bughunter' command
bughunter setup                   # pick a free AI provider
bughunter recon target.com
bughunter hunt  target.com
bughunter validate "my finding"
bughunter report
```

**Option B - Claude Code plugin** *(requires Claude Code)*

```bash
git clone https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition.git
cd Agentic-Bug-Hunter
chmod +x install_tools.sh && ./install_tools.sh   # subfinder · httpx · nuclei · katana · ffuf
chmod +x install.sh      && ./install.sh          # skills + commands → ~/.claude/
```

```bash
claude
/recon target.com        # map the attack surface
/hunt target.com         # test for vulnerabilities
/validate                # run the 7-Question Gate
/report                  # write the submission
```

**Option C - let Claude install it** *(Claude Code only)*

Open your terminal, run `claude`, then paste:

```text
Install the Claude Bug Bounty toolkit from https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition
into ~/tools/. Clone the repo, run ./install_tools.sh then ./install.sh.
Verify /recon /hunt /validate /report are available.
```

---

## MCP

Use Agentic-Bug-Hunter from AI agents (Cursor, Claude Code, Codex, OpenCode).

```text
AI Agent → Agentic-Bug-Hunter MCP → Scope → Recon → Hunt → Validate → Report
```

```bash
pip install 'mcp>=2.2.0'
./install.sh --agent mcp
bughunter mcp doctor
bughunter mcp serve
```

MCP is an adapter over the existing research engine — not a second scanner. Active tools require scope and explicit approval. See [docs/mcp.md](https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition/blob/main/docs/mcp.md).

---

## Commands

### Core Workflow

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Subdomain enum · live host probing · URL crawl · nuclei sweep |
| `/hunt target.com` | Tests IDOR · auth bypass · SSRF · XSS · SQLi · logic flaws and more |
| `/validate` | 7-Question Gate - kills weak findings before you waste time reporting |
| `/report` | Generates an H1 · Bugcrowd · Intigriti · Immunefi submission in 60s |
| `/autopilot target.com` | Full loop, autonomous - scope → recon → hunt → validate → report |

### Recon & Enumeration

| Command | What It Does |
|:---|:---|
| `/surface target.com` | Ranked attack surface from recon data + memory |
| `/scope-aggregate <program>` | All in-scope assets across H1 · Bugcrowd · Intigriti · YWH · Immunefi |
| `/cloud-recon --keyword <name>` | Public S3 · Azure · GCP buckets + CloudFlare-bypass origin IPs |
| `/param-discover <url>` | Hidden HTTP parameters via Arjun · x8 |
| `/secrets-hunt --js-bundle <dir>` | Leaked credentials in source, JS bundles, or a GitHub org |
| `/takeover --recon <dir>` | Subdomain takeover candidates via dnsReaper · subjack |
| `/scan-cves <host>` | Focused nuclei high/critical sweep + optional log4j-scan |
| `/bypass-403 <url>` | Header · method · encoding tricks against 403/401 |
| `/portscan <host>` | Open ports + non-web services (Redis · Docker API · DBs · RDP) via naabu/smap |
| `/screenshot -l urls.txt` | Screenshot live hosts into an HTML gallery - triage + PoC evidence |

### Scanners (Web + LLM)

| Command | What It Does |
|:---|:---|
| `/cors <url>` | CORS misconfig - origin reflection · null · credentialed |
| `/crlf <url>` | CRLF / response-splitting + host-header injection |
| `/nosqli <url>` | NoSQL injection (operator bypass · `$where` timing) |
| `/jwt-scan <token>` | Offline JWT toolkit - alg:none · RS256→HS256 · secret crack |
| `/oob <target>` | Out-of-band listener (interactsh) for blind SSRF/XXE/SQLi |
| `/sast <path>` | Semgrep security packs over fetched JS/source → ranked sinks |
| `/domxss <url>` | Confirms DOM XSS in headless Chromium - reports only when the payload executes |
| `/llm-redteam <endpoint>` | LLM red-team corpus - prompt injection · jailbreak · exfil |

### Smart Contract (Web3)

| Command | What It Does |
|:---|:---|
| `/web3-audit <contract.sol>` | 10-class smart contract audit with Foundry PoC template |
| `/token-scan <contract>` | Rug pull scanner - mint authority · LP lock · honeypot · bonding curve |

### Session & Utility

| Command | What It Does |
|:---|:---|
| `/pickup target.com` | Resume from last session - untested endpoints first |
| `/intel target.com` | CVEs + disclosed reports relevant to this target |
| `/chain` | Bug A found → finds bugs B and C that chain with it |
| `/scope <asset>` | Checks if a domain or URL is in scope before you test it |
| `/triage` | Quick 2-minute go/no-go check |
| `/remember` | Logs the current finding or technique to hunt memory |
| `/memory-gc` | Inspect or rotate hunt-memory JSONL files (10 MB cap, 3 backups) |
| `/arsenal [tool]` | Lists installed external tools or prints an install hint |

---

## What It Finds

<details>
<summary><b>26 Web2 Vulnerability Classes</b></summary>
<br>

| Vulnerability | Typical Payout |
|:---|:---|
| IDOR / BOLA | $500 – $5K |
| Auth Bypass | $1K – $10K |
| XSS (Stored / Reflected / DOM) | $500 – $5K |
| SSRF | $1K – $15K |
| Business Logic | $500 – $10K |
| Race Conditions | $500 – $5K |
| SQL Injection | $1K – $15K |
| OAuth / OIDC | $500 – $5K |
| File Upload → RCE | $500 – $10K |
| GraphQL Auth Bypass | $1K – $10K |
| LLM / Prompt Injection | $500 – $10K |
| API Misconfiguration (mass assignment · JWT · CORS) | $500 – $5K |
| Account Takeover | $1K – $20K |
| SSTI | $2K – $10K |
| Subdomain Takeover | $200 – $5K |
| Cloud / Infra Exposure | $500 – $20K |
| HTTP Request Smuggling | $5K – $30K |
| Cache Poisoning | $1K – $10K |
| MFA / 2FA Bypass | $1K – $10K |
| SAML / SSO Attack | $2K – $20K |
| Error Disclosure / Debug Endpoints | $200 – $5K |
| CSS Injection | $500 – $5K |
| LFI → RCE | $1K – $15K |
| Insecure Deserialization | $5K – $30K |
| Dependency Confusion / Supply Chain | $1K – $20K |
| Padding Oracle / Crypto Misuse | $2K – $20K |

</details>

<details>
<summary><b>10 Web3 / Smart Contract Bug Classes</b></summary>
<br>

| Vulnerability | Typical Payout |
|:---|:---|
| Accounting Desync | $50K – $2M |
| Access Control | $50K – $2M |
| Incomplete Code Path | $50K – $2M |
| Off-By-One | $10K – $100K |
| Oracle Manipulation | $100K – $2M |
| ERC4626 Share Inflation | $50K – $500K |
| Reentrancy | $10K – $500K |
| Flash Loan Attack | $100K – $2M |
| Signature Replay | $10K – $200K |
| Proxy / Upgrade | $50K – $2M |

</details>

---

## AI Agents

Nine specialists, each built for one job:

| Agent | Role |
|:---|:---|
| `recon-agent` | Subdomain enum · live host discovery · URL crawl |
| `report-writer` | Impact-first reports that get paid, not N/A'd |
| `validator` | Runs the 7-Question Gate - kills weak findings |
| `web3-auditor` | Smart contract audit across 10 bug classes |
| `chain-builder` | Bug A → finds bugs B and C that chain with it |
| `autopilot` | Full hunt loop with safety checkpoints |
| `recon-ranker` | Ranks attack surface by highest-value targets first |
| `token-auditor` | Meme coin / token rug pull and security scan |
| `credential-hunter` | Wordlist gen → OSINT → breach-check → spray (hard-stop before spray) |

---

## How It Works

<div align="center">

```
   You ─▶ /recon ─▶ /hunt ─▶ /validate ─▶ /report
              │                  │
              ▼                  ▼
        Hunt Memory       7-Question Gate
   (persists across    (kills weak findings
       sessions)         before you submit)
```

</div>

Every tool in the pipeline is gated on whether it's installed - missing tools are skipped, not errors. Auth headers set once carry through httpx · katana · ffuf · nuclei · dalfox automatically.

---

## Project Structure

<details>
<summary><b>Click to expand the full tree</b></summary>
<br>

```
Agentic-Bug-Hunter/
│
├── skills/                    # AI knowledge bases - loaded as /skill-name
│   ├── bug-bounty/            # Master workflow - all vuln classes, LLM testing, chains
│   ├── bb-methodology/        # Hunting mindset · 5-phase workflow · session discipline
│   ├── web2-recon/            # Subdomain enum · live host discovery · URL crawl
│   ├── web2-vuln-classes/     # 26 bug classes with bypass tables
│   ├── security-arsenal/      # Payloads · bypass tables · gf patterns
│   ├── triage-validation/     # 7-Question Gate · 4 gates · never-submit list
│   ├── report-writing/        # Templates for H1 · Bugcrowd · Intigriti · Immunefi
│   ├── web3-audit/            # Smart contract bugs · Foundry PoC · 10 bug classes
│   ├── meme-coin-audit/       # Rug pull detection · LP attacks · bonding curve
│   ├── credential-attack/     # Password spray methodology · legal guardrails
│   └── client-reverse/        # Request-signing / anti-bot token reversal
│
├── commands/                  # 33 slash commands (/recon /hunt /validate /report …)
├── agents/                    # 9 specialized AI agents (recon, validator, reporter …)
│
├── tools/                     # Python + shell scanner pipeline (~35 tools)
│   ├── hunt.py                # Master orchestrator
│   ├── recon_engine.sh        # Subdomain + URL discovery
│   ├── vuln_scanner.sh        # XSS · SQLi · SSRF · SSTI probe pipeline
│   ├── validate.py            # 4-gate finding validator with identity checks
│   └── …                      # 30+ more scanners - see bughunter/tools/README.md
│
├── memory/                    # Cross-session hunt memory (pattern DB · audit log)
├── rules/                     # Always-active hunting + reporting rules
├── tests/                     # Regression test suite (pytest)
├── web3/                      # 13-chapter smart contract audit guide
├── mcp/                       # MCP — native BugHunter server + Burp · Caido · HackerOne
├── wordlists/                 # Curated wordlists + SecLists / PayloadsAllTheThings refs
├── scripts/                   # Dork runner · full hunt pipeline
├── hooks/                     # Claude Code hook configuration
├── site/                      # rhodawkai.com landing page
├── demo/                      # Local vulnerable target for tutorial recordings
│
├── docs/                      # Extended documentation
│   ├── advanced-techniques.md # Exploitation techniques + chaining strategies
│   ├── auth-sessions.md       # Auth header management guide
│   ├── payloads.md            # Payload reference for common vuln classes
│   ├── smart-contract-audit.md# Smart contract audit deep-dive
│   ├── TUTORIAL.md            # A→Z video tutorial walkthrough
│   └── TODOS.md               # Open improvement items
│
├── .github/                   # GitHub community health files
│   ├── CONTRIBUTING.md        # How to contribute
│   ├── CODE_OF_CONDUCT.md     # Community standards
│   ├── SECURITY.md            # Vulnerability reporting policy
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/        # Bug report · Feature request · False positive
│
├── engine.py                  # Standalone CLI - 'bughunter' command, no subscription needed
├── brain.py                   # Multi-provider LLM layer (Ollama · Groq · DeepSeek · Claude · OpenAI)
├── agent.py                   # LangGraph-style ReAct hunting agent
├── install.sh                 # Install skills + commands → ~/.claude/ (or standalone mode)
├── install_tools.sh           # Install subfinder · httpx · nuclei · katana · ffuf …
├── uninstall.sh               # Remove skills + commands from ~/.claude/
├── uninstall_tools.sh         # Remove external scanning tools
├── serve.py                   # Launch local demo target (python3 serve.py)
├── config.example.json        # Auth session config template
├── requirements.txt           # Python dependencies
├── CLAUDE.md                  # Claude Code plugin manifest (auto-loaded)
├── AGENTS.md                  # Multi-harness plugin guide (OpenCode · Codex · Pi)
├── SKILL.md                   # Master skill shortcut (auto-loaded by agent harnesses)
├── OPENCODE.md                # OpenCode-specific installation guide
├── CHANGELOG.md               # Version history
├── FAQ.md                     # Frequently asked questions
└── TERMS.md                   # Terms of use + authorized testing only
```

</details>

---

## Installation

**Prerequisites:**

```bash
# macOS
brew install go python3 jq

# Linux (Ubuntu/Debian)
sudo apt install golang python3 jq
```

**Scanning tools** (installs subfinder · httpx · nuclei · katana · ffuf · gau · dnsx · nmap · dalfox and more):

```bash
chmod +x install_tools.sh && ./install_tools.sh
```

**Standalone `bughunter` command** (no subscription, works without Claude Code):

```bash
./install.sh --agent standalone
bughunter setup    # choose Ollama (free) · Groq (free tier) · DeepSeek (cheap) · Claude · OpenAI
```

**AI skills + commands** into Claude Code:

```bash
chmod +x install.sh && ./install.sh
```

**Other agent harnesses:**

```bash
./install.sh --agent antigravity # Google Antigravity / Gemini (~/.gemini/config)
./install.sh --agent opencode    # OpenCode
./install.sh --agent pi          # Pi Agent
./install.sh --agent codex       # Codex
./install.sh --agent all         # every supported target
```

**Optional: Chaos API key** (better subdomain coverage)

```bash
export CHAOS_API_KEY="your-key"
echo 'export CHAOS_API_KEY="your-key"' >> ~/.zshrc
```

---

## Rules

Seven rules run every session, no exceptions:

| # | Rule | Why |
|:-:|:---|:---|
| 1 | **Read full scope first** | Only test what the program authorizes |
| 2 | **Real bugs only** | "Can an attacker do this RIGHT NOW?" - if no, stop |
| 3 | **Kill weak findings** | A 30-second check saves hours of wasted reporting |
| 4 | **Never go out of scope** | One wrong request can get you banned |
| 5 | **5-minute rule** | No progress after 5 minutes? Move on |
| 6 | **Validate before report** | `/validate` before spending 30 minutes writing |
| 7 | **Impact first** | Test the bugs with the worst consequences first |

---

## Contributing

PRs welcome. Most valuable:
- New scanner modules or detection techniques
- Payload additions to `skills/security-arsenal/SKILL.md`
- Methodology improvements backed by paid reports
- Platform support (YesWeHack · Synack · HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "feat: short description"
git push origin feature/your-contribution
```

---

## Used By

<p align="center"><i>Teams and researchers running BugHunter in their workflow.</i></p>

<p align="center">
  <a href="https://github.com/MogasalaHemagiri"><b>MogasalaHemagiri</b></a> ·
  <a href="https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition">Agentic-Bug-Hunter-RhodawkaiEdition</a>
</p>

---

<p align="center">
  <a href="https://github.com/MogasalaHemagiri/Agentic-Bug-Hunter-RhodawkaiEdition">GitHub</a>
  ·
  <a href="https://x.com/rhodawkai">X</a>
  ·
  <a href="https://rhodawkai.com">Website</a><br>
  <b>Built by bug hunters, for bug hunters.</b><br>
  <sub>MIT License · For authorized security testing only. Always test within an approved bug bounty program scope.</sub>
</p>

<p align="center">
Built and maintained by <b>RhodawkAI</b> · <a href="https://rhodawkai.com">Website</a> · <a href="https://x.com/rhodawkai">X</a> · <a href="https://github.com/Rhodawk-AI">GitHub</a>
</p>