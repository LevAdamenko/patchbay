# PatchBay

**CVE in, verified patch out — and no proof, no PR.**

PatchBay is an agent pipeline built for the NVIDIA × Nebius hackathon 2026 (Coding and Agentic Engineering track). Give it a CVE id and it:

1. researches the advisory and the upstream fix with **Tavily**,
2. has **NVIDIA Nemotron** (via Nebius Token Factory) write a test that reproduces the vulnerability — it must be **red** on the vulnerable release,
3. has Nemotron write a patch that turns the test **green** without breaking the library's own regression tests,
4. runs a deterministic **mutation gate**: undo or weaken the patch, and the test must go red again,
5. renders a pull-request-style report in which every claim carries a SHA-256-hashed piece of evidence.

If any step cannot be proven, the pipeline refuses to produce a report. A model that says "fixed" is not evidence; a test that fails before the patch, passes after it, and catches every weakened version of the patch is.

## Try it in two minutes (no API keys)

The repository ships recordings of real Nemotron and Tavily responses, so the full pipeline replays offline: models are not called, but every test and patch still runs for real in the sandbox.

```bash
python3 -m venv .venv                         # Python 3.12 or newer
.venv/bin/pip install -e '.[dev]'
.venv/bin/python scripts/fetch_cases.py       # pinned, sha256-checked wheels of the vulnerable releases
.venv/bin/python -m patchbay.demo --offline   # all 3 CVEs, ~25 s
.venv/bin/python -m patchbay.web              # web UI on http://127.0.0.1:8000
```

**Known limitation:** the CVE-2024-22195 recording includes a retry whose prompt quotes a traceback with standard-library paths from the recording machine (Ubuntu, system Python 3.14). Anywhere else, replay stops at that case with `offline replay has no recorded answer`, and the run ends there, before CVE-2024-24762. On those machines run the other two with `--case CVE-2023-32681` and `--case CVE-2024-24762`; all three can be seen in the hosted demo at https://patchbay-demo.vercel.app.

Nebius retires `nvidia/nemotron-3-super-120b-a12b` on 9 November 2026. Offline replay is not affected; for live mode after that date, set `NEMOTRON_MODEL=nvidia/Nemotron-3-Ultra-550b-a55b`.

No Python at all? `site/` is a static copy of the web UI: `scripts/export_static_demo.py` runs the offline pipeline once and saves every event (with its timing) and every report as JSON, and the page plays them back in the browser. Serve it with `python3 -m http.server -d site` or any static host; the banner on the page says it is a replay.

What the CLI prints (abridged):

```
offline replay of recorded live Nemotron and Tavily responses
[research] ok: Found 10 sources
[brief] ok: Brief generated (CWE-200)
[repro] ok: Repro test confirmed RED (assertion)
[patch] ok: Patch passed repro and regression tests
[mutate] ok: Mutation gate passed (100%)
[report] ok: Report rendered successfully
...
# CVE-2024-24762: python-multipart fix
## Patch
-QUOTED_STR = br'"(?:\\.|[^"])*"'
+QUOTED_STR = br'"(?:[^"\\]*(?:\\.[^"\\]*)*)"'
## Evidence
| red        | timeout | ... | 3.017s |
| green      | passed  | ... | 0.395s |
| regression | passed  | ... | 0.347s |
Mutation score: **100%** (1/1 hunk reversals killed; 0/0 operator mutants killed).
Evidence digest (SHA-256): `39fea442…`
```

The web UI shows the same run stage by stage over server-sent events: pick a case, press Run, watch research → brief → repro → patch → mutation gate → report, then read the rendered report.

## The three demo CVEs

| Case | Package | Vulnerable → fixed | Class | What Nemotron's patch does |
|---|---|---|---|---|
| CVE-2024-24762 | python-multipart | 0.0.6 → 0.0.7 | ReDoS (CWE-1333) | rewrites the quoted-string regex so it cannot backtrack exponentially |
| CVE-2023-32681 | requests | 2.30.0 → 2.31.0 | credential leak (CWE-200) | re-adds `Proxy-Authorization` after a redirect only for `http` URLs, so HTTPS redirects stop leaking proxy credentials |
| CVE-2024-22195 | Jinja2 | 3.1.2 → 3.1.3 | attribute injection (CWE-79) | rejects `xmlattr` keys containing spaces — the essence of the official 3.1.3 fix |

All three are recorded from live runs against `nvidia/nemotron-3-super-120b-a12b`; all three pass the mutation gate at 100 %. Versions come from `cases/*/case.toml` and were checked on the real releases: red on the vulnerable wheel, green on the fixed one.

## How it works

```
 CVE id ──► 1 research ──► 2 brief ──► 3 repro ──► 4 patch ──► 5 mutation gate ──► 6 report
            (Tavily)      (Nemotron)  (Nemotron   (Nemotron    (deterministic)      (deterministic,
                                       + sandbox)  + sandbox)                         refuses w/o evidence)
                                                       ▲              │
                                                       └── survivors ─┘
```

**1 · Research (Tavily).** Tavily is the source of truth for *what* is broken. PatchBay searches advisory domains (`github.com`, `nvd.nist.gov`, `osv.dev`, `security.snyk.io`) for the description, affected and fixed versions, CWE and fix commit. Without sources there is no brief.

**2 · Brief (Nemotron).** Nemotron reads the sources and the vulnerable file and produces a structured brief: CWE, affected function, trigger, expected safe behaviour — each field cites a retrieved URL.

**3 · Repro (Nemotron + sandbox).** Nemotron writes `test_cve_repro.py`. It is accepted only if it is red on the vulnerable release because of an assertion failure or timeout (not an import or syntax error) **and** green on the release with the official upstream fix. That second check is an oracle the model never sees: it rejects tests that merely assert the bug exists, which no patch could ever turn green. Failures go back to Nemotron with the sandbox log, up to 3 attempts.

**4 · Patch (Nemotron + sandbox).** Nemotron answers with SEARCH/REPLACE edit blocks against the single target file; PatchBay computes the diff itself, so a malformed diff from the model cannot slip through. The patch must turn the repro green and keep the library's upstream regression tests green.

**5 · Mutation gate (deterministic).** The gate reverts each hunk of the patch and applies small operator mutations to the added lines, then reruns the repro test on each mutant. It passes only if every hunk reversal is caught and at least 80 % of operator mutants are caught. Mutants that survive are sent back to Nemotron with a request for a narrower patch — up to 4 patch attempts in total (shown as `retry` in the web UI).

**6 · Report (deterministic).** The report embeds the sources, brief, test, patch and an evidence table: SHA-256 of every test, patch and log, the outcome and duration of the red, green and regression runs, the mutation score, and one digest over all of it. The renderer refuses to emit a report if any of that is missing.

Deeper design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Where Nemotron and Tavily are used

| Call | Stage | Why it is needed |
|---|---|---|
| Tavily search (`search_depth=basic`) | research | grounds the brief in real advisories instead of the model's memory |
| Nemotron 3 Super 120B (`nvidia/nemotron-3-super-120b-a12b`), fallback Nemotron 3 Ultra 550B | brief, repro, patch, patch retry | reads sources and code, writes the reproduction test and the fix, narrows the fix when the gate finds survivors |

Nemotron runs on Nebius Token Factory through its OpenAI-compatible API (`patchbay/clients/nemotron.py`). It is a reasoning model, so `max_tokens` defaults to 32768; if the reasoning budget still eats the answer, PatchBay retries once without thinking.

## Live mode and recording fixtures

Offline replay is the default (`LIVE=0`). To call the real services:

```bash
export LIVE=1 NEBIUS_API_KEY=... TAVILY_API_KEY=...
.venv/bin/python -m patchbay.demo --case CVE-2024-24762
```

Settings are read from the environment, then from an optional secrets file outside the repo (`~/.config/hackathon/secrets.env`, or the path in `PATCHBAY_SECRETS_FILE`). See [`.env.example`](.env.example):

| Variable | Default | Meaning |
|---|---|---|
| `LIVE` | `0` | `1` = call Nebius and Tavily; `0` = replay `fixtures/` |
| `NEBIUS_API_KEY` | — | Nebius Token Factory key |
| `TAVILY_API_KEY` | — | Tavily key |
| `NEMOTRON_MODEL` | `nvidia/nemotron-3-super-120b-a12b` | primary model |
| `NEMOTRON_FALLBACK_MODEL` | `nvidia/Nemotron-3-Ultra-550b-a55b` | used if the primary fails |
| `NEMOTRON_MAX_TOKENS` | `32768` | completion budget, reasoning included |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Token Factory endpoint |
| `FIXTURES_DIR` | `fixtures` | where recordings are read from |

To record new fixtures, run `LIVE=1 python scripts/record_fixtures.py [--case CVE-ID] [--attempts N]`. It records into a staging directory and only replaces `fixtures/<case>/` when the whole pipeline succeeds; Tavily responses are cached in `.record-cache/` (gitignored) so retries do not spend search credits. Fixture keys are a hash of the request with run-to-run noise masked (pytest durations, sandbox temp paths, memory addresses), so replay is deterministic. Keys are never written to fixtures, logs or reports.

## Safety

- **Curated catalog only.** Users pick one of the vetted cases; there is no way to type an arbitrary CVE or upload code.
- **Local copies only.** Vulnerable releases are pinned, sha256-checked wheels downloaded once into gitignored `cases/<CVE>/site/`. Nothing is downloaded during a run, and the patch may touch exactly one file of that library.
- **No remote targets.** The "exploit" is a unit test that calls a local function with crafted input.
- **Sandboxed model code.** Model-written tests and patches run only in a subprocess sandbox: temporary directory, environment stripped of API keys, wall-clock timeout, and CPU, memory and process limits on Linux.

## Tests

```bash
.venv/bin/python -m pytest -q    # 138 tests: stages, sandbox, mutation gate, report guard, replay, web
```

Use `python -m pytest` rather than bare `pytest` so the `scripts` package is importable. Tests that need fake model output build synthetic fixtures in a temp directory and never touch `fixtures/`.

## Project layout

```
patchbay/
  clients/       Nemotron and Tavily clients, fixture record/replay
  stages/        research, brief, repro, patch
  pipeline.py    runs the stages, emits events, refuses on missing evidence
  mutate.py      mutation gate
  report.py      evidence-checked report renderer
  sandbox.py     isolated pytest runner
  demo.py        CLI demo
  web.py         FastAPI web UI with server-sent events (also renders the static page)
cases/           case.toml, upstream regression tests, reference fixes per CVE
fixtures/        recorded Nemotron and Tavily responses
scripts/         fetch_cases, record_fixtures, probe_nemotron, export_static_demo
site/            static replay of the web UI (generated by export_static_demo)
docs/            architecture
```

## License

MIT — see [`LICENSE`](LICENSE). The demo libraries keep their own licenses (Apache-2.0 and BSD-3-Clause) and are downloaded at setup, never committed.
