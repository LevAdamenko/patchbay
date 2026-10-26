# PatchBay architecture

PatchBay takes a CVE id and produces a pull-request-style report: what the
vulnerability is (with sources), a test that reproduces it, a patch, and proof
that the test actually guards the patch. The rule that drives the design:
**no proof, no PR.** The report generator cannot emit a report unless every
claim in it has machine-checkable evidence attached.

```
 CVE id ──► 1 research ──► 2 brief ──► 3 repro ──► 4 patch ──► 5 mutation gate ──► 6 report
            (Tavily)      (Nemotron)  (Nemotron   (Nemotron    (deterministic)      (deterministic,
                                       + sandbox)  + sandbox)                         refuses w/o evidence)
```

## Scope and safety

- Only a **curated catalog** of cases (3 for the demo). Judges pick a case;
  they cannot type an arbitrary CVE or upload code.
- Each case pins the vulnerable release of a permissively licensed
  pure-Python library. `scripts/fetch_cases.py` downloads the pinned wheels
  (sha256-checked, `--no-deps`, dependencies pinned too) into
  `cases/<CVE-ID>/site/` once, at setup or image build; third-party code is
  never committed and nothing is downloaded during a run. The patch may touch
  exactly one file of that library (`target` in `case.toml`).
- No exploit ever targets a remote system. The "exploit" is a unit test
  that calls a local function with crafted input.
- Model-written code (tests and patches) is untrusted and only runs inside
  the sandbox runner (see below).

## Package layout

```
patchbay/
  config.py        env + ~/.config/hackathon/secrets.env loading, LIVE flag
  clients/
    nemotron.py    OpenAI-compatible client for Nebius Token Factory
    tavily.py      REST client for https://api.tavily.com/search
    replay.py      fixture record/replay shared by both clients
  cases/           catalog loader (cases/<CVE-ID>/case.toml)
  stages/
    research.py    1  Tavily queries -> Source list
    brief.py       2  Nemotron -> VulnBrief (every field cites a Source)
    repro.py       3  Nemotron writes test -> sandbox -> must be RED for the right reason
    patch.py       4  Nemotron writes diff -> sandbox -> repro GREEN + upstream tests GREEN
    mutate.py      5  mutation gate over the patched lines
    report.py      6  Evidence -> PR markdown, or a refusal
  sandbox.py       isolated pytest runner
  evidence.py      Evidence dataclasses + hashing
  pipeline.py      runs stages, emits events
  web.py           FastAPI app: GET / (one HTML page), GET /run/<case> (SSE)
  demo.py          python -m patchbay.demo --offline [--case CVE-…]
cases/<CVE-ID>/
  case.toml        package, pinned wheels + sha256, license, advisory URLs,
                   target file, attribution
  site/            fetched wheels, unpacked (gitignored)
  tests/           functional regression tests for the target (ours, small)
fixtures/          recorded Nemotron/Tavily responses, one dir per case
scripts/record_fixtures.py   LIVE=1 run that refreshes fixtures/
```

## Stages

### 1. Research (Tavily)

Tavily is the source of truth for *what* is broken, so it sits on the core
path, not as decoration. Queries per case:

1. `"<CVE-ID> <package> advisory"` with `include_domains` =
   `github.com, nvd.nist.gov, osv.dev, security.snyk.io` — advisory text,
   affected/fixed versions, CWE.
2. `"<package> <fixed version> fix <CVE-ID> commit"` with
   `include_domains=["github.com"]` — the upstream fix commit/PR, used only
   as a hint for the brief, never copied into the patch.

Output: a list of `Source(url, title, snippet, retrieved_at)`.

### 2. Brief (Nemotron)

Nemotron (default `nvidia/nemotron-3-super-120b-a12b`, fallback
`nvidia/Nemotron-3-Ultra-550b-a55b`) turns the sources plus the target
file into a structured `VulnBrief` via tool calling / JSON output:
vulnerability class (CWE), affected function, a trigger input, the expected
safe behaviour. **Every field must cite a source URL from stage 1**; a field
without a citation is rejected and the stage retries once, then fails.

### 3. Repro (Nemotron + sandbox)

Nemotron writes `test_cve_repro.py` against the target library. The sandbox
runs it on the **unpatched** copy. Accepted only if the test fails *for the
right reason*:

- outcome is an assertion failure or a timeout (for ReDoS / infinite loops,
  the test uses a hard timeout), and
- not a collection error, `ImportError`, `SyntaxError`, `NameError`, or a
  failure in test setup.

Up to 3 attempts; the sandbox output of the failed attempt is fed back.

### 4. Patch (Nemotron + sandbox)

Nemotron returns a unified diff against the target file only (diffs that
touch any other path are rejected before applying). Accepted only if, in the
sandbox, the repro test is now GREEN **and** the case's upstream regression
tests are still GREEN (a patch that deletes the feature does not pass).
Up to 3 attempts.

### 5. Mutation gate (deterministic, no model)

Question it answers: *would the repro test notice if the fix were undone or
weakened?* Mutants are generated only on lines the patch touched:

- **hunk reversal**: undo each hunk of the patch on its own (all must be killed);
- **operator mutants** on added lines: flip comparisons (`<`↔`<=`, `==`↔`!=`),
  `and`↔`or`, drop a `not`, replace a returned/raised guard with `pass`,
  change numeric bounds by ±1.

Each mutant runs the repro test in the sandbox. A mutant is *killed* when the
test fails. Gate passes when every hunk-reversal mutant is killed and the
operator-mutant kill rate is ≥ 80 %. Survivors are listed in the report.
This is PatchBay's own implementation (hunk-scoped, patch-aware), written
from scratch for this repo.

### 6. Report (deterministic)

`report.render(evidence)` builds the PR markdown: title, CVE summary with
cited sources, the test, the diff, and an evidence table (red run, green run,
regression run, mutation score) with SHA-256 of every artifact and log. It
**raises `MissingEvidence`** if any of these is absent or inconsistent
(e.g. the test hash in the green run differs from the red run). Tests prove
this guard: removing any single piece of evidence makes rendering fail.

The demo stops at the report; it does not open a real PR anywhere.

## Sandbox runner

`sandbox.run(case, files, timeout)`:

- copies the case into a fresh temp dir, writes the candidate test/patch;
- runs `python -I -m pytest -q -p no:cacheprovider` in a subprocess with a
  stripped environment (no `NEBIUS_API_KEY`, no `TAVILY_API_KEY`, no proxy
  vars, `HOME` = temp dir), wall-clock timeout, and on Linux
  `RLIMIT_CPU` / `RLIMIT_AS` / `RLIMIT_NPROC`;
- parses the JUnit XML to classify the outcome (pass / assertion / timeout /
  error-kind), returns it with the captured log and its hash.

On the hosted demo the whole app runs in a container with no outbound network
except Token Factory and Tavily; the sandbox subprocess inherits that.

## Offline mode and fixtures

Both clients go through `replay.py`. With `LIVE=0` (default, used by tests and
the offline demo) responses come from `fixtures/<case>/<stage>-<n>.json`,
keyed by a hash of the request. With `LIVE=1` real calls are made;
`scripts/record_fixtures.py` writes them back. The sandbox, mutation gate and
report are never mocked — they run for real in both modes, so the offline demo
still proves the patch.

Keys come only from the environment (optionally loaded from
`~/.config/hackathon/secrets.env`); they are never logged or committed.
`.env.example` lists the variable names with empty values.

## Web demo

FastAPI serves one static HTML page with three case buttons. `GET /run/<case>`
streams stage events over SSE (`stage`, `status`, `detail`, `evidence_hash`),
so the whole path is visible in about 45 seconds: sources found → brief →
red test → patch → green → mutants killed → report.

## Checks

- `pytest -q` — unit tests per stage, sandbox outcome classification,
  mutation gate on a known-good and a known-weak test, report refusal tests.
- `python -m patchbay.demo --offline` — all 3 cases end to end, no keys.

## Demo cases (verified 13.10.2026 against the real releases)

Each pair was installed in a clean venv; the probe is red on the vulnerable
release and green on the fixed one.

| Case | Package (vulnerable → fixed) | Class | Probe |
|---|---|---|---|
| CVE-2024-24762 | python-multipart 0.0.6 → 0.0.7, Apache-2.0 | ReDoS (CWE-1333) | `parse_options_header('a/b; x="' + '\\' * n)` grows ~2.6× per +2 chars; 0.0.7 constant |
| CVE-2024-22195 | Jinja2 3.1.2 → 3.1.3, BSD-3 | attribute injection (CWE-79) | `xmlattr` with key `'x onclick="alert(1)" y'` renders an extra attribute; 3.1.3 raises `ValueError`. Only spaces are covered here (`/`, `>`, `=` are CVE-2024-34064, fixed in 3.1.4) |
| CVE-2023-32681 | requests 2.30.0 → 2.31.0, Apache-2.0 | credential leak (CWE-200) | `Session.rebuild_proxies` keeps `Proxy-Authorization` on an https request; 2.31.0 strips it |

Backups, also verified: sqlparse 0.4.3 → 0.4.4 (CVE-2023-30608, ReDoS) and
zipp 3.19.0 → 3.19.1 (CVE-2024-5569, infinite loop).
