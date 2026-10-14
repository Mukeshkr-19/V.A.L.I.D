# Security model

This document describes what V.A.L.I.D. trusts, what it protects, and where
its protections stop. It describes the current implementation; it is not a
certification or compliance statement.

## Trust boundaries

**Pull-request content is data.** In `.github/workflows/valid.yml`:

- **Reviewer code comes from the base commit.**
  - The scan job checks out the PR base commit into `trusted-base/`. It
    installs dependencies from that commit's `requirements-lock.txt` and runs
    that commit's wheel and `scripts/ci_scan.py`.
  - The PR head commit is checked out separately into `pr-head/` and is only
    scanned, never imported or executed.
  - Both checkouts use `persist-credentials: false`.
- **Job permissions are minimal.**
  - Workflow-level permissions are empty. The scan job has `contents: read`
    only.
  - The report job adds `pull-requests: write` to update one comment. It does
    not check out or run PR code; it reads the downloaded artifacts.
- **The comment and gate check what they read.**
  - The sticky comment is used only if its first line is the
    `<!-- valid-report -->` marker, and is capped at 60,000 bytes.
  - It is skipped if the scan record or the live PR head no longer matches
    the commit that was scanned.
  - The gate fails unless the record's head commit, completion flags, exit
    codes, all six artifacts and the verdict agree.
- **The workflow file itself is not protected by this split.** For
  `pull_request` events GitHub uses the workflow definition from the pull
  request, so a pull request can change `valid.yml`. Protect
  `.github/workflows/` with required human review, for example code-owner
  rules and branch protection.

**Scanned Terraform.** The analyzer parses Terraform as text, using a real HCL
parser and Checkov. It never runs Terraform, providers or plugins from the
scanned tree, and makes no cloud API calls. A Checkov configuration file
(`.checkov.yaml` or `.checkov.yml`) in the scanned tree could skip checks or
change results, so such a scan is refused as `INCOMPLETE`. The output
directory may not be
inside the scanned input, must be new or empty, and may not be a symbolic
link.

## Credential isolation

- **PR scans run without provider keys.**
  - The CI wrapper starts the analyzer with every environment variable whose
    name matches `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `API_KEY`,
    `PRIVATE` or `CREDENTIAL` (case-insensitive) removed, plus all `PYTHON*`
    variables.
  - The analyzer's stdout and stderr are discarded, and public diagnostics
    contain only stage names, error types and exit codes.
  - The scan and report workflows define no model secrets. The separate trusted
    AI-enrichment job introduces its key only during evidence review.
- **AI keys stay out of public output.** When an operator enables AI locally,
  the key is used only in the HTTP `Authorization` header. It is never placed
  in the request body, logs, artifacts, process arguments, environment
  variables of the transport process, or files (see
  [Transport lifecycle](#transport-lifecycle)).

## Trusted GitHub AI enrichment

`valid-ai.yml` runs on completion of the existing PR-review workflow. It checks
out the immutable default-branch event SHA, never PR source. API checks require
one current open same-repository PR targeting the default branch and an author
with write/maintain/admin access. The scan workflow must be unchanged between
the PR base and head. Forks, non-writing authors, changed scanner workflows,
cancelled runs and stale heads are excluded before introducing the model key.

The job has contents:read, actions:read and pull-requests:write and a six-minute
deadline. The source artifact must be unique, unexpired and at most 8 MiB.
Downloaded records must contain exactly the six bounded regular scan files;
their schemas, counts, evidence references, verdict and recorded exit must agree.
INCOMPLETE records cannot trigger inference. The model key is scoped to one
enrichment step after trusted dependencies are installed. The existing inference
bounds apply: ten distinct issues, 2,400 output tokens and a shared 20-second
budget with at most one transient retry.

Original artifacts and the scan record remain byte-for-byte unchanged; advice
is published separately. The publisher rechecks the live PR head immediately
before updating only the existing bot-owned marker comment. It never creates
a competing comment. Comment errors are nonfatal and cannot alter the gate.
Provider failure or missing keys visibly retains basic guidance. Protect workflow
files through human review; repository writers can edit trusted default-branch
code and therefore remain part of the operator's trust boundary.

## Raw-artifact minimization

- `raw_checkov.json` keeps an explicit minimal set of fields per failed check
  (`check_id`, `check_name`, `severity`, `file_path`, `file_line_range`,
  `resource`) plus scan coverage.
  Checkov source excerpts (`code_block`), definitions, evaluated values and
  unknown nested data are dropped.
- Retained free text is sanitized: private absolute paths and recognizable
  credential patterns are removed.
- Tests place a synthetic canary in a Terraform literal and in every
  non-retained field. They check that the canary appears in none of the six
  published artifacts and that repeated scans are byte-identical.
- `comment.md` HTML-escapes report text and masks recognizable token and
  credential-assignment patterns.

## Fail-closed coverage

- A failed required stage, a required coverage gap, or a required check that
  could not be evaluated makes the verdict `INCOMPLETE` (exit 1). This covers
  policy loading, Checkov, parsing, custom rules, normalization, risk and
  report generation.
- Missing scanner output never becomes `PASS`.
- If the report cannot be rendered, a conservative `INCOMPLETE` report is
  published instead. It says which stage failed and what the verdict was
  before the failure.
- In CI, a missing, mismatched or invalid scan record fails the gate.

## AI explanations: bounded and constrained

AI supplies advisory impact explanations, proposed actions and verification
questions after the deterministic verdict. Its generated prose cannot change
detector findings, evidence strength, policy, score, verdict or exit code.
The report labels accepted generated advice separately from basic guidance.

**Input bounds (checked before any request is built):**

- At most 10 distinct issue representatives per request. Matching built-in and
  Checkov detections on the same resource share advice but retain their own IDs.
- Per finding: at most 16 evidence items. IDs are at most 128 characters,
  evidence summaries at most 4,000 characters, and each approved option at
  most 1,000 characters.
- A finding over any bound is not sent and keeps its template.
- Evidence summaries are redacted, then truncated to 500 characters.
- The serialized request is at most 64 KiB. Whole findings are dropped from
  the request to fit; evidence IDs are never truncated.
- Redacted evidence summaries, evidence IDs, resource/path identity, start line,
  rule, priority, policy and basic guidance are sent. Raw Terraform, plans,
  state, file contents and repository-derived instructions are never sent.

**Output bounds:**

- The response is limited to 64 KiB, and the request asks for at most 2,400
  tokens.
- The response must be a JSON array covering exactly the requested findings.
  Each entry must have exactly the permitted keys, the finding's exact
  evidence IDs and unchanged evidence strength. Generated titles are bounded
  at 140 characters, impact explanations at 1,200 and proposed actions at
  1,600. Validation runs before and after redaction. The model cannot supply
  the advice-origin field; the validator computes it.

**Advisory wording.** The basic template is context, not mandatory copy text.
The validator rejects unknown finding/evidence IDs, altered strength, extra
fields, specific unsupported resource/network/port/source-line references,
hidden control characters and selected unsafe instructions or assurances.
Unknown severity and uncertain evidence require a verification caveat.
These are bounded structural and identifier checks, not complete semantic
verification: plausible but unsupported prose may pass. Human review is required.
Report text is escaped and redacted. Terraform examples come from a reviewed
product catalog, not provider-generated code, and are never executed.

**Template fallback.** Any of the following produces the deterministic
templates for every finding:

- no or invalid configuration;
- network, TLS, DNS, timeout or HTTP errors;
- redirects, oversized or unparsable responses;
- validation failures (including prompt-injection output that violates the contract);
- an exhausted budget.

Unselected issues keep basic guidance too. Identical template copies are labeled
basic even when returned by a provider. Generated prose can vary across calls;
exact-repeat guarantees apply to basic-mode scans, not live generated advice.
Findings, summary, verdict and exit code are unaffected by provider failure.
On completed scans, `ai.json` contains one explanation per finding in finding
order. A genuine failure of the deterministic templates makes reporting
`INCOMPLETE`; that recovery can preserve findings while publishing an empty
explanation list.

**Provider configuration:**

- Configuration comes only from explicit environment variables, with no
  defaults.
- `nebius` accepts only `https://api.tokenfactory.us-central1.nebius.com/v1`
  and `nvidia/` model identifiers.
- Malformed endpoints are rejected without any network call. That includes
  non-HTTPS URLs, embedded credentials, query or fragment, bad ports, unusual
  path segments, and keys with whitespace or control characters.

## Transport lifecycle

The production transport (`valid/_ai_transport.py`, standard library only)
runs each attempt in a short-lived child Python process.

- **What runs in the child:** name resolution, TCP connect, TLS handshake,
  request send and response reads.
- **How the child is started:**
  - command `python -I -B -c <bootstrap> <package directory>`, which ignores
    `PYTHON*` variables and the user site and writes no bytecode;
  - working directory `/`, in its own process session;
  - environment reduced to `PATH`, plus `SSL_CERT_FILE` and `SSL_CERT_DIR`
    when set;
  - stderr discarded.
- **How the key reaches the child:** the request, including the
  `Authorization` header, is sent over the child's stdin pipe (at most
  1 MiB). It is not in arguments, the environment, files or logs. The child
  writes one JSON result to stdout.
- **What the child does:**
  - TLS uses the default certificate and host-name verification.
  - Environment proxies are not used.
  - The child opens one connection explicitly, then disables `http.client`
    automatic reconnection, so a closed socket cannot trigger a second
    connection.
  - It sends one POST and never follows redirects: any 3xx response is a
    failure.
- **Deadline:**
  - One shared 20-second wall-clock budget covers request preparation, all
    attempts, response reads, parsing and validation.
  - Each attempt's socket timeout is at most 20 seconds and never more than
    the remaining budget.
  - At most one retry, only after a transport error, HTTP 429 or 5xx, and
    only if budget remains.
  - A result that completes after the deadline is discarded.
- **Cancellation:**
  - When the budget expires, the parent sends `SIGKILL` to the child's
    process group, which contains only that child, and reaps it before
    returning the template fallback. It uses a two-second initial reap wait;
    if that times out, it kills and waits for exit again. The AI budget is
    not an unconditional bound on total CLI elapsed time.
  - No resolver call, connection or send from that attempt continues after
    the fallback is returned.
  - Bytes the child had already handed to the operating system before the
    kill may still be transmitted by the kernel.
- **Platforms:** process-group kill is used where available (macOS, Linux).
  Windows is untested.

`valid.explain.explain()` also accepts a `transport` callable. That is a test
interface: such callbacks run in a thread whose late result is discarded but
which cannot be forcibly stopped. The process-isolation guarantees above
apply only to the default production transport used by the CLI.

## Limitations

- **Redaction** masks documented patterns only:
  - private absolute paths (`/Users/`, `/home/`, `/private/`, `/tmp/`,
    Windows drive paths);
  - AWS access-key IDs and GitHub token shapes;
  - `password`/`secret`/`api_key`/`access_token` `=`/`:` assignments;
  - `CANARY_` test markers.

  It cannot recognize every secret. Do not put secrets in Terraform, and
  treat artifacts from private repositories as private.
- **Schema and ID checks** prove structure, coverage and identity, not the
  truth of generated prose. Proposed actions require environment-specific review.
- **Static scope:** no plan, apply, state, drift or deployment validation.
  IPv6 exposure is outside the built-in SSH rule, and values that need
  resolution become coverage gaps rather than findings.
- **Verification so far:** local tests on macOS with Python 3.12, including
  loopback transport tests with synthetic credentials.
  [Linux CI](https://github.com/Mukeshkr-19/V.A.L.I.D/actions/runs/38176382089)
  also passed the test suite, installed-wheel fixtures and exact artifact repeats;
  its optional actionlint test was skipped because the binary was unavailable.
  Both workflows passed actionlint locally.
  - The [demo PR](https://github.com/Mukeshkr-19/V.A.L.I.D/pull/1) demonstrated
    blocking risky input, blocking missing-input recovery and passing fixed input,
    artifact transfer between jobs, successful job-summary writes and updates to
    one sticky bot comment. No infrastructure was deployed.
  - A [bounded live synthetic smoke](demo.md#live-verification-receipt) on
    October 12, 2026 (UTC) verified production HTTPS transport, Nebius Token
    Factory serving `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`, and strict
    explanation acceptance. Findings, summary and verdict were unchanged.
    This is evidence for one account and one request under the earlier
    template-copy contract; it does not prove the new generated-advice behavior.
    PR scans remain key-free; the separate AI workflow needs a configured secret
    and live verification before its serving behavior can be claimed.
  - Not yet demonstrated: Windows behavior, live generated advice under this
    contract or live AI in GitHub PR jobs. Earlier Linux evidence predates
    this contract; consult checks for the current commit.
  - Dependency versions are pinned, but the lock file does not pin hashes.

## Sharing reports safely

- Share the published artifacts (`comment.md`, `summary.json`,
  `findings.json`, `ai.json`, `raw_custom.json`, `raw_checkov.json`), which
  are minimized and sanitized as described above. Still review them before
  sharing outside your organization: resource names, file names and evidence
  summaries come from your Terraform.
- Do not share Terraform state, plans, `.tfvars` files, `.env` files, shell
  history or terminal logs. They can contain credentials and are not
  sanitized by V.A.L.I.D.
- Never include API keys in issues, pull requests, comments or screenshots.
  If a key may have been exposed, revoke it with the provider.

## Reporting problems

Report bugs through the issue tracker of the repository where you obtained
V.A.L.I.D. Include:

- the V.A.L.I.D. version;
- the Python and Checkov versions;
- the command you ran, its exit code and the status line;
- a minimal synthetic Terraform example that reproduces the problem.

For a suspected security issue, do not post exploit details, real Terraform
from private systems, or any credential in a public issue. Use the hosting
platform's private vulnerability reporting if the repository enables it;
otherwise open a minimal public issue asking the maintainers for a private
channel.
