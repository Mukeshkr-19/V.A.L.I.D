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
  - The workflows define no model secrets.
- **AI keys stay out of public output.** When an operator enables AI locally,
  the key is used only in the HTTP `Authorization` header. It is never placed
  in the request body, logs, artifacts, process arguments, environment
  variables of the transport process, or files (see
  [Transport lifecycle](#transport-lifecycle)).

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

AI is optional and advisory. It runs after the deterministic verdict, and its
result can only select explanation text.

**Input bounds (checked before any request is built):**

- At most 10 findings per request.
- Per finding: at most 16 evidence items. IDs are at most 128 characters,
  evidence summaries at most 4,000 characters, and each approved option at
  most 1,000 characters.
- A finding over any bound is not sent and keeps its template.
- Evidence summaries are redacted, then truncated to 500 characters.
- The serialized request is at most 64 KiB. Whole findings are dropped from
  the request to fit; evidence IDs are never truncated.
- Only redacted evidence summaries, evidence IDs and the approved options are
  sent. Raw Terraform, plans, state, file contents and repository-derived
  instructions are never sent.

**Output bounds:**

- The response is limited to 64 KiB, and the request asks for at most 800
  tokens.
- The response must be a JSON array covering exactly the requested findings.
  Each entry must have exactly the permitted keys, the finding's exact
  evidence IDs, its unchanged evidence strength, and title, why-it-matters
  and recommended-action text equal to the approved options. The response is
  validated as received and again after its text fields are redacted.

**Constrained wording.** The approved options are currently the single
deterministic template strings, so a valid response can only reproduce the
template wording. These checks prove that the explanation matches approved
text and the cited evidence IDs. They do not prove that arbitrary free-form
prose is grounded, and V.A.L.I.D. does not accept free-form prose.

**Template fallback.** Any of the following produces the deterministic
templates for every finding:

- no or invalid configuration;
- network, TLS, DNS, timeout or HTTP errors;
- redirects, oversized or unparsable responses;
- validation failures;
- an exhausted budget.

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
  - Each attempt's socket timeout is at most 10 seconds and never more than
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
  truth of free-form text. That is why only approved wording is accepted.
- **Static scope:** no plan, apply, state, drift or deployment validation.
  IPv6 exposure is outside the built-in SSH rule, and values that need
  resolution become coverage gaps rather than findings.
- **Verification so far:** local tests on macOS with Python 3.12, including
  loopback transport tests with synthetic credentials.
  - Not yet demonstrated: a clean Linux CI run, live PR comments, GitHub
    artifact transfer between jobs, a successful TLS session with a live
    provider, Nebius serving and account model availability.
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
