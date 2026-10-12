# V.A.L.I.D.

**Verification and Analysis Layer for Infrastructure Diffs**

A GitHub Action and Python CLI that review Terraform code and answer:
**“Does this change need attention before it is merged?”**

For example, a Terraform file that opens SSH to the internet or disables
database deletion protection receives **HIGH RISK**, with the exact resource,
rule and evidence explaining why.

V.A.L.I.D. uses deterministic checks to choose the verdict. It works with
**no model key, no cloud account and no Terraform installation**. Optional AI
can explain supplied evidence only; it cannot create findings, choose the
verdict, change the exit code, deploy infrastructure or merge a PR.

## Start here

- **Try the tool:** follow the five-minute demo below.
- **Read a result:** open `comment.md` for people or `summary.json` for automation.
- **Use it on a PR:** put Terraform in `infra/` and open a pull request.
- **See the walkthrough:** [Demo guide](docs/demo.md).
- **Understand the safeguards:** [Security guide](docs/security.md).

## Setup

Use **Python 3.12**. Package installation needs internet access.
These commands start from a fresh clone:

```sh
git clone https://github.com/Mukeshkr-19/V.A.L.I.D.git
cd V.A.L.I.D
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pip check
```

The lock file includes Checkov, the required Terraform scanner. Missing
Checkov produces `INCOMPLETE`; it does not produce a clean bill of health.

## Five-minute demo

Run these commands from the repository root in the activated environment.
Disable the optional provider so this demo makes no model calls:

```sh
export VALID_AI_PROVIDER=disabled
DEMO_DIR=$(mktemp -d)

python -m valid scan --path fixtures/risky --output "$DEMO_DIR/risky"
echo "risky exit=$?"

python -m valid scan --path fixtures/fixed --output "$DEMO_DIR/fixed"
echo "fixed exit=$?"
```

| Example | Expected verdict | Exit | What it shows |
|---|---|---|---|
| `fixtures/risky` | **HIGH RISK** | **1** | Public SSH, missing tags and disabled RDS deletion protection |
| `fixtures/fixed` | **REVIEW** | **0** | The blocking built-in issues are fixed; other Checkov findings still need review |

**Exit 1 for the risky example is the expected result.** It means the gate
would block that revision. The fixed example is REVIEW rather than PASS
because unmapped Checkov findings have unknown severity; fixing the three
built-in issues does not make the entire Terraform tree issue-free.

Read the reports:

```sh
cat "$DEMO_DIR/risky/comment.md"
cat "$DEMO_DIR/fixed/comment.md"
python -m json.tool "$DEMO_DIR/fixed/summary.json"
```

Each scan needs a **new or empty output folder**. The demo creates a fresh
temporary folder every time, so repeat runs do not overwrite evidence.
The reports describe static source code; no infrastructure is created.

## Scan your Terraform

```sh
python -m valid scan --path infra --output out/my-scan-1
```

Replace `infra` with your Terraform directory. Replace the output path for
the next run, or choose another empty directory. Output cannot be inside
the scanned directory or point through a symbolic link.

## Understand the verdict

| Verdict | Meaning | Exit |
|---|---|---|
| **PASS** | Analysis completed and no policy condition requires review or blocking | 0 |
| **REVIEW** | Analysis completed, but findings or unknown severity need human review | 0 |
| **HIGH RISK** | An evaluated deterministic finding matches a blocking high/critical policy | 1 |
| **INCOMPLETE** | Required analysis failed or could not cover required checks | 1 |

`INCOMPLETE` takes precedence over `HIGH RISK`, then `REVIEW`, then `PASS`.
Missing input, malformed Terraform and scanner failures cannot silently pass.
The score is informational; it does not decide the verdict.

## How it works

```text
Terraform source
    → Checkov + three built-in rules
    → normalized findings and evidence IDs
    → deterministic risk verdict
    → template explanations (optional constrained AI)
    → Markdown report + JSON artifacts
```

The three built-in checks cover:

- SSH ingress open to `0.0.0.0/0` on TCP 22.
- Missing or empty `owner` / `environment` tags on supported AWS resources.
- Explicitly disabled RDS deletion protection.

Checkov adds its own policy checks. Values that require variable, module or
expression resolution can become visible coverage gaps. This is a source
scanner: it does not read plans or state and does not know whether a resource
is being created, changed or destroyed. Two detectors can report the same risk.

## What appears on a pull request

The included workflow scans **`infra/` from the PR head** using reviewer
code from the trusted base commit. It publishes:

1. One sticky comment that updates when another commit is pushed.
2. The report in the job summary.
3. Downloadable scan artifacts.
4. A passing or failing review gate.

To try it, change `infra/main.tf` on a new branch and open a PR to `main`.
That file is a copy of the fixed synthetic fixture for demonstration.
The workflow does not deploy it.

**Merge blocking requires a repository branch-protection rule.**
The workflow reports a failed check; it does not configure branch protection.
Fork PRs may lack permission to post a comment, while summaries, artifacts and
the gate still work. Workflow-file changes themselves require human review.

## Report files

| File | Use it for |
|---|---|
| `comment.md` | Human-readable verdict, findings and recommended actions |
| `summary.json` | Verdict, score, counts and coverage for automation |
| `findings.json` | Individual findings, locations and evidence IDs |
| `raw_checkov.json` | Sanitized retained Checkov records |
| `raw_custom.json` | Built-in findings and parser coverage |
| `ai.json` | Evidence-linked explanations, including template-only runs |

The name `ai.json` does **not** mean a model was called. Completed no-key
scans write template explanations to this file too. Normal scan publication
writes all six files together; an output-write failure rolls back the files
created by that run.

## Run the tests

With the setup above and **Node.js on PATH** for the workflow-comment tests:

```sh
export VALID_AI_PROVIDER=disabled
python -m pytest tests -q -p no:cacheprovider -rs
```

The CLI does not need Node.js. Install `actionlint` to include workflow linting
in the test suite; that optional test is skipped when the binary is missing.

## Optional AI: what to expect

Templates are the default and the fallback on every provider failure.
The current AI contract accepts only approved template wording, so it does
**not** generate new advice or improve the wording. Findings, verdict and exit
code remain the same with or without a provider.

**Live Nebius integration verified:** on October 12, 2026 (UTC), one bounded
request with synthetic finding evidence returned HTTP 200 from Nebius Token
Factory using `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`. V.A.L.I.D. accepted the
explanation; the deterministic findings, summary and HIGH RISK / exit 1 result
stayed unchanged. See the [verification receipt](docs/demo.md#live-verification-receipt).

This proves serving for the tested account at that time. Confirm the exact,
case-sensitive model ID in your own account's catalog. Templates still work
without a key, and GitHub PR scans remain template-only.


<details>
<summary>Built-in rules, scanner policy and coverage details</summary>

## What it checks

Three built-in rules read Terraform literally (a real HCL parser; no variable,
module or expression resolution):

| Rule | Detects | Priority / policy |
|---|---|---|
| `DG-AWS-NET-001` | Security-group ingress open to `0.0.0.0/0` on TCP 22 | high / block |
| `DG-AWS-RDS-001` | `aws_db_instance` with explicit `deletion_protection = false` | high / block |
| `DG-AWS-TAG-001` | Missing or empty required tags (`owner`, `environment`) on `aws_security_group`, `aws_instance`, `aws_db_instance` | medium / warn |

Checkov 3.3.8 also runs on the same directory. Two Checkov checks are mapped
explicitly by the packaged policy (`valid/data/checkov_severity.yaml`):
`CKV_AWS_24` (public SSH, high / block) and `CKV_AWS_293` (RDS deletion
protection, high / block). Every other Checkov failure keeps its scanner
severity, which Checkov 3.3.8 does not report offline, so it is recorded as
`unknown` with policy `warn`.

When a value cannot be read literally (for example a CIDR or tag map built
from a variable), the affected check is reported as a visible coverage gap
instead of being silently skipped.

### Scope

- Static analysis of the Terraform source tree only. There is no
  `terraform init`, `plan` or `apply`, no state or plan reading, no cloud API
  access, and no deployment or merge action.
- Every finding has `change_action: "unknown"`: the tool does not know whether
  a resource is being created, changed or destroyed.
- Counts are detector findings. Checkov and a built-in rule can describe the
  same underlying risk, so one problem may appear twice.

## Verdicts and exit codes

| Status | When | Exit |
|---|---|---|
| `INCOMPLETE` | A required stage failed, a required coverage gap exists, or a required check could not be evaluated | 1 |
| `HIGH RISK` | An evaluated, deterministic high/critical finding with `block` policy | 1 |
| `REVIEW` | Unknown severity, a heuristic or `warn` finding, low/medium findings, non-blocking high findings, or optional gaps | 0 |
| `PASS` | None of the above | 0 |

Precedence is top to bottom: `INCOMPLETE` wins over `HIGH RISK`, which wins
over `REVIEW`. The numeric score (info 0, low 1, medium 3, high 7, critical 10;
unknown and not-evaluated excluded) is reported but does not choose the
verdict.

Because unmapped Checkov checks have `unknown` severity, a Terraform tree with
any unmapped Checkov failure is at least `REVIEW`. The included fixed fixture
is `REVIEW` for that reason, not `PASS`.

Missing Checkov, a scanner timeout, malformed scanner output, unparsable
Terraform, an empty or missing source directory and internal stage failures
all produce `INCOMPLETE` with exit 1. Malformed command-line usage and an
unusable output directory also exit 1.

</details>

<details>
<summary>Dependency versions and installed-wheel setup</summary>

## Setup

Requires Python 3.12 (`requires-python = ">=3.12,<3.13"`).

| File | Purpose |
|---|---|
| `pyproject.toml` | Package metadata. Runtime dependencies: `pydantic>=2.11,<3`, `PyYAML>=6.0,<7`. Optional extras: `scan` (`checkov==3.3.8`), `test` (`pytest>=8`). |
| `requirements-hackathon.txt` | Direct pins: `checkov==3.3.8`, `pydantic==2.14.0`, `PyYAML==6.0.3`, `pytest==9.1.1`. |
| `requirements-lock.txt` | Full resolved set, produced with Python 3.12.14 on macOS arm64. Versions are pinned; hashes are not. |

Checkov is needed for every real scan: without it, scans are `INCOMPLETE`.
The CLI looks for a `checkov` executable on `PATH`.

### From a source checkout

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pip check
python -m pytest tests -q -p no:cacheprovider -rs
```

The full suite also uses Node.js on `PATH` to execute the PR-comment tests.
Install `actionlint` on `PATH` to run the workflow lint check; that check is
skipped when the executable is absent. The CLI itself does not need either
tool. Run tests with AI configuration unset as shown in the demo.

Run commands from the repository root so `python -m valid` imports the
checkout.

### As an installed wheel

The same steps CI uses. The wheel build needs no package-index access once
setuptools is present:

```sh
python -m pip install -r requirements-lock.txt
python -m pip install setuptools==80.9.0
python -m pip wheel --no-deps --no-build-isolation --no-index -w dist .
python -m pip install --no-deps --no-index dist/valid-0.1.0-py3-none-any.whl
python -m pip check
```

The wheel ships the policy file (`valid/data/checkov_severity.yaml`) and the
AI transport helper, so the installed package does not depend on the source
tree. To confirm the import comes from the installed package, run from another
directory with `python -I`, which ignores `PYTHONPATH` and the working
directory:

```sh
cd /tmp
python -I -c "import valid, valid.cli; print(valid.__file__, valid.cli.POLICY_FILE)"
```

</details>

<details>
<summary>Artifact schemas and repeatability</summary>

## Artifacts

| File | Contents |
|---|---|
| `raw_checkov.json` | Minimal retained Checkov record: rule IDs, resources, paths, lines, coverage. Source excerpts and evaluated values are dropped; retained text is sanitized. |
| `raw_custom.json` | Built-in rule findings and literal-parse coverage. |
| `findings.json` | Normalized findings with stable finding IDs (`f_` plus 16 hex digits), evidence IDs (`e_` plus 16 hex digits), fingerprints, location, resource, priority, policy and evidence strength. |
| `summary.json` | Status, score, severity and category counts, top priority, merged coverage and ordered reasons (`schema_version` `1.0.0`). |
| `comment.md` | Markdown report. First line is `<!-- valid-report -->`, second is `## V.A.L.I.D. Review - <STATUS>`. |
| `ai.json` | On a completed scan, one explanation per finding in `findings.json` order: `finding_id`, `evidence_ids`, `title`, `why_it_matters`, `recommended_action`, `evidence_strength`. Template failure during `INCOMPLETE` recovery can leave this list empty. |

Repeat tests compare all six artifacts byte for byte for the pinned scanner
and unchanged fixtures in template-only mode. The adapter sorts sanitized
failed-check records by canonical content, so changing Checkov's emission
order does not change `raw_checkov.json`. The verdict and finding identities
do not depend on record order or run time.

When explanation and report generation succeed, `comment.md` and `ai.json`
use the same explanation list. An `INCOMPLETE` fallback report can omit the
detailed explanation table.

</details>

<details>
<summary>Optional AI provider configuration and validation</summary>

## Explanations and optional AI

### Default: template-only, no network

With no AI configuration (the normal case), explanations come from fixed
deterministic templates. No provider is contacted and no network connection
is opened for explanations.

### Constrained AI mode

When an operator configures a provider, V.A.L.I.D. sends a bounded, redacted
request for at most ten findings and accepts the response only if every
explanation:

- covers exactly the requested findings, once each;
- cites exactly that finding's evidence IDs and keeps its evidence strength;
- copies the title, why-it-matters and recommended-action text exactly from
  the approved options for that finding.

The approved options are currently the same single deterministic template
strings, so a valid AI response reproduces the template wording. AI mode does
not generate new prose or improve wording, and schema or ID checks are not
presented as proof that arbitrary free-form text is grounded. Any failure
(network, timeout, status, size, parse or validation) silently selects the
templates. Findings, summary, verdict and exit code are identical with no
key, a valid AI response, or a failing provider.

### Configuration

Configuration comes only from environment variables set by the operator:

| Variable | Meaning |
|---|---|
| `VALID_AI_PROVIDER` | `nebius` or `openai_compatible`. Unset, empty, `disabled`, `none`, `off`, `template` or any unknown value means template-only. |
| `VALID_AI_BASE_URL` | Explicit HTTPS base URL. `/chat/completions` is appended. |
| `VALID_AI_MODEL` | Explicit model identifier. There is no default. |
| `VALID_AI_API_KEY` | Provider key. If unset, `NEBIUS_API_KEY` (for `nebius`) or `OPENAI_API_KEY` (for `openai_compatible`) is used. |

Any missing or invalid value means template-only, with no network call.

**`nebius`** accepts exactly one base URL,
`https://api.tokenfactory.us-central1.nebius.com/v1` (a single trailing slash
is allowed), and a model identifier starting with `nvidia/`. Other hosts,
paths, ports and model names are rejected. Whether a particular model is
served for your account is not checked: there is no catalog lookup, default
or substitution. `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` was verified in a
live synthetic smoke test. Model identifiers are case-sensitive: use the exact
ID returned by your account's catalog, without lowercasing it.

**`openai_compatible`** accepts any explicit HTTPS base URL without embedded
credentials, query string, fragment, whitespace, or `.`, `..` or empty path
segments, and any model identifier (up to 128 characters) made of letters,
digits and `._:/@+-`.

Example using the verified model ID (keep real keys in a secret manager or
your shell's secure storage, never in files committed to a repository):

```sh
export VALID_AI_PROVIDER=nebius
export VALID_AI_BASE_URL=https://api.tokenfactory.us-central1.nebius.com/v1
export VALID_AI_MODEL='nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B'
read -rs NEBIUS_API_KEY && export NEBIUS_API_KEY   # type the key; it is not echoed
python -m valid scan --path fixtures/risky --output out/risky-ai
```

Request and response limits, the process-isolated transport and its
cancellation behavior are described in [docs/security.md](docs/security.md).

</details>

<details>
<summary>GitHub workflow permissions, recovery and trust boundaries</summary>

## GitHub pull-request workflow

`.github/workflows/valid.yml` runs on `pull_request` (opened, synchronize,
reopened):

1. **Scan job** (`contents: read` only). It checks out the base commit as
   trusted reviewer code and the PR head commit as data only, both without
   persisted credentials. It installs the reviewer from the base commit's
   lock file and wheel, then runs `scripts/ci_scan.py` on `pr-head/infra`.
   The wrapper launches the analyzer in its own process group, with
   credential-like variables removed from its environment (names matching
   `TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, `PRIVATE`, `CREDENTIAL`), so PR
   scans run template-only. It enforces a 600-second analyzer budget, then
   validates all six artifacts and records `scan_meta.json`. If any earlier
   step failed, a recovery step records a conservative `INCOMPLETE` result.
2. **Report job** (`contents: read`, `pull-requests: write`). It downloads the
   record, writes `comment.md` to the job summary and updates one sticky PR
   comment identified by the `<!-- valid-report -->` marker. Comment updates
   are nonfatal, so a comment failure never changes the gate.
3. **Final gate.** It passes only when the scan record matches the PR head
   commit, the wrapper and analyzer completed with exit 0, all six artifacts
   are present and consistent, and the verdict is `PASS` or `REVIEW`.

Notes:

- **Scanned path.** Only `infra/` in the PR head is scanned. To scan another
  directory, change `--scan-path pr-head/infra` in `valid.yml`.
- **Trust boundary.** Reviewer code, its dependencies and the wrapper come
  from the base commit, but GitHub takes the workflow file itself from the
  pull request. Changes to `.github/workflows/` therefore need human review,
  for example through code-owner rules.
- **Forks.** For pull requests from forks, GitHub normally grants a read-only
  token, so the sticky comment may not be posted. The job summary, artifacts
  and final gate still run.
- **Cancellation.** Runs for the same PR share a concurrency group with
  `cancel-in-progress: true`. A newer push cancels the older run, which then
  produces no passing gate; the newer run's gate is the one that counts.
- **Merge blocking.** The workflow reports a pass/fail check. Blocking merges
  on it requires a branch-protection rule configured by the repository owner.

`.github/workflows/ci.yml` runs the test suite on Linux, builds and installs
the wheel, and checks the installed CLI against both fixtures and for
byte-identical repeat scans.

</details>

## Known limitations

- **Not covered:** IPv6 exposure (for example `::/0`) by the built-in SSH
  rule, which only flags `0.0.0.0/0`, and values that need variable, module
  or expression resolution, which become coverage gaps.
- **Not performed:** plan or apply, state, drift or deployment validation,
  and merge actions.
- **Unmapped Checkov checks** have unknown severity and produce `REVIEW`.
- **Redaction** in AI requests and outputs covers documented patterns only
  (see [docs/security.md](docs/security.md)); it cannot recognize every secret.
- **What has been verified:** 625 tests pass locally on macOS with Python 3.12.
  [Linux CI](https://github.com/Mukeshkr-19/V.A.L.I.D/actions/runs/38176382089)
  passed 624 tests (the optional actionlint test was skipped), installed-wheel
  fixture checks and exact repeats of all six artifacts. Both workflows passed
  actionlint locally.
  - The [demo PR](https://github.com/Mukeshkr-19/V.A.L.I.D/pull/1)
    demonstrated [HIGH RISK / exit 1](https://github.com/Mukeshkr-19/V.A.L.I.D/actions/runs/38176517083),
    [missing-input INCOMPLETE / exit 1](https://github.com/Mukeshkr-19/V.A.L.I.D/actions/runs/38176751486),
    and [fixed REVIEW / exit 0](https://github.com/Mukeshkr-19/V.A.L.I.D/actions/runs/38176876800).
    Each run uploaded valid artifacts, completed the job-summary step and updated
    the same sticky bot comment.
  - Not yet demonstrated: a live Nebius request, account availability of any
    specific model, or Windows behavior.
- **No guarantees** of production readiness, uptime, cost savings or
  compliance.

## License

MIT. See [LICENSE](LICENSE).
