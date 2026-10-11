# V.A.L.I.D.

Deterministic Terraform pull-request risk review.

V.A.L.I.D. scans a Terraform source directory, combines Checkov 3.3.8 results
with three built-in literal checks, and publishes a reproducible verdict plus
evidence-linked report artifacts. The verdict, score and exit code come only
from deterministic policy. Optional AI explanations are advisory: they never
add, remove or change findings, coverage, the verdict or the exit code.

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

## Usage

```text
python -m valid scan --path <terraform-dir> --output <new-or-empty-dir>
```

- `--output` must be a new or empty directory. Existing files are never
  overwritten, symbolic links are refused, and the output may not be inside
  the scanned input.
- Every successful run publishes all six artifacts as one set, or none: if
  writing fails, files created by the run are rolled back and the command
  exits 1.

Example with the included fixtures:

```sh
python -m valid scan --path fixtures/risky --output out/risky   # HIGH RISK, exit 1
python -m valid scan --path fixtures/fixed --output out/fixed   # REVIEW, exit 0
```

See [docs/demo.md](docs/demo.md) for a step-by-step walkthrough.

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
or substitution. The planned `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`
identifier has not been verified as available; confirm it with your provider
account before relying on it.

**`openai_compatible`** accepts any explicit HTTPS base URL without embedded
credentials, query string, fragment, whitespace, or `.`, `..` or empty path
segments, and any model identifier (up to 128 characters) made of letters,
digits and `._:/@+-`.

Example (placeholder values only; keep real keys in a secret manager or
your shell's secure storage, never in files committed to a repository):

```sh
export VALID_AI_PROVIDER=nebius
export VALID_AI_BASE_URL=https://api.tokenfactory.us-central1.nebius.com/v1
export VALID_AI_MODEL='nvidia/<verified-model-id>'  # replace the placeholder
read -rs NEBIUS_API_KEY && export NEBIUS_API_KEY   # type the key; it is not echoed
python -m valid scan --path fixtures/risky --output out/risky-ai
```

Request and response limits, the process-isolated transport and its
cancellation behavior are described in [docs/security.md](docs/security.md).

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
  - The open [demo PR](https://github.com/Mukeshkr-19/V.A.L.I.D/pull/1)
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
