# Demo

This walkthrough uses the two included Terraform fixtures. No AI key, cloud
account or Terraform installation is needed. Set up the environment first as
described in the [README](../README.md#quickstart), then run everything from the
repository root.

## 1. Local scan without AI configuration

Make sure no AI provider is configured, so explanations are template-only and
no provider is contacted:

```sh
unset VALID_AI_PROVIDER VALID_AI_BASE_URL VALID_AI_MODEL VALID_AI_API_KEY NEBIUS_API_KEY OPENAI_API_KEY
```

Each scan needs a new or empty output directory:

```sh
DEMO=$(mktemp -d)
python -m valid scan --path fixtures/risky --output "$DEMO/risky"; echo "exit=$?"
python -m valid scan --path fixtures/fixed --output "$DEMO/fixed"; echo "exit=$?"
```

Expected results:

| Fixture | Status | Exit | Why |
|---|---|---|---|
| `fixtures/risky` | `HIGH RISK` | 1 | Public SSH ingress (`CKV_AWS_24`, `DG-AWS-NET-001`) and disabled RDS deletion protection (`CKV_AWS_293`, `DG-AWS-RDS-001`) are blocking high findings; `DG-AWS-TAG-001` adds medium tag findings |
| `fixtures/fixed` | `REVIEW` | 0 | No blocking or custom findings remain; the remaining unmapped Checkov checks have unknown severity, which requires review |

With Checkov 3.3.8, a local run produced 21 findings (score 37) for the risky
fixture and 14 findings (score 0) for the fixed one.

Running these fixture scans again into fresh directories reproduces the same
verdict and byte-identical outputs across all six artifacts. The adapter
canonically orders retained Checkov records before publication.

## 2. Inspect the artifacts

```sh
ls "$DEMO/risky"
# ai.json  comment.md  findings.json  raw_checkov.json  raw_custom.json  summary.json

head -n 2 "$DEMO/risky/comment.md"
# <!-- valid-report -->
# ## V.A.L.I.D. Review - HIGH RISK
```

Status, score and the first reasons:

```sh
python -c 'import json, sys; s = json.load(open(sys.argv[1])); print(s["status"], s["score"]); print("\n".join(s["reasons"][:4]))' "$DEMO/risky/summary.json"
```

Finding and evidence IDs, and the matching explanation for each finding:

```sh
python - "$DEMO/risky" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
findings = json.loads((out / "findings.json").read_text())
explanations = json.loads((out / "ai.json").read_text())
for finding, explanation in zip(findings, explanations):
    evidence = [item["evidence_id"] for item in finding["evidence"]]
    assert explanation["finding_id"] == finding["finding_id"]
    assert sorted(explanation["evidence_ids"]) == sorted(evidence)
    print(finding["finding_id"], finding["source"]["rule_id"], finding["priority"], evidence, "-", explanation["title"])
PY
```

The IDs are derived from the finding content, not from run time or hash
seeds, so they are identical on every run.

## 3. Draft pull-request demo

The following steps show the workflow on a repository that contains
`.github/workflows/valid.yml`. They are instructions, not a record of an
existing pull request. Use a test repository you control, and do not merge
the demo branch or deploy anything.

1. On a new branch, add the risky fixture as the scanned path. The workflow
   scans only `infra/`:

   ```sh
   git switch -c valid-demo
   mkdir -p infra
   cp fixtures/risky/main.tf infra/main.tf
   git add infra/main.tf
   git commit -m "Demo: risky Terraform"
   git push -u origin valid-demo
   ```

2. Open a **draft** pull request from `valid-demo`. Then check:
   - the "Report and gate" job's summary shows `## V.A.L.I.D. Review - HIGH RISK`;
   - the final gate step fails with `verdict is HIGH RISK`;
   - a single comment starting with `<!-- valid-report -->` appears, if the
     token is allowed to comment (see the README notes on forks);
   - the `valid-scan` workflow artifact contains `scan_meta.json` and the six
     artifacts.

3. Replace the file with the fixed fixture and push again:

   ```sh
   cp fixtures/fixed/main.tf infra/main.tf
   git commit -am "Demo: fixed Terraform"
   git push
   ```

   If the previous run is still in progress it is cancelled. The new run
   updates the same sticky comment, and its gate passes with verdict `REVIEW`.

4. Close the draft pull request and delete the branch when finished.

## 4. Generated AI review (operator only)

Only do this after you have:

- an account with your provider;
- a key stored outside the repository;
- confirmation from the provider that the model identifier you plan to use
  is available to your account.

V.A.L.I.D. does not check model availability during a scan. A separate
bounded synthetic smoke verified the model below; its receipt is recorded
at the end of this section. Confirm its exact ID in your own account's catalog.

```sh
export VALID_AI_PROVIDER=nebius
export VALID_AI_BASE_URL=https://api.tokenfactory.us-central1.nebius.com/v1
export VALID_AI_MODEL='nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B'
read -rs NEBIUS_API_KEY && export NEBIUS_API_KEY   # type the key; it is not echoed
python -m valid scan --path fixtures/risky --output "$DEMO/risky-ai"; echo "exit=$?"
unset NEBIUS_API_KEY
```

Expected results:

- The status and exit code are the same as the no-key run (`HIGH RISK`, exit 1).
- `findings.json` and `summary.json` are byte-identical to the no-key run.
- Accepted generated explanations show `origin: "ai"` in `ai.json` and
  AI-assisted review in `comment.md`. Read the proposed actions and verification
  questions; the fix plan includes reviewed attribute examples for supported rules.
- Up to ten distinct issues receive AI review. Unreviewed issues, identical
  template copies and provider failures show `origin: "template"` and basic guidance.
- Advice can differ across live calls. Exact finding/evidence references and
  the deterministic summary must remain unchanged. HTTP success alone does
  not demonstrate acceptance of generated advice.
- If the provider is unreachable, slow or returns invalid output, the report
  explicitly shows basic guidance. Provider failure never changes the verdict.

Safety rules for this step:

- Never paste keys into commands that are saved to shell history, issues,
  pull requests or chat.
- Never commit `.env` files. The repository's `.gitignore` excludes common
  secret and Terraform state files, but review what you stage.
- Share only the published artifacts. Do not share raw private Terraform, plan
  or state files, or terminal logs that might contain credentials.

### Live verification receipt

A separate operator-run smoke used the production explanation service and
HTTPS transport from commit
[`e8abf98`](https://github.com/Mukeshkr-19/V.A.L.I.D/commit/e8abf98b9f0e80c1e6cd1da87f880b1722c4bf00).
It sent synthetic finding evidence only, made one inference attempt, and saved
a redacted receipt. No raw response, API key or Authorization header was retained.

| Check | Observed result |
|---|---|
| Timestamp | 2026-10-12 02:29:29 UTC |
| Provider | Nebius Token Factory |
| HTTPS base URL | `https://api.tokenfactory.us-central1.nebius.com/v1` |
| Requested and returned model | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` |
| HTTP status | 200; chat completion received |
| Product validation | Explanation accepted; approved template wording preserved |
| Deterministic result | Findings and summary unchanged; HIGH RISK, exit 1 |
| Attempts / elapsed time | 1 / 3.763 seconds |
| Token usage | 292 prompt + 467 completion = 759 total |
| Source integrity | Verified before and after the check |

This establishes live Nebius serving and product response acceptance for one
account and one synthetic finding. It does not prove that every future request
will succeed, that other accounts have access, or that GitHub PR jobs call a
model. This historical request used the earlier template-copy contract; it
does not validate the new generated-advice behavior. The PR scanning workflow
intentionally runs without provider credentials. The separate enrichment helpers
are not yet installed as a privileged GitHub workflow.
