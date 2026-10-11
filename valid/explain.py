"""Bounded evidence-only AI explanations with deterministic template fallback.

``explain(findings)`` always returns exactly one Explanation per supplied
finding, in input order. It asks an operator-configured model to select from
pre-approved template wording for at most the first ten findings, then
strictly validates the response; every other finding, and every provider
failure, uses the deterministic templates directly. AI output never changes
findings, scores, verdicts, or exit codes — the caller publishes it as
advisory text only.

Safety bounds (hardcoded, not repository-configurable):
- input is only redacted normalized evidence summaries, evidence IDs, and the
  permitted template options — never raw Terraform, plans, state, full repo
  files, repository-derived prompts, tools, or deployment/merge capability;
- hard input bounds are checked before any request is built: a finding with
  too many evidence items, an over-long ID, an over-long evidence summary, or
  over-long template text is not sent (it keeps its deterministic template),
  and the serialized request never exceeds MAX_REQUEST_BYTES — findings that
  would exceed it are dropped from the request, never truncated;
- at most ten findings per request, one bounded structured request, at most
  one transient retry, finite token and response-byte limits; no autonomous
  loops;
- one shared wall-clock deadline (SHARED_BUDGET_SECONDS) covers every attempt
  including name resolution, connect, send, and response reads. Each attempt
  runs in a supervised child process (valid._ai_transport); when the deadline
  expires that child is killed and reaped before fallback, and no further
  attempt starts. A response that completes after the deadline is never
  accepted;
- HTTPS-only explicit endpoints; redirects are never followed (any 3xx is a
  failure after exactly one request), and environment proxies are not used.
  Provider keys travel only in the Authorization header and never enter the
  payload, logs, or artifacts.

Provider configuration comes only from explicit operator environment
variables: VALID_AI_PROVIDER (``nebius`` or ``openai_compatible``),
VALID_AI_BASE_URL, VALID_AI_MODEL, and a key from VALID_AI_API_KEY (or the
provider-specific NEBIUS_API_KEY / OPENAI_API_KEY). Absent, disabled, or
invalid configuration means template-only operation — the normal no-key
path, never INCOMPLETE, and it makes no network call.

Nebius mode accepts only the documented Token Factory base URL in
NEBIUS_BASE_URLS and an explicitly configured ``nvidia/`` model identifier.
Whether a given model identifier is served for a particular account is not
checked here: there is no default endpoint, no default model, no catalog
lookup, and no substitution. ``openai_compatible`` accepts any explicit
HTTPS base URL without credentials, query, or fragment.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any

from valid import _ai_transport, redact, templates, validate_ai
from valid.models import Explanation, Finding

MAX_SELECTED_FINDINGS = 10
SHARED_BUDGET_SECONDS = 20.0
PER_ATTEMPT_TIMEOUT_SECONDS = 10.0
MAX_ATTEMPTS = 2
CANCEL_JOIN_SECONDS = 2.0
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKENS = 800
MAX_SUMMARY_CHARS = 500
MAX_SUMMARY_INPUT_CHARS = 4000
MAX_EVIDENCE_PER_FINDING = 16
MAX_ID_CHARS = 128
MAX_OPTION_CHARS = 1000
MAX_MODEL_CHARS = 128
MAX_REQUEST_BYTES = 64 * 1024

PROVIDER_ENV = "VALID_AI_PROVIDER"
BASE_URL_ENV = "VALID_AI_BASE_URL"
MODEL_ENV = "VALID_AI_MODEL"
KEY_ENVS = ("VALID_AI_API_KEY", "NEBIUS_API_KEY", "OPENAI_API_KEY")

NEBIUS_BASE_URLS = frozenset({"https://api.tokenfactory.us-central1.nebius.com/v1"})
_NVIDIA_MODEL = re.compile(r"nvidia/[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
_GENERIC_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}")
_TOKEN_CHARS = re.compile(r"[\x21-\x7e]+")

_TEMPLATE_ONLY = frozenset({"", "disabled", "none", "off", "template"})
_KNOWN_PROVIDERS = frozenset({"nebius", "openai_compatible"})

SYSTEM_POLICY = (
    "You are a strict evidence-bound explainer for infrastructure risk findings. "
    "For each supplied finding, copy exactly the permitted title, why_it_matters, "
    "and recommended_action options given for that finding_id. "
    "Set evidence_ids to the finding's evidence IDs and evidence_strength to the "
    "finding's evidence strength. Never invent findings, evidence IDs, resources, "
    "ports, addresses, costs, policies, or assurances. "
    "Return a single JSON array with one object per finding using exactly the keys "
    "finding_id, evidence_ids, title, why_it_matters, recommended_action, "
    "evidence_strength."
)

Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class TransportError(Exception):
    """A bounded transport failure: timeout, connection loss, or cancellation."""


class AIRequestError(Exception):
    """The provider request could not be completed within budget."""


class AIResponseError(Exception):
    """The provider response was missing, oversized, or unparsable."""


class BudgetExhausted(AIRequestError):
    """The shared wall-clock deadline expired; no further attempt is made."""


# --------------------------------------------------------------------------- configuration


def _provider_name(raw: str) -> str:
    return raw.strip().lower().replace("-", "_")


def _provider_key(provider: str, env: Mapping[str, str]) -> str:
    specific = "NEBIUS_API_KEY" if provider == "nebius" else "OPENAI_API_KEY"
    for name in ("VALID_AI_API_KEY", specific):
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def _endpoint(provider: str, base: str) -> str | None:
    """Return the chat-completions URL for an acceptable base URL, else None."""
    if not _TOKEN_CHARS.fullmatch(base):
        return None
    if provider == "nebius" and base.rstrip("/") not in NEBIUS_BASE_URLS:
        return None
    if base.endswith("//"):
        return None
    try:
        parsed = urllib.parse.urlsplit(base)
        parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
        or "?" in base
        or "#" in base
    ):
        return None
    path = parsed.path.rstrip("/")
    if any(segment in (".", "..") for segment in path.split("/")) or "//" in path:
        return None
    return urllib.parse.urlunsplit(("https", parsed.netloc, path + "/chat/completions", "", ""))


def _configure(env: Mapping[str, str]) -> dict[str, str] | None:
    """Resolve an explicit provider configuration, or None for template-only.

    Unknown providers and any absent, malformed, or disallowed endpoint, model,
    or key select template-only operation without making a network call.
    """
    provider = _provider_name(env.get(PROVIDER_ENV) or "")
    if provider in _TEMPLATE_ONLY or provider not in _KNOWN_PROVIDERS:
        return None
    base = (env.get(BASE_URL_ENV) or "").strip()
    model = (env.get(MODEL_ENV) or "").strip()
    key = _provider_key(provider, env)
    if not base or not model or not key:
        return None
    if not _TOKEN_CHARS.fullmatch(key):
        return None
    pattern = _NVIDIA_MODEL if provider == "nebius" else _GENERIC_MODEL
    if len(model) > MAX_MODEL_CHARS or not pattern.fullmatch(model):
        return None
    endpoint = _endpoint(provider, base)
    if endpoint is None:
        return None
    return {"provider": provider, "endpoint": endpoint, "model": model, "key": key}


# --------------------------------------------------------------------------- request bounds


def _payload_entry(finding: Finding) -> dict[str, Any] | None:
    """The bounded request entry for one finding, or None if it exceeds a bound."""
    if len(finding.finding_id) > MAX_ID_CHARS:
        return None
    if not finding.evidence or len(finding.evidence) > MAX_EVIDENCE_PER_FINDING:
        return None
    for item in finding.evidence:
        if len(item.evidence_id) > MAX_ID_CHARS or len(item.summary) > MAX_SUMMARY_INPUT_CHARS:
            return None
    template = templates.explain([finding])[0]
    options = {
        "title": template.title,
        "why_it_matters": template.why_it_matters,
        "recommended_action": template.recommended_action,
    }
    if any(len(value) > MAX_OPTION_CHARS for value in options.values()):
        return None
    return {
        "finding_id": finding.finding_id,
        "evidence_ids": sorted(item.evidence_id for item in finding.evidence),
        "evidence_strength": finding.evidence_strength,
        "evidence": [
            {
                "evidence_id": item.evidence_id,
                "summary": redact.redact_text(item.summary, max_chars=MAX_SUMMARY_CHARS),
            }
            for item in finding.evidence
        ],
        "options": options,
    }


def _body(model: str, entries: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {
            "model": model,
            "max_tokens": MAX_TOKENS,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_POLICY},
                {
                    "role": "user",
                    "content": json.dumps(
                        {"findings": entries}, ensure_ascii=False, separators=(",", ":")
                    ),
                },
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _bounded_request(model: str, candidates: list[Finding]) -> tuple[list[Finding], bytes | None]:
    """Select in-bound findings and build a request no larger than MAX_REQUEST_BYTES.

    Returns the findings actually sent (input order) and the request body, or
    an empty selection and None when nothing fits.
    """
    selected: list[Finding] = []
    entries: list[dict[str, Any]] = []
    for finding in candidates[:MAX_SELECTED_FINDINGS]:
        entry = _payload_entry(finding)
        if entry is not None:
            selected.append(finding)
            entries.append(entry)
    while entries:
        body = _body(model, entries)
        if len(body) <= MAX_REQUEST_BYTES:
            return selected, body
        selected.pop()
        entries.pop()
    return [], None


# --------------------------------------------------------------------------- transport


def _default_transport(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
    *,
    deadline: float | None = None,
) -> tuple[int, bytes]:
    """POST once over HTTPS in a supervised child process; never redirects.

    The child is killed and reaped if ``deadline`` passes, so no resolution,
    connection, or send continues after this returns.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise TransportError("provider endpoint is not HTTPS")
    if deadline is None:
        deadline = time.monotonic() + timeout
    try:
        return _ai_transport.supervised_post(
            url, headers, body, timeout, deadline, MAX_RESPONSE_BYTES, CANCEL_JOIN_SECONDS
        )
    except _ai_transport.DeadlineExpired as error:
        raise BudgetExhausted("provider attempt exceeded the shared deadline") from error
    except _ai_transport.ResponseTooLarge as error:
        raise AIResponseError("provider response exceeds the byte limit") from error
    except (_ai_transport.TransportFailure, OSError, ValueError) as error:
        raise TransportError("provider transport failed (%s)" % type(error).__name__) from error


_default_transport.supervised = True  # type: ignore[attr-defined]


def _attempt(
    transport: Transport,
    url: str,
    headers: dict[str, str],
    body: bytes,
    deadline: float,
) -> tuple[int, bytes]:
    """Run one transport call under the shared wall-clock deadline.

    The default transport supervises and reaps its own child process. Other
    (injected) transports run in a worker whose late result is discarded.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BudgetExhausted("provider budget exhausted")
    timeout = min(PER_ATTEMPT_TIMEOUT_SECONDS, remaining)
    if getattr(transport, "supervised", False):
        result = transport(url, headers, body, timeout, deadline=deadline)
        if time.monotonic() > deadline:
            raise BudgetExhausted("provider result arrived after the deadline")
        return result
    outcome: dict[str, Any] = {}
    done = threading.Event()

    def run() -> None:
        try:
            outcome["value"] = transport(url, headers, body, timeout)
        except BaseException as error:
            outcome["error"] = error
        finally:
            done.set()

    worker = threading.Thread(target=run, name="valid-ai-attempt", daemon=True)
    worker.start()
    finished = done.wait(remaining)
    if not finished or time.monotonic() > deadline:
        worker.join(CANCEL_JOIN_SECONDS)
        raise BudgetExhausted("provider attempt exceeded the shared deadline")
    worker.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _parse_response(raw: bytes) -> Any:
    try:
        envelope = json.loads(raw.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("empty model content")
        return json.loads(content)
    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError) as error:
        raise AIResponseError(
            "provider response is not usable (%s)" % type(error).__name__
        ) from error


def _request(
    config: dict[str, str],
    body: bytes,
    transport: Transport,
    deadline: float,
) -> Any:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + config["key"],
    }
    for _ in range(MAX_ATTEMPTS):
        try:
            status, raw = _attempt(transport, config["endpoint"], headers, body, deadline)
        except BudgetExhausted:
            raise
        except (TransportError, TimeoutError, ConnectionError, OSError):
            continue
        if status == 429 or 500 <= status <= 599:
            continue
        if status != 200:
            raise AIRequestError("provider returned status %d" % status)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AIResponseError("provider response exceeds the byte limit")
        return _parse_response(raw)
    raise AIRequestError("provider request did not complete within budget")


# --------------------------------------------------------------------------- service


def _redacted_items(candidate: Any) -> Any:
    redacted = []
    for item in candidate:
        entry = dict(item)
        for field in ("title", "why_it_matters", "recommended_action"):
            entry[field] = redact.redact_text(item[field])
        redacted.append(entry)
    return redacted


def explain(
    findings: list[Finding],
    *,
    env: Mapping[str, str] | None = None,
    transport: Transport | None = None,
) -> list[Explanation]:
    """Explain every supplied finding, falling back to templates on any failure.

    ``env`` overrides the process environment (tests); ``transport`` overrides
    the HTTPS transport (bounded doubles). Neither is used on the template-only
    path, which makes no network call.
    """
    items = list(findings)
    for finding in items:
        if not isinstance(finding, Finding):
            raise ValueError("explain requires Finding objects")
    config = _configure(dict(env) if env is not None else os.environ)
    if config is None or not items:
        return templates.explain(items)
    deadline = time.monotonic() + SHARED_BUDGET_SECONDS
    try:
        selected, body = _bounded_request(config["model"], items)
        if body is None:
            return templates.explain(items)
        candidate = _request(config, body, transport or _default_transport, deadline)
        validate_ai.validate(candidate, selected)
        checked = validate_ai.validate(_redacted_items(candidate), selected)
        if time.monotonic() > deadline:
            raise BudgetExhausted("provider result was ready only after the deadline")
        merged = {explanation.finding_id: explanation for explanation in checked}
        rest = templates.explain(
            [finding for finding in items if finding.finding_id not in merged]
        )
        tail = {explanation.finding_id: explanation for explanation in rest}
        return [
            merged[finding.finding_id] if finding.finding_id in merged else tail[finding.finding_id]
            for finding in items
        ]
    except Exception:
        return templates.explain(items)
