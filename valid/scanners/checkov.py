"""Real Checkov subprocess adapter.

``run(path, config)`` executes the pinned Checkov release against a Terraform
path and returns a :class:`valid.models.RawScanResult`. The adapter:

* passes an argument array to :func:`subprocess.run` (never a shell string),
* applies a finite timeout from ``config.scanner_timeout_seconds``,
* scopes the scan to the Terraform framework only,
* disables external Terraform module downloads, Prisma Cloud data downloads and
  user supplied check directories/git repositories, config files or enforcement
  rules,
* distinguishes a *completed* scan that reported violations (valid JSON, often a
  nonzero return code) from an *execution failure* (missing executable, timeout,
  malformed/empty/unrecognised output, unreadable path, unexpected exit status),
* refuses to execute a scan whose root carries an untrusted Checkov config file,
  because such a file can suppress required checks,
* treats an exit status outside ``{0, 1}`` as an execution failure even when the
  stdout happens to be recognised JSON, and
* rejects malformed required result structures (a check bucket that is present
  but not a list, or a bucket entry that is not an object) as a required
  coverage gap instead of silently dropping the records,
* retains, for every failed check, only an explicit minimal record (rule
  id/name, scanner severity, source-relative location and line range, and
  resource identity), so the raw artifact never carries Terraform source
  excerpts, definitions/context, evaluated configuration (including the
  unordered ``check_result.evaluated_keys`` list) or unknown scanner fields at
  any nesting depth, and
* reports Checkov's skipped/suppressed checks as a required coverage gap, so a
  suppressed check is never read as evaluated evidence.

The module only returns values. It never writes artifacts (the CLI owns
``raw_checkov.json``), never raises for scan-level problems, and never falls back
to a canned/demo payload.

Behaviour verified against the real release (Checkov 3.3.8, Python 3.12) is
recorded in ``tests/test_checkov_adapter.py``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

from valid.models import Coverage, RawScanResult, ValidConfig

CHECKOV_VERSION = "3.3.8"
DEFAULT_COMMAND: tuple[str, ...] = ("checkov",)

# Coverage stage/gap identifiers owned by this adapter. Every one of them is
# *required*: the deterministic risk policy turns a required stage failure or a
# required gap into INCOMPLETE, so none of them can be skipped silently.
#   ``checkov_execution``          the scanner did not complete: refused, not
#                                  found, timed out, unexpected exit status, or
#                                  output that could not be recognised.
#   ``checkov_file_parsing``       Checkov reported Terraform parse errors.
#   ``checkov_local_config``       an untrusted config file was found at the
#                                  scan root, so the scan was refused before
#                                  the subprocess was started.
#   ``checkov_unusable_location``  failed checks were dropped because their path
#                                  was outside the scan root or unusable.
#   ``checkov_malformed_results``  a required result structure was malformed,
#                                  including a report list carrying a member
#                                  that is not a report envelope.
#   ``checkov_missing_records``    the report's own counters declared more
#                                  records than the payload actually carried.
#   ``checkov_skipped_checks``     Checkov skipped/suppressed checks, so their
#                                  evidence was never evaluated.
#   ``checkov_no_evaluated_files`` no Terraform resource was evaluated.
EXECUTION_STAGE = "checkov_execution"
PARSING_STAGE = "checkov_file_parsing"
UNUSABLE_LOCATION_GAP = "checkov_unusable_location"
NO_EVALUATED_FILES_GAP = "checkov_no_evaluated_files"
LOCAL_CONFIG_GAP = "checkov_local_config"
MALFORMED_RESULTS_GAP = "checkov_malformed_results"
MISSING_RECORDS_GAP = "checkov_missing_records"
SKIPPED_CHECKS_GAP = "checkov_skipped_checks"

# Checkov summary counters, paired with the result bucket that carries their
# evidence. Only these three are cross-checked: a positive ``passed`` count is
# not required to be listed record-by-record.
_COUNTER_FIELDS: tuple[tuple[str, str], ...] = (
    ("failed", "failed_checks"),
    ("skipped", "skipped_checks"),
    ("parsing_errors", "parsing_errors"),
)

# At most this many missing-record diagnostics are kept, so a hostile payload
# with many reports cannot produce an unbounded diagnostic list.
COUNTER_NOTE_LIMIT = 12

REQUIRED_STAGES: tuple[str, ...] = (EXECUTION_STAGE, PARSING_STAGE)

# Checkov exits 0 when nothing failed and 1 when failed checks were reported.
# ``--soft-fail`` is never passed, so the real return code stays observable.
COMPLETED_RETURN_CODES: frozenset[int] = frozenset({0, 1})

# Terraform-only scope plus hermeticity flags. Spellings verified against the
# pinned release's ``--help`` output:
#   --framework FRAMEWORK [FRAMEWORK ...]
#   --download-external-modules DOWNLOAD_EXTERNAL_MODULES
#   --skip-download   (no Prisma Cloud data downloads; observed to halve runtime
#                     and to null out ``bc_check_id`` while leaving failed check
#                     ids/counts unchanged)
SCOPE_FLAGS: tuple[str, ...] = (
    "--framework",
    "terraform",
    "--download-external-modules",
    "False",
    "--skip-download",
)

# Flags that would widen or weaken the frozen scan contract. Asserted absent.
FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    {
        "--add-check",
        "--baseline",
        "--bc-api-key",
        "--check",
        "--config-file",
        "--create-baseline",
        "--create-config",
        "--download-external-modules-dir",
        "--external-checks-dir",
        "--external-checks-git",
        "--hard-fail-on",
        "--no-cert-verify",
        "--policy-metadata-filter",
        "--policy-metadata-filter-exception",
        "--run-all-external-checks",
        "--skip-check",
        "--soft-fail",
        "--soft-fail-on",
        "--use-enforcement-rules",
        "--var-file",
    }
)

# Explicit minimal retained-record contract for failed checks.
#
# A raw artifact must not become a copy of the scanned Terraform.  For every
# failed check the adapter builds a *new* record from an allowlist: the
# detector's identity and rule name, its scanner severity token, the
# source-relative location and line range, and the resource identity.  Every
# other key Checkov supplies -- source excerpts (``code_block``), definitions
# and context, parsed or evaluated configuration (``check_result``, including
# its unordered ``evaluated_keys`` list), raw values, credentials, and unknown
# fields at any nesting depth -- is dropped rather than forwarded.
# ``RETAINED_FAILED_CHECK_KEYS`` is asserted in the tests, so widening the
# artifact requires an explicit edit here.
#
# Limits: this removes the fields the adapter does not retain; it is not a
# general secret detector.  The free-text fields that are retained (rule name,
# severity token, resource identity) still pass through :func:`sanitize`, which
# strips private path prefixes and recognisable credential patterns only, so a
# secret written directly into a retained free-text field is not guaranteed to
# be redacted.
RULE_ID_KEYS: tuple[str, ...] = ("check_id", "bc_check_id")
SEVERITY_KEYS: tuple[str, ...] = ("severity", "bc_severity")
RETAINED_FAILED_CHECK_KEYS: frozenset[str] = frozenset(
    {"check_id", "check_name", "severity", "file_path", "file_line_range", "resource"}
)

# Checkov auto-discovers these files from the working directory and from the
# scanned root, even when an explicit ``--config-file`` is supplied. The adapter
# isolates the working directory, but a config file discovered at the scan root
# is untrusted input that can skip required checks, swap in external checks or
# change the exit code, so the scan is refused before the subprocess starts.
CONFIG_FILE_NAMES: tuple[str, ...] = (".checkov.yaml", ".checkov.yml")

# Keys of the flat, resource-less envelope Checkov 3.3.8 prints when nothing was
# evaluated (empty directory, no Terraform files, only unsupported resources).
FLAT_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"passed", "failed", "skipped", "parsing_errors", "resource_count"}
)
FLAT_OPTIONAL_KEYS: frozenset[str] = frozenset({"checkov_version", "url"})

_SENSITIVE_ENV_EXACT: frozenset[str] = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_CONFIG_FILE",
        "AWS_PROFILE",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "BC_API_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }
)

_SENSITIVE_ENV_RE = re.compile(
    r"^(?:"
    r"CHECKOV_.*"
    r"|CKV_.*"
    r"|PRISMA_.*"
    r"|BC_.*"
    r"|.*_(?:TOKEN|PASSWORD|PASSWD|SECRET|SECRET_KEY|API_KEY|ACCESS_KEY|ACCESS_KEY_ID|CREDENTIALS)"
    r")$",
    re.IGNORECASE,
)

_SECRET_VALUE_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
_WHITESPACE_RE = re.compile(r"\s+")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class CheckovOutputError(Exception):
    """Checkov stdout could not be recognised as a completed scan report."""


# --------------------------------------------------------------------------- #
# Command construction
# --------------------------------------------------------------------------- #
def resolve_command(config: ValidConfig) -> list[str]:
    """Return the configured Checkov argv prefix as a fresh list."""
    configured = getattr(config, "checkov_command", None)
    parts = list(DEFAULT_COMMAND) if configured is None else list(configured)
    argv = [str(part) for part in parts]
    if not argv or any(not part.strip() for part in argv):
        raise ValueError("checkov_command must contain at least one non-empty element")
    return argv


def build_command(path: Path, config: ValidConfig) -> list[str]:
    """Build the full Checkov argv for a Terraform-only scan of ``path``.

    ``path`` always stays a single argv element, so a directory name containing
    shell metacharacters remains inert data.
    """
    target = Path(path)
    argv = resolve_command(config)
    selector = "-f" if target.is_file() else "-d"
    return [*argv, *SCOPE_FLAGS, "-o", "json", selector, str(target)]


def scan_timeout_seconds(config: ValidConfig) -> int:
    """Finite subprocess timeout in seconds, always >= 1."""
    raw = getattr(config, "scanner_timeout_seconds", None)
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 120
    return value if value >= 1 else 1


def _child_environment() -> dict[str, str]:
    """Environment for the scanner: inherited minus credential material.

    ``CHECKOV_*``/``CKV_*`` variables are dropped as well: Checkov reads options
    such as ``CKV_VAR_FILE`` from the environment, which would let the ambient
    environment widen the frozen scan scope.
    """
    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in _SENSITIVE_ENV_EXACT or _SENSITIVE_ENV_RE.match(key):
            continue
        environment[key] = value
    return environment


# --------------------------------------------------------------------------- #
# Sanitisation and path canonicalisation
# --------------------------------------------------------------------------- #
def _squash(text: Any) -> str:
    return _WHITESPACE_RE.sub(" ", str(text)).strip()


def sanitize(text: Any, root: Path | None = None) -> str:
    """Return ``text`` with private absolute paths and secret values removed.

    The scan root is substituted before the home directory, otherwise a root
    nested inside the home directory would only be partially replaced.
    """
    value = _squash(text)
    replacements: list[tuple[str, str]] = []
    if root is not None:
        replacements.append((str(root), "<scan-root>"))
    replacements.append((str(Path.home()), "~"))
    for private, placeholder in replacements:
        if private:
            value = value.replace(private, placeholder)
    return _SECRET_VALUE_RE.sub("<redacted>", value)


def canonical_location(raw: Any, root: Path) -> str | None:
    """Canonicalise a Checkov path to a root-relative forward-slash path.

    Returns ``None`` when the location is unusable: empty, a real path outside
    the scan root, a Windows drive path, or anything containing ``..``. Checkov
    reports locations relative to the scanned directory with a leading slash
    (``/main.tf``), which is resolved against ``root``.
    """
    if raw is None:
        return None
    text = str(raw).strip().replace("\\", "/")
    if not text or "\x00" in text:
        return None
    if text.startswith("/"):
        try:
            resolved = Path(text).resolve()
            return _clean_relative(resolved.relative_to(root).as_posix())
        except (OSError, ValueError):
            pass
        if (root / text.lstrip("/")).exists():
            return _clean_relative(text.lstrip("/"))
        return None
    return _clean_relative(text)


def _clean_relative(candidate: str) -> str | None:
    text = candidate.strip().replace("\\", "/")
    if not text or text.startswith("/") or _WINDOWS_DRIVE_RE.match(text):
        return None
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _retained_text(value: Any, root: Path) -> str | None:
    """Return sanitised free text, or None when nothing usable was supplied."""
    if not isinstance(value, str) or not value.strip():
        return None
    return sanitize(value, root) or None


def _retained_token(entry: dict[str, Any], keys: Sequence[str], root: Path) -> str | None:
    """Return the first usable string value among ``keys``, sanitised."""
    for key in keys:
        candidate = entry.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return sanitize(candidate, root) or None
    return None


def _retained_line_range(value: Any) -> list[int] | None:
    """Return a canonical ``[start, end]`` pair, or None when unusable.

    Only an ordered pair of positive integers carries meaning; anything else is
    dropped instead of being forwarded, which also keeps the artifact free of
    arbitrary supplied shapes.
    """
    if isinstance(value, (list, tuple)) and len(value) == 2:
        start, end = value
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and not isinstance(start, bool)
            and not isinstance(end, bool)
            and start > 0
            and end > 0
            and start <= end
        ):
            return [start, end]
    return None


def _retained_resource(value: Any, root: Path) -> str | dict[str, str | None] | None:
    """Return the resource identity only: a name, or a ``{type, address}`` pair."""
    if isinstance(value, str) and value.strip():
        return sanitize(value, root) or None
    if isinstance(value, dict):
        retained: dict[str, str | None] = {
            "type": _retained_text(value.get("type"), root),
            "address": _retained_text(value.get("address"), root),
        }
        if retained["type"] is not None or retained["address"] is not None:
            return retained
    return None


def _retained_failed_check(
    entry: dict[str, Any], root: Path, location: str
) -> dict[str, Any] | None:
    """Build the minimal retained record for one failed check.

    Returns ``None`` when no usable rule id was supplied: a finding with no
    identity cannot be reported, and the caller records that as required
    malformed data (fail closed) rather than dropping the record silently.
    """
    rule_id = _retained_token(entry, RULE_ID_KEYS, root)
    if rule_id is None:
        return None
    return {
        "check_id": rule_id,
        "check_name": _retained_text(entry.get("check_name"), root),
        "severity": _retained_token(entry, SEVERITY_KEYS, root),
        "file_path": location,
        "file_line_range": _retained_line_range(entry.get("file_line_range")),
        "resource": _retained_resource(entry.get("resource"), root),
    }


def _relative_or_sanitized(text: Any, root: Path) -> str:
    """Sanitise a scanner message, turning a bare in-root path into a relative one.

    Checkov reports parse failures as absolute file paths; those become the
    source-relative path instead of a private absolute one.
    """
    as_path = canonical_location(text, root)
    if as_path is not None:
        return as_path
    value = _squash(text)
    prefix = str(root).rstrip("/") + "/"
    if value.startswith(prefix):
        value = value[len(prefix) :]
    return sanitize(value, root)


# --------------------------------------------------------------------------- #
# Output parsing
# --------------------------------------------------------------------------- #
def _iter_reports(payload: Any) -> list[dict[str, Any]]:
    """Return the report envelopes of a decoded Checkov payload.

    Both envelopes produced by the pinned release are supported: a single report
    object, and a list of per-framework report objects. A payload containing no
    report at all raises; the flat resource-less envelope is handled separately
    by :func:`_flat_counts`.
    """
    if isinstance(payload, dict):
        candidates: list[Any] = [payload]
    elif isinstance(payload, list):
        candidates = list(payload)
    else:
        raise CheckovOutputError("scanner output was JSON but not a report object or list")
    reports = [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict)
        and (
            isinstance(candidate.get("results"), dict)
            or isinstance(candidate.get("summary"), dict)
        )
    ]
    if not reports and _flat_counts(payload) is None:
        raise CheckovOutputError("scanner output contained no recognised Checkov report")
    return reports


def _malformed_report_members(payload: Any) -> list[int]:
    """Indexes of list members that are not recognised report envelopes.

    A multi-framework payload is a list of report objects. A member that is not
    one of those (a string, a number, an object without ``results``/``summary``)
    means part of the payload could not be read, so the surrounding valid report
    must not be presented as covering the whole scan.
    """
    if not isinstance(payload, list):
        return []
    return [
        index
        for index, candidate in enumerate(payload)
        if not (
            isinstance(candidate, dict)
            and (
                isinstance(candidate.get("results"), dict)
                or isinstance(candidate.get("summary"), dict)
            )
        )
    ]


def _flat_counts(payload: Any) -> dict[str, int] | None:
    """Return the resource-less count envelope, when the payload is that shape.

    The shape is accepted only when every key is known and all required counters
    are present, so an arbitrary JSON object is never mistaken for a scan report.
    """
    if not isinstance(payload, dict):
        return None
    keys = set(payload)
    if not keys or not keys <= (FLAT_REQUIRED_KEYS | FLAT_OPTIONAL_KEYS):
        return None
    if not FLAT_REQUIRED_KEYS <= keys:
        return None
    counts = {
        key: value
        for key, value in payload.items()
        if isinstance(value, int) and not isinstance(value, bool)
    }
    if not FLAT_REQUIRED_KEYS <= set(counts):
        return None
    return counts


def load_payload(
    stdout: str,
) -> tuple[list[dict[str, Any]], dict[str, int] | None, list[int]]:
    """Decode Checkov stdout into (reports, flat_counts, malformed_members).

    Tolerates leading/trailing wrapper noise; rejects empty, malformed and
    unrecognised output. ``malformed_members`` lists the positions of any list
    entries that are not report envelopes.
    """
    text = (stdout or "").strip()
    if not text:
        raise CheckovOutputError("scanner produced no output")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = _decode_embedded(text)
    reports = _iter_reports(payload)
    if reports:
        return reports, None, _malformed_report_members(payload)
    flat = _flat_counts(payload)
    if flat is None:  # pragma: no cover - guarded by _iter_reports
        raise CheckovOutputError("scanner output contained no recognised Checkov report")
    return [], flat, []


def _decode_embedded(text: str) -> Any:
    """Decode an embedded Checkov payload surrounded by wrapper noise.

    More than one recognised payload is treated as an error rather than silently
    reporting only the first one, because dropping a report could hide findings.
    """
    decoder = json.JSONDecoder()
    recognized: list[Any] = []
    index = 0
    while index < len(text):
        candidates = [pos for pos in (text.find("{", index), text.find("[", index)) if pos != -1]
        if not candidates:
            break
        start = min(candidates)
        try:
            value, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        try:
            _iter_reports(value)
        except CheckovOutputError:
            index = start + 1
            continue
        recognized.append(value)
        index = start + end
    if not recognized:
        raise CheckovOutputError("scanner output was not valid JSON")
    if len(recognized) > 1:
        raise CheckovOutputError("scanner output contained more than one report")
    return recognized[0]


def _text_list(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [f"{key}: {item}" for key, item in value.items()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _sanitize_parsing_errors(reports: Iterable[dict[str, Any]], root: Path) -> list[str]:
    collected: list[str] = []
    for report in reports:
        results = report.get("results")
        if not isinstance(results, dict):
            continue
        for entry in _text_list(results.get("parsing_errors")):
            note = _relative_or_sanitized(entry, root)
            if note and note not in collected:
                collected.append(note)
    return collected


def _sanitize_checks(
    reports: Iterable[dict[str, Any]], root: Path
) -> tuple[list[dict[str, Any]], list[str], int, list[str]]:
    """Return (failed_checks, evaluated_files, rejected, malformed, unidentified).

    ``failed_checks`` are minimal retained records, never the scanner's own
    record: see :func:`_retained_failed_check`.  ``rejected`` counts failed
    checks dropped because their location was unusable, and ``unidentified``
    counts failed checks dropped because no usable rule id was supplied; both
    are reported as required data loss rather than skipped silently.
    ``malformed`` names required result structures that could not be read: a
    ``results`` or ``summary`` object that is the wrong type, a check bucket
    that is present but not a list, or a bucket entry that is not an object.
    Those are reported instead of being skipped, because silently skipping them
    could hide failed checks.  A bucket that is *absent* is tolerated: the
    pinned release omits the buckets that do not apply to a framework report.
    """
    failed: list[dict[str, Any]] = []
    evaluated: set[str] = set()
    rejected = 0
    unidentified = 0
    malformed: set[str] = set()
    for report in reports:
        summary = report.get("summary")
        if summary is not None and not isinstance(summary, dict):
            # A summary that is present but unreadable is malformed supplied
            # data, not unavailable metadata, so it must fail closed.
            malformed.add("summary")
        results = report.get("results")
        if results is None:
            continue
        if not isinstance(results, dict):
            malformed.add("results")
            continue
        for bucket in ("failed_checks", "passed_checks", "skipped_checks"):
            if bucket not in results:
                continue
            entries = results[bucket]
            if not isinstance(entries, list):
                malformed.add(bucket)
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    malformed.add(bucket)
                    continue
                location = canonical_location(entry.get("file_path"), root)
                if location is None:
                    if bucket == "failed_checks":
                        rejected += 1
                    continue
                if bucket == "skipped_checks":
                    # A skipped row is a coverage limitation, not evaluated
                    # evidence, so it must not make the scan look covered.
                    continue
                evaluated.add(location)
                if bucket != "failed_checks":
                    continue
                record = _retained_failed_check(entry, root, location)
                if record is None:
                    unidentified += 1
                    continue
                failed.append(record)
    # Scanner emission order is not evidence. Sort only the sanitized records;
    # the complete canonical value handles mixed resource types and ties while
    # preserving every retained field and duplicate record.
    failed.sort(key=lambda record: json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return failed, sorted(evaluated), rejected, sorted(malformed), unidentified


def _skipped_check_presence(
    reports: Iterable[dict[str, Any]],
) -> tuple[int, list[str]]:
    """Return (skipped record count, readable check ids) for a payload.

    A skipped check (inline ``checkov:skip`` comment, or a trusted snapshot
    policy) is evidence the scan does not cover, so it is surfaced as a coverage
    limitation instead of being read as an evaluated check. The count comes from
    record presence, so a missing, empty or malformed ``check_id`` can never
    erase the limitation; ids are only used for the diagnostic text.
    """
    count = 0
    ids: list[str] = []
    for report in reports:
        results = report.get("results")
        if not isinstance(results, dict):
            continue
        entries = results.get("skipped_checks")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            count += 1
            if not isinstance(entry, dict):
                continue
            check_id = entry.get("check_id")
            if isinstance(check_id, str) and check_id and check_id not in ids:
                ids.append(check_id)
    return count, ids


def _declared_counter_totals(
    reports: Iterable[dict[str, Any]],
) -> tuple[dict[str, int], set[str], set[str]]:
    """Declared totals, which counters are comparable, and which are malformed.

    Intended to be called with a *single* report so each report's supplied
    counters are judged on their own. Within that one report a counter is
    comparable only when it is stated as a non-negative integer: an absent
    summary or an explicitly null counter makes it unknowable, so it is dropped
    from ``comparable`` rather than invented. A counter supplied with a value of
    the wrong shape is malformed rather than missing, so it is returned for
    fail-closed handling even when another report carries no summary at all.
    """
    totals = {key: 0 for key, _ in _COUNTER_FIELDS}
    comparable = {key for key, _ in _COUNTER_FIELDS}
    malformed: set[str] = set()
    for report in reports:
        summary = report.get("summary")
        if not isinstance(summary, dict):
            comparable.clear()
            break
        for key, _ in _COUNTER_FIELDS:
            if key not in summary or summary[key] is None:
                comparable.discard(key)
                continue
            value = summary[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                malformed.add(key)
                comparable.discard(key)
                continue
            totals[key] += value
    return totals, comparable, malformed


def _observed_counter_totals(reports: Iterable[dict[str, Any]]) -> dict[str, int | None]:
    """Raw record counts actually carried by one report's own buckets.

    Entries are counted before validation, so declared-versus-observed compares
    presence rather than how many records survived sanitisation. ``None`` means
    the bucket was present but unreadable, so no count can be compared.
    """
    observed: dict[str, int | None] = {key: 0 for key, _ in _COUNTER_FIELDS}
    for report in reports:
        results = report.get("results")
        if results is None:
            continue
        if not isinstance(results, dict):
            for key, _ in _COUNTER_FIELDS:
                observed[key] = None
            continue
        for key, bucket in _COUNTER_FIELDS:
            if observed[key] is None:
                continue
            entries = results.get(bucket)
            if entries is None:
                continue
            if not isinstance(entries, list):
                observed[key] = None
                continue
            observed[key] += len(entries)
    return observed


def _missing_record_notes(
    declared: dict[str, int],
    comparable: set[str],
    observed: dict[str, int | None],
) -> list[str]:
    """Diagnostics for counters that declare more records than are present.

    A summary that says ``failed=1`` while the ``failed_checks`` bucket is
    absent, or a failure list shorter than its counter, means required records
    were lost or truncated. That must fail closed instead of reading as a clean
    scan; the readable records are still reported.
    """
    labels = {
        "failed": "failed check",
        "skipped": "skipped check",
        "parsing_errors": "parsing error",
    }
    notes: list[str] = []
    for key, _ in _COUNTER_FIELDS:
        count = observed.get(key)
        if key not in comparable or count is None or declared[key] <= count:
            continue
        notes.append(
            f"checkov: the report declares {declared[key]} {labels[key]}(s) but only "
            f"{count} record(s) were present; {declared[key] - count} required "
            "record(s) are missing or truncated"
        )
    return notes


def _counter_evidence_notes(
    reports: Iterable[dict[str, Any]],
) -> tuple[list[str], set[str]]:
    """Validate each report's counters against that report's own records.

    Every report is inspected on its own, so an unrelated report's absent
    summary, absent/null counter or empty bucket can neither suppress nor offset
    known missing evidence, and a supplied malformed counter is still seen after
    a report with no summary. Unavailable counters stay unavailable for that
    report; nothing is invented. Returns the (deduplicated, bounded)
    missing-record diagnostics and the malformed counter names.
    """
    notes: list[str] = []
    malformed: set[str] = set()
    for report in reports:
        declared, comparable, report_malformed = _declared_counter_totals([report])
        observed = _observed_counter_totals([report])
        malformed |= report_malformed
        for note in _missing_record_notes(declared, comparable, observed):
            if note not in notes:
                notes.append(note)
    if len(notes) > COUNTER_NOTE_LIMIT:
        hidden = len(notes) - COUNTER_NOTE_LIMIT
        notes = notes[:COUNTER_NOTE_LIMIT] + [
            f"checkov: {hidden} further report(s) also declared records that were "
            "missing or truncated"
        ]
    return notes, malformed


def detected_config_files(root: Path) -> list[str]:
    """Checkov config files the scanner would auto-discover at the scan root.

    ``root`` may be the scan directory or a single scanned file; Checkov scans
    the containing directory in the latter case, so the containing directory is
    what gets inspected.
    """
    scope_root = root.parent if root.is_file() else root
    if not scope_root.is_dir():
        return []
    return [name for name in CONFIG_FILE_NAMES if (scope_root / name).is_file()]


# --------------------------------------------------------------------------- #
# Result construction
# --------------------------------------------------------------------------- #
def _error_result(
    message: str,
    root: Path | None,
    *,
    return_code: int | None = None,
    coverage_notes: Sequence[str] = (),
    stages: Sequence[str] = (EXECUTION_STAGE,),
    gaps: Sequence[str] = (),
) -> RawScanResult:
    return RawScanResult(
        status="error",
        tool="checkov",
        version=CHECKOV_VERSION,
        failed_checks=[],
        parsing_errors=[],
        coverage=Coverage(
            required_failed_stages=list(stages),
            required_gaps=list(gaps),
            diagnostics=[sanitize(note, root) for note in coverage_notes],
        ),
        return_code=return_code,
        diagnostics=[sanitize(message, root)],
    )


def _resolve_root(path: Any) -> tuple[Path | None, RawScanResult | None]:
    try:
        candidate = Path(path)
    except (TypeError, ValueError):
        return None, _error_result("scan path is not a usable filesystem path", None)
    try:
        root = candidate.resolve(strict=True)
    except OSError:
        return None, _error_result("scan path does not exist or cannot be resolved", None)
    if not root.is_dir() and not root.is_file():
        return None, _error_result("scan path is neither a file nor a directory", root)
    if not os.access(root, os.R_OK):
        return None, _error_result("scan path is not readable", root)
    if root.is_dir() and not os.access(root, os.R_OK | os.X_OK):
        return None, _error_result("scan directory is not searchable", root)
    return root, None


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run(path: Path, config: ValidConfig) -> RawScanResult:
    """Run real Checkov against ``path`` and return a raw scan result.

    Never raises for scan-level problems: execution failures come back as
    ``status="error"`` with a required stage failure, so the caller cannot report
    them as a clean scan.
    """
    target, failure = _resolve_root(path)
    if failure is not None or target is None:
        return failure  # type: ignore[return-value]

    scope_root = target.parent if target.is_file() else target

    try:
        argv = build_command(target, config)
    except ValueError as error:
        return _error_result(str(error), scope_root)

    timeout = scan_timeout_seconds(config)
    scope_notes = [
        "checkov: framework=terraform only; external module downloads disabled",
        f"checkov: timeout={timeout}s",
    ]
    config_files = detected_config_files(target)
    if config_files:
        # Checkov honours a config file discovered at the scan root, so supplied
        # input could skip a required check or point the scanner at extra
        # checks.  The scan is refused before any subprocess starts: a completed
        # result that silently covers less than the frozen policy is worse than
        # an explicit INCOMPLETE.
        scope_notes.append(
            "checkov: scan root contains "
            + ", ".join(config_files)
            + "; untrusted scanner configuration is not executed"
        )
        return _error_result(
            "checkov scan refused: the scan root contains untrusted scanner "
            "configuration ("
            + ", ".join(config_files)
            + "); a supplied policy file can suppress required checks",
            scope_root,
            coverage_notes=scope_notes,
            gaps=[LOCAL_CONFIG_GAP],
        )

    with tempfile.TemporaryDirectory(prefix="valid-checkov-") as workdir:
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=workdir,
                env=_child_environment(),
                stdin=subprocess.DEVNULL,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _error_result(
                f"checkov timed out after {timeout}s", scope_root, coverage_notes=scope_notes
            )
        except FileNotFoundError:
            return _error_result(
                f"checkov executable not found: {Path(argv[0]).name}",
                scope_root,
                coverage_notes=scope_notes,
            )
        except OSError as error:
            return _error_result(
                f"checkov could not be executed: {type(error).__name__}",
                scope_root,
                coverage_notes=scope_notes,
            )

    return_code = completed.returncode
    if return_code not in COMPLETED_RETURN_CODES:
        # Exit 0 (nothing failed) and 1 (failed checks reported) are the only
        # completed statuses.  Anything else means the scanner did not finish
        # normally, so even recognised JSON cannot be trusted as a full scan.
        return _error_result(
            f"checkov exited with unexpected status {return_code}; the report "
            "cannot be trusted as a completed scan",
            scope_root,
            return_code=return_code,
            coverage_notes=scope_notes,
        )

    try:
        reports, flat_counts, malformed_members = load_payload(completed.stdout)
    except CheckovOutputError as error:
        return _error_result(
            f"checkov output could not be parsed: {error}",
            scope_root,
            return_code=return_code,
            coverage_notes=scope_notes,
        )

    (
        failed_checks,
        evaluated_files,
        rejected,
        malformed,
        unidentified,
    ) = _sanitize_checks(reports, scope_root)
    parsing_errors = _sanitize_parsing_errors(reports, scope_root)
    skipped_count, skipped_ids = _skipped_check_presence(reports)
    missing_notes, malformed_counters = _counter_evidence_notes(reports)
    malformed = sorted(set(malformed) | malformed_counters)
    if unidentified:
        # A failed record the adapter could not identify is required data that
        # could not be read, so it must fail closed like any other malformed
        # required structure instead of vanishing from the artifact.
        malformed = sorted(set(malformed) | {"failed_check.check_id"})

    coverage = Coverage(
        required_failed_stages=[PARSING_STAGE] if parsing_errors else [],
        required_gaps=[MALFORMED_RESULTS_GAP]
        if (malformed or malformed_members)
        else [],
        evaluated_files=evaluated_files,
        diagnostics=[sanitize(note, scope_root) for note in scope_notes],
    )
    diagnostics: list[str] = []
    if malformed:
        diagnostics.append(
            "checkov: malformed required result structure ("
            + ", ".join(sorted(malformed)[:10])
            + "); the affected records were rejected, not ignored"
        )
    if malformed_members:
        diagnostics.append(
            f"checkov: {len(malformed_members)} report list member(s) were not "
            "report envelopes and were rejected, not ignored (index "
            + ", ".join(str(index) for index in malformed_members[:10])
            + ")"
        )
    if unidentified:
        diagnostics.append(
            f"checkov: {unidentified} failed check(s) were omitted because no "
            "usable rule id was supplied; a failed record with no identity "
            "cannot be reported"
        )
    if missing_notes:
        coverage.required_gaps.append(MISSING_RECORDS_GAP)
        diagnostics.extend(missing_notes)
    if skipped_count:
        coverage.required_gaps.append(SKIPPED_CHECKS_GAP)
        detail = ", ".join(skipped_ids[:10]) if skipped_ids else (
            "no diagnostic check ids were supplied"
        )
        diagnostics.append(
            f"checkov: {skipped_count} check(s) skipped, so their evidence was "
            f"not evaluated: {detail}"
        )
    if rejected:
        coverage.required_gaps.append(UNUSABLE_LOCATION_GAP)
        diagnostics.append(
            f"checkov: {rejected} failed check(s) omitted because their file path was "
            "outside the scan root or unusable"
        )
    if not failed_checks and not evaluated_files and not parsing_errors:
        coverage.required_gaps.append(NO_EVALUATED_FILES_GAP)
        resource_count = (flat_counts or {}).get("resource_count")
        detail = f" (resource_count={resource_count})" if resource_count is not None else ""
        diagnostics.append(f"checkov: no Terraform resources were evaluated{detail}")

    return RawScanResult(
        status="complete",
        tool="checkov",
        version=CHECKOV_VERSION,
        failed_checks=failed_checks,
        parsing_errors=parsing_errors,
        coverage=coverage,
        return_code=return_code,
        # Some diagnostics embed scanner-supplied text (skipped check ids), so
        # every retained free-text diagnostic is sanitised like the records are.
        diagnostics=[sanitize(note, scope_root) for note in diagnostics],
    )
