"""Literal HCL parser and deterministic custom rules for V.A.L.I.D.

This module performs a *literal* (no variable/module resolution) parse of
Terraform ``.tf`` files and evaluates three custom rules:

* ``DG-AWS-NET-001`` - public inbound SSH (``0.0.0.0/0`` on TCP 22).
* ``DG-AWS-TAG-001`` - missing/empty required tags.
* ``DG-AWS-RDS-001`` - explicit ``deletion_protection = false``.

It relies on a real HCL parser (never regex) and degrades to visible
coverage gaps whenever the input cannot be understood literally.
"""

from __future__ import annotations

import io
import ipaddress
import re
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - import guard exercised by integration environment
    import hcl2  # type: ignore
except Exception as exc:  # pragma: no cover
    hcl2 = None  # type: ignore[assignment]
    _HCL2_IMPORT_ERROR: str | None = f"{type(exc).__name__}: {exc}"
else:
    _HCL2_IMPORT_ERROR = None

# Frozen identities of the three deterministic custom rules.
TOOL = "valid"
VERSION = "0.1.0"

RULE_NET = "DG-AWS-NET-001"
RULE_TAG = "DG-AWS-TAG-001"
RULE_RDS = "DG-AWS-RDS-001"
RULE_COVERAGE = "DG-COVERAGE-GAP"

SSH_PORT = 22
PUBLIC_CIDR = "0.0.0.0/0"
INTERPOLATION_START = "${"
PROTOCOL_ANY = "-1"
PROTOCOL_ALL_KEYWORDS = frozenset({"all", "any"})
PROTOCOL_ALL_TOKENS = frozenset({PROTOCOL_ANY}) | PROTOCOL_ALL_KEYWORDS
PROTOCOL_TCP_NUMBER = "6"  # IANA protocol number for TCP.
# Non-TCP protocols literal analysis can classify safely: they cannot carry
# TCP 22, so a rule limited to one of them is clean.  Anything else is an
# unsupported token whose TCP coverage is undecidable (a required gap).
PROTOCOL_UDP_TOKENS = frozenset({"udp", "17"})  # 17 = IANA UDP
PROTOCOL_ICMP_TOKENS = frozenset({"icmp", "1", "icmpv6", "58"})  # 1 = ICMP, 58 = ICMPv6

# Supported implicit provider scope: V.A.L.I.D.'s custom rules and default
# taggable types are AWS resources served by the ``aws`` provider.
AWS_RESOURCE_PREFIX = "aws_"
AWS_PROVIDER_NAME = "aws"

RESERVED_KEYS = frozenset({"__is_block__", "__start_line__", "__end_line__", "__comments__"})
_PROVIDER_ARG = "provider"

LITERAL_HCL = "literal_hcl"
COVERAGE_GAP = "coverage_gap"


class CoverageGap(RuntimeError):
    """Raised when required literal coverage cannot be produced."""

    def __init__(self, reason: str, *, path: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.path = path


# ---------------------------------------------------------------------------
# Parser-version-tolerant helpers
# ---------------------------------------------------------------------------


def _require_hcl2() -> Any:
    if hcl2 is None:  # pragma: no cover - only reachable without the dependency
        raise CoverageGap(
            "HCL parser unavailable: cannot import hcl2 "
            f"({_HCL2_IMPORT_ERROR}); literal Terraform evaluation impossible"
        )
    return hcl2


def _is_interpolation(value: Any) -> bool:
    """True when *value* contains a Terraform interpolation/reference."""
    if isinstance(value, str):
        return INTERPOLATION_START in value
    if isinstance(value, (list, tuple)):
        return any(_is_interpolation(item) for item in value)
    if isinstance(value, dict):
        return any(_is_interpolation(item) for item in value.values())
    return False


def _first(value: Any) -> Any:
    """Unwrap the single-element lists some parser versions emit."""
    while isinstance(value, list):
        if not value:
            return None
        value = value[0]
    return value


def _container(value: Any) -> Any:
    """Unwrap only the parser's outer single-element container list.

    ``cidr_blocks = ["a", "b"]`` is emitted as ``[["a", "b"]]``: unwrapping
    that one container keeps the real list intact, unlike :func:`_first`
    which collapses it to its first item.
    """
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _unwrap(value: Any) -> Any:
    """Normalise a block-attribute value to the shape the rules expect.

    ``bc-python-hcl2`` wraps a scalar attribute as ``[value]`` and keeps an
    object/block attribute as ``[{...}]``.  Object attributes are returned as
    a plain dict so the tag rule can read them directly.
    """
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
        return value[0]
    return _first(value)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _strip_quotes(text: str) -> str:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _plain_str(value: Any) -> str:
    """Return a literal string, keeping ``${...}`` references verbatim."""
    unwrapped = _first(value)
    if isinstance(unwrapped, str):
        return unwrapped.strip() if _is_interpolation(unwrapped) else _strip_quotes(unwrapped)
    if isinstance(unwrapped, bool):
        return "true" if unwrapped else "false"
    if isinstance(unwrapped, int | float):
        return str(unwrapped)
    return ""


def _literal_blocks(doc: dict[str, Any]) -> list[tuple[str, Any]]:
    """Yield ``(block_type, payload)`` pairs from a parsed document."""
    if not isinstance(doc, dict):
        return []
    return [
        (block_type, payload)
        for block_type, payload in doc.items()
        if block_type not in RESERVED_KEYS
    ]


def _iter_block_entries(payload: Any) -> Iterable[tuple[Any, Any]]:
    """Iterate ``(label, body)`` entries of a top-level block list."""
    for entry in _as_list(payload):
        if not isinstance(entry, dict):
            continue
        for key, value in entry.items():
            if key in RESERVED_KEYS:
                continue
            yield key, value


def _resource_entries(
    payload: Any,
) -> Iterable[tuple[str, str, dict[str, Any], int | None, int | None]]:
    """Yield ``(type, name, body, start, end)`` for every resource entry."""
    for type_key, type_body in _iter_block_entries(payload):
        resource_type = _plain_str(type_key)
        if isinstance(type_body, dict):
            type_start = type_body.get("__start_line__")
            type_end = type_body.get("__end_line__")
            for name_key, body in type_body.items():
                if name_key in RESERVED_KEYS:
                    continue
                if isinstance(body, dict):
                    start = body.get("__start_line__")
                    end = body.get("__end_line__")
                else:
                    start, end = None, None
                if start is None:
                    start = type_start
                if end is None:
                    end = type_end
                yield (
                    resource_type,
                    _plain_str(name_key),
                    body if isinstance(body, dict) else {},
                    start,
                    end,
                )
        else:
            yield resource_type, "", {}, None, None


def _provider_default_tags(body: dict[str, Any]) -> dict[str, Any] | None:
    """Extract a literal ``default_tags.tags`` map from a provider body."""
    defaults = _first(body.get("default_tags"))
    if not isinstance(defaults, dict):
        return None
    tags = _first(defaults.get("tags"))
    if not isinstance(tags, dict):
        return None
    return {str(key): _first(value) for key, value in tags.items()}


def _nested_blocks(body: dict[str, Any], *names: str) -> list[dict[str, Any]]:
    """Return inline block bodies for the given block labels."""
    found: list[dict[str, Any]] = []
    for name in names:
        for entry in _as_list(body.get(name)):
            entry = _first(entry)
            if isinstance(entry, dict):
                found.append(entry)
    return found


def _is_inline_block(value: Any) -> bool:
    """True when *value* looks like an inline block (``ingress { ... }``).

    One parser dialect marks blocks with ``__is_block__``; the pinned dialect
    emits a list of block-body dicts instead.
    """
    if isinstance(value, dict):
        return True
    if isinstance(value, list) and value:
        return all(isinstance(item, dict) for item in value)
    return False


def _attributes(body: dict[str, Any]) -> dict[str, Any]:
    """Return literal attributes, dropping parser metadata only.

    Inline blocks (``ingress { ... }``) and object attributes (``tags = { ... }``)
    are both kept: the two dialects are not reliably distinguishable by shape,
    and DG-AWS-NET-001 / DG-AWS-TAG-001 read these values directly.  Anything
    containing an interpolation is reported as unresolved by the caller.
    """
    attrs: dict[str, Any] = {}
    for key, value in body.items():
        if key in RESERVED_KEYS:
            continue
        attrs[key] = value
    return attrs


# ---------------------------------------------------------------------------
# Document loading (parser-version tolerant, with line numbers)
# ---------------------------------------------------------------------------


def _tree_block_lines(parser: Any, text: str) -> dict[str, tuple[int | None, int | None]]:
    """Map ``TYPE.NAME`` -> ``(start, end)`` using the parser's lark tree.

    Returns an empty mapping when the installed parser exposes no tree API;
    callers then rely on dict-level ``__start_line__`` metadata.
    """
    tree_parser = getattr(parser, "parse_to_tree", None)
    if tree_parser is None:
        return {}
    try:
        tree = tree_parser(io.StringIO(text))
    except Exception:
        return {}

    lines: dict[str, tuple[int | None, int | None]] = {}

    def labels_of(block: Any) -> list[str]:
        labels: list[str] = []
        for child in getattr(block, "children", []) or []:
            if getattr(child, "data", None) != "string":
                continue
            parts = [
                sub
                for sub in getattr(child, "children", []) or []
                if getattr(sub, "data", None) == "string_part"
            ]
            if parts:
                tokens = getattr(parts[0], "children", []) or []
                if tokens:
                    labels.append(str(getattr(tokens[0], "value", tokens[0])))
        return labels

    def visit(node: Any) -> None:
        if getattr(node, "data", None) == "block":
            labels = labels_of(node)
            if len(labels) >= 2:
                meta = getattr(node, "meta", None)
                lines.setdefault(
                    f"{labels[0]}.{labels[1]}",
                    (getattr(meta, "line", None), getattr(meta, "end_line", None)),
                )
        for child in getattr(node, "children", []) or []:
            visit(child)

    try:
        visit(tree)
    except Exception:
        return {}
    return lines


def _load_document(parser: Any, text: str) -> dict[str, Any]:
    """Parse *text* into a document dict.

    Raises :class:`CoverageGap` when the HCL is malformed.
    """
    options_cls = getattr(getattr(parser, "utils", None), "SerializationOptions", None)
    load = getattr(parser, "load", None)
    if load is None:  # pragma: no cover - defensive
        raise CoverageGap("HCL parser exposes no load() entry point")

    attempts: list[dict[str, Any]] = [{}]
    if options_cls is not None:
        # python-hcl2 >= 8: with_meta=True marks blocks and keeps comments.
        try:
            attempts.insert(0, {"serialization_options": options_cls(with_meta=True)})
        except Exception:
            pass

    last_error: Exception | None = None
    for kwargs in attempts:
        try:
            doc = load(io.StringIO(text), **kwargs)
        except TypeError:
            continue
        except Exception as exc:  # lark syntax errors land here
            last_error = exc
            continue
        if isinstance(doc, dict):
            return doc
    if last_error is not None:
        raise CoverageGap(f"malformed HCL: {type(last_error).__name__}: {last_error}")
    raise CoverageGap("HCL parser returned no usable document")


# ---------------------------------------------------------------------------
# Model construction
# ---------------------------------------------------------------------------


def _build_models() -> tuple[Any, Any]:
    """Import the frozen foundation models.

    Raises :class:`CoverageGap` with an explicit reason when
    ``valid.terraform_types`` is unavailable.
    """
    try:
        from valid.terraform_types import ParsedScan, ResourceBlock  # type: ignore
    except Exception as exc:
        raise CoverageGap(
            "foundation models unavailable: cannot import valid.terraform_types "
            f"({type(exc).__name__}: {exc}); ParsedScan/ResourceBlock required for parse()"
        ) from exc
    return ParsedScan, ResourceBlock


def _safe_relative_path(path: Path, root: Path) -> str:
    """Return a forward-slash root-relative path, rejecting traversal."""
    resolved = path.resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise CoverageGap(
            f"unsafe path outside scan root: {path.name or '.'}"
        ) from exc
    return resolved.relative_to(root_resolved).as_posix()


def _is_safe_file(path: Path, root: Path) -> bool:
    """Reject symlinks and any file resolving outside *root*."""
    try:
        if path.is_symlink():
            return False
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _relative_to_root(path: Path, root: Path) -> str:
    """Best-effort root-relative POSIX path (used for gap reasons).

    Falls back to the bare file name so a diagnostic never exposes a private
    absolute path.
    """
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name or "."


def _discover_files(path: Path) -> list[Path]:
    """Return the Terraform files to parse for *path* (a file or directory)."""
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(child for child in path.rglob("*.tf") if child.is_file())
    return []


def parse(path: Path, config: Any) -> Any:
    """Parse Terraform at *path* into a :class:`ParsedScan`.

    Literal evaluation only: no variables, locals, modules or provider
    aliases are resolved.  Anything that cannot be read literally becomes a
    visible coverage gap rather than a silent skip.
    """
    ParsedScan, ResourceBlock = _build_models()
    parser = _require_hcl2()

    path = Path(path)
    if not path.exists():
        raise CoverageGap(f"scan path does not exist: {path.name or '.'}")

    root = path if path.is_dir() else path.parent
    files = _discover_files(path)

    parsed: dict[str, list[Any]] = {}
    required_gaps: list[str] = []
    optional_gaps: list[str] = []
    diagnostics: list[str] = []
    evaluated: list[str] = []

    if not files:
        required_gaps.append(
            f"no Terraform files found under scan root '{path.name or '.'}'"
        )

    for file_path in files:
        if not _is_safe_file(file_path, root):
            skipped = _relative_to_root(file_path, root)
            diagnostics.append(f"skipped unsafe/symlinked file: {skipped}")
            required_gaps.append(
                f"{skipped}: unsafe symlink or path outside scan root; not evaluated"
            )
            continue
        relative = _safe_relative_path(file_path, root)
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            required_gaps.append(f"{relative}: unreadable file ({type(exc).__name__})")
            continue
        try:
            document = _load_document(parser, text)
        except CoverageGap as gap:
            required_gaps.append(f"{relative}: {gap.reason}")
            continue

        evaluated.append(relative)
        required_gaps.extend(_module_gaps(document, relative))
        blocks = _document_blocks(document, ResourceBlock, relative, parser, text)
        if blocks:
            parsed[relative] = blocks

    return ParsedScan(
        parsed=parsed,
        coverage=_coverage(
            required_gaps=required_gaps,
            optional_gaps=optional_gaps,
            evaluated=evaluated,
            diagnostics=diagnostics,
        ),
    )


def _coverage(
    *,
    required_gaps: list[str] | None = None,
    optional_gaps: list[str] | None = None,
    evaluated: list[str] | None = None,
    diagnostics: list[str] | None = None,
) -> Any:
    """Build a :class:`Coverage` model with fresh factories."""
    try:
        from valid.models import Coverage  # type: ignore
    except Exception as exc:  # pragma: no cover - foundation prerequisite
        raise CoverageGap(
            f"foundation models unavailable: cannot import valid.models ({exc})"
        ) from exc
    return Coverage(
        required_gaps=list(required_gaps or []),
        optional_gaps=list(optional_gaps or []),
        evaluated_files=list(evaluated or []),
        diagnostics=list(diagnostics or []),
    )


def _document_blocks(
    document: dict[str, Any],
    ResourceBlock: Any,
    relative: str,
    parser: Any,
    text: str,
) -> list[Any]:
    """Convert a parsed document into :class:`ResourceBlock` instances."""
    tree_lines = _tree_block_lines(parser, text)
    blocks: list[Any] = []
    for block_type, payload in _literal_blocks(document):
        if block_type == "resource":
            for type_name, name, body, start, end in _resource_entries(payload):
                line_start, line_end = tree_lines.get(f"{type_name}.{name}", (None, None))
                blocks.append(
                    _resource_block(
                        ResourceBlock,
                        relative,
                        type_name,
                        name,
                        body,
                        line_start if line_start is not None else start,
                        line_end if line_end is not None else end,
                    )
                )
        elif block_type == "provider":
            for label, body in _iter_block_entries(payload):
                alias = _plain_str(_first(body.get("alias"))) if isinstance(body, dict) else ""
                blocks.append(
                    _provider_block(ResourceBlock, relative, _plain_str(label), alias, body)
                )
    return blocks


def _split_attributes(body: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Split a block body into literal values and unresolved attribute names.

    Nested block bodies (``ingress { ... }``) and object attributes
    (``tags = { ... }``) are structurally indistinguishable, so both are kept
    in the literal map.  The three rules read them directly and must be able to
    report a required gap for an unresolvable value *inside* them, which would
    be impossible if the container were dropped.  Plain values containing an
    interpolation are named unresolved and excluded from the literal map.
    """
    attrs = _attributes(body)
    literal: dict[str, Any] = {}
    unresolved: list[str] = []
    for key, value in attrs.items():
        if _is_inline_block(value):
            literal[key] = value
            if _is_interpolation(value):
                unresolved.append(key)
        elif _is_interpolation(value):
            unresolved.append(key)
        else:
            literal[key] = value
    return literal, sorted(unresolved)


def _resource_block(
    ResourceBlock: Any,
    relative: str,
    type_name: str,
    name: str,
    body: dict[str, Any],
    start: int | None,
    end: int | None,
) -> Any:
    address = f"{type_name}.{name}" if name else type_name
    literal, unresolved = _split_attributes(body)
    # A literal ``provider`` argument is recorded as a plain association string
    # (``aws`` or ``aws.west``) even though the parser presents the traversal as
    # an interpolation.  A genuinely dynamic reference stays unresolved so the
    # tag rule reports a coverage gap instead of guessing an association.
    association = _provider_reference(body.get(_PROVIDER_ARG))
    if association is not None:
        literal[_PROVIDER_ARG] = association
        unresolved = [name for name in unresolved if name != _PROVIDER_ARG]
    return ResourceBlock(
        block_type="resource",
        resource_type=type_name,
        name=name,
        address=address,
        path=relative,
        start_line=start,
        end_line=end,
        literal_attributes=literal,
        unresolved_attributes=unresolved,
    )


def _provider_block(
    ResourceBlock: Any,
    relative: str,
    provider_type: str,
    alias: str,
    body: Any,
) -> Any:
    """Record a provider block with its literal ``default_tags``.

    ``alias`` is the explicit provider ``alias`` argument; the block label is
    ``provider_type`` (e.g. ``aws``).  The address follows the frozen contract:
    ``provider.<type>`` or ``provider.<type>.<alias>``.
    """
    alias_name = alias or "default"
    attrs = _attributes(body) if isinstance(body, dict) else {}
    unresolved = sorted(key for key, value in attrs.items() if _is_interpolation(value))
    literal = {key: value for key, value in attrs.items() if not _is_interpolation(value)}
    literal["alias"] = alias_name
    defaults = _provider_default_tags(body) if isinstance(body, dict) else None
    if defaults is not None and not any(_is_interpolation(v) for v in defaults.values()):
        literal["default_tags"] = defaults
    address = (
        f"provider.{provider_type}"
        if alias_name == "default"
        else f"provider.{provider_type}.{alias_name}"
    )
    return ResourceBlock(
        block_type="provider",
        resource_type=provider_type,
        name=alias_name,
        address=address,
        path=relative,
        start_line=None,
        end_line=None,
        literal_attributes=literal,
        unresolved_attributes=unresolved,
    )


def _module_gaps(document: dict[str, Any], relative: str) -> list[str]:
    """Report module blocks whose content cannot be resolved literally.

    ``ResourceBlock`` is frozen to ``block_type in {"resource", "provider"}``,
    so modules are never modelled as blocks; their unresolved content is
    reported as a visible required coverage gap instead.
    """
    gaps: list[str] = []
    for block_type, payload in _literal_blocks(document):
        if block_type != "module":
            continue
        for label, body in _iter_block_entries(payload):
            source = _plain_str(_first(body.get("source"))) if isinstance(body, dict) else ""
            location = f"{relative}:module.{_plain_str(label)}"
            gaps.append(
                f"{location}: module content is not resolved by literal parsing "
                f"(source={source or 'unknown'}); rules inside it are not evaluated"
            )
    return gaps


# ---------------------------------------------------------------------------
# Network rule helpers
# ---------------------------------------------------------------------------


def _is_public_ipv4_cidr(value: Any) -> bool:
    """True for a literal ``0.0.0.0/0`` (unrestricted public IPv4) CIDR."""
    text = _plain_str(value)
    if not text or _is_interpolation(text):
        return False
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return network.version == 4 and network.prefixlen == 0


def _to_int(value: Any) -> int | None:
    """Best-effort literal integer for a port bound."""
    unwrapped = _first(value)
    if isinstance(unwrapped, bool):
        return None
    if isinstance(unwrapped, int):
        return unwrapped
    if isinstance(unwrapped, float) and unwrapped.is_integer():
        return int(unwrapped)
    if isinstance(unwrapped, str) and not _is_interpolation(unwrapped):
        try:
            return int(unwrapped.strip())
        except ValueError:
            return None
    return None


def _permits_ssh(from_port: Any, to_port: Any) -> bool:
    """True when the literal port range covers TCP 22 (inclusive)."""
    low = _to_int(from_port)
    high = _to_int(to_port)
    if low is None or high is None:
        return False
    if low > high:
        low, high = high, low
    return low <= SSH_PORT <= high


def _is_any_protocol(value: Any) -> bool:
    """True for ``-1``/``all``/``any`` protocol tokens."""
    text = _plain_str(value).strip().lower()
    return text in PROTOCOL_ALL_TOKENS


def _protocol_tokens(protocol: Any) -> tuple[list[str], bool]:
    """Return ``(literal protocol tokens, unknown)`` for a rule's protocol.

    ``unknown`` is True when any part of the value cannot be read literally,
    which makes the rule's TCP coverage undecidable.  AWS accepts a protocol
    name (``tcp``), its IANA number (``6``) or ``-1`` for all protocols.
    """
    if protocol is None:
        return [], False
    raw = _container(protocol)
    if isinstance(raw, dict):
        return [], True
    tokens: list[str] = []
    for item in _as_list(raw):
        if item is None or _is_interpolation(item):
            return [], True
        text = _plain_str(item).strip().lower()
        if text:
            tokens.append(text)
    return tokens, False


def _token_is_tcp(token: str) -> bool:
    """True for the TCP protocol name or its IANA protocol number."""
    return token in {"tcp", PROTOCOL_TCP_NUMBER}


def _token_is_known_protocol(token: str) -> bool:
    """True when a literal protocol token can be classified safely.

    A recognized non-TCP protocol (UDP/ICMP) cannot carry TCP 22 and is clean;
    an unrecognized value is unsupported, so its TCP coverage stays unknown.
    """
    return (
        token in PROTOCOL_ALL_TOKENS
        or _token_is_tcp(token)
        or token in PROTOCOL_UDP_TOKENS
        or token in PROTOCOL_ICMP_TOKENS
    )


def _permits_tcp22(from_port: Any, to_port: Any, protocol: Any) -> bool:
    """True when the literal rule permits TCP port 22.

    An all-protocol rule (``-1``/``all``/``any``) permits every protocol and
    port, so its port bounds are irrelevant.
    """
    tokens, unknown = _protocol_tokens(protocol)
    if unknown:
        return False
    if not tokens:
        # No protocol given: TCP 22 is permitted when the port range covers it.
        return _permits_ssh(from_port, to_port)
    if any(token in PROTOCOL_ALL_TOKENS for token in tokens):
        return True
    if not any(_token_is_tcp(token) for token in tokens):
        return False
    return _permits_ssh(from_port, to_port)


def _tcp22_verdict(from_port: Any, to_port: Any, protocol: Any) -> tuple[str, str]:
    """Classify one literal ingress rule against TCP 22.

    Returns ``("permits", "")``, ``("clean", "")`` or ``("unknown", reason)``
    so that an undecidable rule becomes a required coverage gap instead of a
    silent pass.
    """
    tokens, unknown = _protocol_tokens(protocol)
    if unknown:
        return "unknown", "protocol is not resolvable literally"
    if tokens and any(token in PROTOCOL_ALL_TOKENS for token in tokens):
        return "permits", ""
    if tokens:
        # A recognized non-TCP protocol (UDP/ICMP) is clean; an unrecognized
        # literal is unsupported, so TCP 22 exposure cannot be ruled out.
        unsupported = sorted({token for token in tokens if not _token_is_known_protocol(token)})
        if unsupported:
            return "unknown", (
                "protocol %s is not a recognized literal protocol"
                % ", ".join(repr(token) for token in unsupported)
            )
        if not any(_token_is_tcp(token) for token in tokens):
            return "clean", ""
    if from_port is None and to_port is None:
        return "unknown", "no port bounds are set on the rule"
    low = _to_int(from_port)
    high = _to_int(to_port)
    if low is None or high is None:
        return "unknown", "port bounds are not resolvable literally"
    return ("permits" if _permits_ssh(low, high) else "clean"), ""


def _ingress_candidates(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Inline ingress blocks of an ``aws_security_group``."""
    return _nested_blocks(body, "ingress")


def _dynamic_block_labels(body: dict[str, Any]) -> list[str]:
    """Labels of ``dynamic "label" { ... }`` blocks declared on a resource.

    The pinned parser emits a ``dynamic`` attribute holding a list of
    ``{label: body}`` dicts, so the label is read from that real structure
    rather than from any regex or textual scan.
    """
    labels: list[str] = []
    for entry in _as_list(body.get("dynamic")):
        entry = _first(entry)
        if not isinstance(entry, dict):
            continue
        for key in entry:
            if key in RESERVED_KEYS:
                continue
            labels.append(_plain_str(key))
    return labels


def _standalone_direction(body: dict[str, Any]) -> str | None:
    """Direction of an ``aws_security_group_rule``.

    Returns ``"ingress"``/``"egress"`` only for a recognized literal token;
    an unresolvable or unrecognized ``type`` returns ``None`` so the caller
    reports a required coverage gap instead of assuming egress/clean.
    """
    raw = body.get("type")
    if raw is None:
        return None
    text = _plain_str(_first(raw)).strip().lower()
    if _is_interpolation(text):
        return None
    if text in {"ingress", "egress"}:
        return text
    return None


def _standalone_rule(body: dict[str, Any]) -> dict[str, Any] | None:
    """Body of an ``aws_security_group_rule`` when it is a literal ingress rule."""
    if _standalone_direction(body) == "ingress":
        return body
    return None


def _net_findings_for_resource(
    block: Any,
    make_finding: Any,
    resource_type: str,
    body: dict[str, Any],
) -> tuple[list[Any], list[str]]:
    """Evaluate DG-AWS-NET-001 for one resource body."""
    findings: list[Any] = []
    gaps: list[str] = []

    # A candidate is ``(label, rule, direction_unknown)``.  ``direction_unknown``
    # marks a rule whose ingress/egress direction literal analysis cannot decide.
    candidates: list[tuple[str, dict[str, Any], bool]] = []
    if resource_type == "aws_security_group":
        candidates.extend(
            ("inline ingress", item, False) for item in _ingress_candidates(body)
        )
        # A ``dynamic "ingress"`` block is a real parser structure whose content
        # is generated by a ``for_each`` expression.  Literal analysis cannot
        # evaluate it, so it must surface as a required coverage gap rather than
        # being silently ignored.  ``dynamic "egress"`` stays out of scope: it
        # cannot create inbound exposure.
        for dynamic_label in _dynamic_block_labels(body):
            if dynamic_label.strip().lower() == "ingress":
                gaps.append(
                    f"{block.path}:{block.address}: dynamic ingress block is not "
                    "evaluated by literal parsing; public TCP 22 ingress may exist; "
                    "not evaluated"
                )
    elif resource_type == "aws_security_group_rule":
        standalone = _standalone_rule(body)
        if standalone is not None:
            candidates.append(("standalone rule", standalone, False))
        elif _standalone_direction(body) is None:
            candidates.append(("standalone rule", body, True))
    elif resource_type == "aws_vpc_security_group_ingress_rule":
        candidates.append(("vpc ingress rule", body, False))

    for label, rule, direction_unknown in candidates:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        protocol = rule.get("ip_protocol", rule.get("protocol"))
        cidr_keys = ("cidr_blocks", "cidr_ipv4", "ipv6_cidr_blocks", "cidr_ipv6")
        cidr_values: list[Any] = []
        for key in cidr_keys:
            # Unwrap only the parser's outer container: a list of CIDRs keeps
            # every entry, while a bare string (``cidr_ipv4``) stays a scalar.
            cidr_values.extend(_as_list(_container(rule.get(key))))

        # An unresolvable CIDR makes the rule's exposure undecidable, but a
        # literal public entry is still judged on its own evidence.
        unresolved_cidr = any(_is_interpolation(value) for value in cidr_values)
        if unresolved_cidr:
            gaps.append(
                f"{block.path}:{block.address}: {label} CIDR is not resolvable literally"
            )
        public = [value for value in cidr_values if _is_public_ipv4_cidr(value)]
        if direction_unknown:
            # The rule's direction is undecidable, so a public ingress rule
            # cannot be excluded; a private-only rule still cannot expose TCP 22.
            if public or unresolved_cidr:
                gaps.append(
                    f"{block.path}:{block.address}: {label} direction is not "
                    "resolvable literally (``type`` is not a literal ingress/egress); "
                    "public TCP 22 ingress cannot be excluded; not evaluated"
                )
            continue
        if not public:
            continue
        verdict, reason = _tcp22_verdict(from_port, to_port, protocol)
        if verdict == "unknown":
            gaps.append(
                f"{block.path}:{block.address}: {label} is open to public IPv4 "
                f"0.0.0.0/0 but TCP 22 exposure cannot be determined literally "
                f"({reason}); not evaluated"
            )
            continue
        if verdict == "clean":
            continue
        findings.append(
            _finding(
                make_finding,
                block=block,
                rule_id=RULE_NET,
                severity="high",
                category="security",
                template_id="open_ssh",
                policy_mode="block",
                evidence_strength="deterministic",
                summary=(
                    f"public IPv4 0.0.0.0/0 inbound {label} permits TCP 22 "
                    f"(protocol {_plain_str(_container(protocol)) or 'unspecified'})"
                ),
            )
        )
    return findings, gaps


# ---------------------------------------------------------------------------
# Tag rule helpers
# ---------------------------------------------------------------------------


def _tag_value(tags: dict[str, Any], key: str) -> tuple[bool, bool]:
    """Return ``(present, resolvable_literal_nonempty)`` for *key*."""
    if key not in tags:
        return False, False
    value = _first(tags[key])
    if _is_interpolation(value):
        return True, False
    text = value.strip() if isinstance(value, str) else value
    if isinstance(text, str) and text == "":
        return True, False
    if text in (None, ""):
        return True, False
    return True, True


def _merged_tags(
    body: dict[str, Any],
    provider_defaults: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Merge provider ``default_tags`` with resource ``tags``.

    Resource values win.  Returns the merged literal map plus the list of
    tags whose values could not be resolved literally.
    """
    merged = {key: value for key, value in provider_defaults.items()}
    unresolved: list[str] = []
    resource_tags = _unwrap(body.get("tags"))
    if isinstance(resource_tags, dict):
        for key, value in resource_tags.items():
            name = str(key)
            if _is_interpolation(value):
                unresolved.append(name)
                merged.pop(name, None)
                continue
            merged[name] = value
    return merged, unresolved


def _tag_findings_for_resource(
    block: Any,
    make_finding: Any,
    resource_type: str,
    body: dict[str, Any],
    config: Any,
    provider_defaults: dict[str, Any],
) -> tuple[list[Any], list[str]]:
    """Evaluate DG-AWS-TAG-001 for one supported taggable resource."""
    required = list(getattr(config, "required_tags", None) or ["owner", "environment"])
    merged, unresolved = _merged_tags(body, provider_defaults)
    gaps: list[str] = []
    for name in unresolved:
        gaps.append(
            f"{block.path}:{block.address}: tag '{name}' value is not resolvable literally"
        )

    # A tag whose value is unknown is never also reported as deterministically
    # absent: the unresolved value is the coverage gap above instead.
    determinable = [key for key in required if key not in unresolved]
    missing = [key for key in determinable if not _tag_value(merged, key)[0]]
    empty = [key for key in determinable if _tag_value(merged, key) == (True, False)]
    if not missing and not empty:
        return [], gaps

    findings = [
        _finding(
            make_finding,
            block=block,
            rule_id=RULE_TAG,
            severity="medium",
            category="governance",
            template_id="missing_tags",
            policy_mode="warn",
            evidence_strength="deterministic",
            summary=(
                f"{resource_type} missing or empty required tags "
                f"(missing={missing}, empty={empty})"
            ),
        )
    ]
    return findings, gaps


# ---------------------------------------------------------------------------
# RDS rule helpers
# ---------------------------------------------------------------------------


def _rds_findings_for_resource(
    block: Any,
    make_finding: Any,
    body: dict[str, Any],
) -> tuple[list[Any], list[str]]:
    """Evaluate DG-AWS-RDS-001 for one ``aws_db_instance``."""
    gaps: list[str] = []
    unresolved = set(getattr(block, "unresolved_attributes", None) or [])
    if "deletion_protection" in unresolved:
        gaps.append(
            f"{block.path}:{block.address}: deletion_protection value is not "
            "resolvable literally; conservatively not evaluated"
        )
        return [], gaps
    if "deletion_protection" not in body:
        gaps.append(
            f"{block.path}:{block.address}: deletion_protection not set; "
            "conservatively not evaluated"
        )
        return [], gaps

    raw = _unwrap(body.get("deletion_protection"))
    if _is_interpolation(raw):
        gaps.append(
            f"{block.path}:{block.address}: deletion_protection value is not "
            "resolvable literally; conservatively not evaluated"
        )
        return [], gaps

    value = raw.strip().lower() if isinstance(raw, str) else raw
    if value is True:
        return [], gaps
    if value is False:
        return (
            [
                _finding(
                    make_finding,
                    block=block,
                    rule_id=RULE_RDS,
                    severity="high",
                    category="reliability",
                    template_id="rds_deletion_protection",
                    policy_mode="block",
                    evidence_strength="deterministic",
                    summary="aws_db_instance has deletion_protection = false",
                )
            ],
            gaps,
        )
    # A non-boolean literal (e.g. "yes") cannot be judged safely.
    gaps.append(
        f"{block.path}:{block.address}: deletion_protection is not a boolean literal; "
        "conservatively not evaluated"
    )
    return [], gaps


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _finding_models() -> tuple[Any, Any, Any, Any]:
    """Import the finding value objects owned by the frozen foundation."""
    try:
        from valid.models import (  # type: ignore
            FindingSource,
            Location,
            Recommendation,
            ResourceRef,
        )
    except Exception as exc:  # pragma: no cover - foundation prerequisite
        raise CoverageGap(
            f"foundation models unavailable: cannot import valid.models ({exc})"
        ) from exc
    return FindingSource, Location, Recommendation, ResourceRef


def _finding(
    make_finding: Any,
    *,
    block: Any,
    rule_id: str,
    severity: str,
    category: str,
    template_id: str,
    policy_mode: str,
    evidence_strength: str,
    summary: str,
) -> Any:
    """Build one canonical Finding through the shared identity factory."""
    FindingSource, Location, Recommendation, ResourceRef = _finding_models()
    return make_finding(
        source=FindingSource(
            tool=TOOL,
            version=VERSION,
            rule_id=rule_id,
            scanner_severity=severity,
            severity_origin="custom_rule",
        ),
        location=Location(path=block.path, start_line=block.start_line, end_line=block.end_line),
        resource=ResourceRef(type=block.resource_type, address=block.address),
        category=category,
        priority=severity,
        evidence_strength=evidence_strength,
        evidence_summaries=[(LITERAL_HCL, summary)],
        recommendation=Recommendation(template_id=template_id),
        policy_mode=policy_mode,
    )


def _coverage_finding(make_finding: Any, *, path: str, reason: str) -> Any:
    """Build a required coverage-gap Finding (unknown/not_evaluated/warn)."""
    FindingSource, Location, Recommendation, _ = _finding_models()
    return make_finding(
        source=FindingSource(
            tool=TOOL,
            version=VERSION,
            rule_id=RULE_COVERAGE,
            scanner_severity="unknown",
            severity_origin="custom_rule",
        ),
        location=Location(path=path, start_line=None, end_line=None),
        resource=None,
        category="governance",
        priority="unknown",
        evidence_strength="not_evaluated",
        evidence_summaries=[(COVERAGE_GAP, reason)],
        recommendation=Recommendation(template_id="scanner_review"),
        policy_mode="warn",
    )


def _load_make_finding() -> Any:
    """Import the canonical identity factory from :mod:`valid.normalize`."""
    try:
        from valid.normalize import make_finding  # type: ignore
    except Exception as exc:
        raise CoverageGap(
            "foundation unavailable: cannot import valid.normalize.make_finding "
            f"({type(exc).__name__}: {exc}); canonical finding identities required"
        ) from exc
    return make_finding


# ---------------------------------------------------------------------------
# Public scan entry point
# ---------------------------------------------------------------------------

NETWORK_TYPES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    }
)


# ---------------------------------------------------------------------------
# Provider default_tags resolution
# ---------------------------------------------------------------------------


def _provider_registry(
    blocks_by_path: dict[str, list[Any]],
) -> dict[tuple[str, str], tuple[bool, str, Any]]:
    """Index literal provider ``default_tags`` by ``(provider_type, alias)``.

    Each value is ``(declared, state, tags)``.  ``declared`` distinguishes a
    provider configuration that exists (and simply omits ``default_tags``) from
    one that was never declared: an explicitly referenced alias that is not
    declared must become a required coverage gap, while an undeclared implicit
    default keeps the implied-empty semantics.  The default (unaliased)
    provider is keyed with an empty alias.  Two providers sharing a key with
    differing tags are marked ``ambiguous`` so the merge is never silently
    guessed.
    """
    registry: dict[tuple[str, str], tuple[bool, str, Any]] = {}
    for blocks in blocks_by_path.values():
        for block in blocks:
            if getattr(block, "block_type", None) != "provider":
                continue
            provider_type = getattr(block, "resource_type", "")
            address = getattr(block, "address", "") or ""
            alias = address.split(".")[-1] if address.count(".") >= 2 else ""
            attrs = getattr(block, "literal_attributes", {}) or {}
            unresolved = getattr(block, "unresolved_attributes", []) or []
            if "default_tags" in attrs:
                tags = attrs.get("default_tags")
                claim: tuple[str, Any] = (
                    ("literal", tags) if isinstance(tags, dict) else ("unresolved", None)
                )
            elif "default_tags" in unresolved:
                claim = ("unresolved", None)
            else:
                claim = ("absent", None)
            key = (provider_type, alias)
            existing = registry.get(key)
            if existing is None:
                registry[key] = (True, claim[0], claim[1])
            elif (existing[1], existing[2]) != claim:
                registry[key] = (True, "ambiguous", None)
    return registry


_PROVIDER_REFERENCE = re.compile(
    r"^\$\{\s*([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?\s*\}$"
)
_PROVIDER_REFERENCE_TEXT = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$")

# Reference heads that address a variable/local/module rather than a provider.
_NON_PROVIDER_HEADS = frozenset(
    {"var", "local", "module", "data", "each", "count", "terraform", "path", "self"}
)


def _provider_reference(value: Any) -> str | None:
    """Resolve a literal ``provider`` argument to ``name`` or ``name.alias``.

    ``provider = aws.west`` reaches this module as ``${aws.west}``; that is a
    literal traversal, not a variable, so it can be read directly.  Anything
    containing a variable or a computed expression returns ``None``.
    """
    if value is None:
        return None
    unwrapped = _container(value)
    if isinstance(unwrapped, (list, tuple, dict)):
        return None
    text = _plain_str(unwrapped).strip()
    if not text:
        return None
    match = _PROVIDER_REFERENCE.match(text)
    if match:
        name, alias = match.group(1), match.group(2)
        if name in _NON_PROVIDER_HEADS:
            return None
        return f"{name}.{alias}" if alias else name
    if INTERPOLATION_START in text:
        return None
    if not _PROVIDER_REFERENCE_TEXT.match(text):
        return None
    return None if text.split(".", 1)[0] in _NON_PROVIDER_HEADS else text


def _provider_local_name(resource_type: str) -> str | None:
    """Grounded provider local name for a resource without a ``provider`` argument.

    The supported scope is AWS: an ``aws_*`` resource type is served by the
    (implicit) ``aws`` provider configuration.  The mapping is derived from the
    resource type prefix only, never from arbitrary names declared elsewhere in
    the scan, so a stray ``provider "aws_db"`` can never be borrowed by an
    ``aws_db_instance``.  A type outside the supported scope returns ``None`` so
    the caller records a required coverage gap instead of guessing default_tags.
    """
    if resource_type.startswith(AWS_RESOURCE_PREFIX):
        return AWS_PROVIDER_NAME
    return None


def _applicable_provider_alias(
    block: Any, attrs: dict[str, Any], relative: str
) -> tuple[str | None, str | None, list[str]]:
    """Resolve the provider configuration a resource actually uses.

    Returns ``(provider_name, alias, gaps)``.  A resource without a literal
    ``provider`` argument uses the *default* (unaliased) configuration; when no
    default provider is declared that configuration is implied to be empty.
    ``(None, None, gaps)`` means the reference could not be resolved literally.
    """
    address = getattr(block, "address", "")
    if "provider" not in attrs:
        # A dynamic ``provider`` argument is recorded as unresolved by the
        # parser; it must not be silently treated as the default configuration.
        if _PROVIDER_ARG in (getattr(block, "unresolved_attributes", None) or []):
            return None, None, [
                f"{relative}:{address}: provider reference is not resolvable "
                "literally; applicable provider default_tags are unknown"
            ]
        return "", "", []
    reference = _provider_reference(attrs.get("provider"))
    if reference is None:
        return None, None, [
            f"{relative}:{address}: provider reference is not resolvable literally; "
            "applicable provider default_tags are unknown"
        ]
    name, _, alias = reference.partition(".")
    return name, alias, []


def _resolve_default_tags(
    registry: dict[tuple[str, str], tuple[bool, str, Any]],
    provider_name: str,
    alias: str,
    relative: str,
    address: str,
    gaps: list[str],
) -> tuple[dict[str, Any], bool]:
    """Literal ``default_tags`` for one provider configuration.

    Returns ``(tags, unknown)``.  ``unknown`` is True when the applicable
    configuration cannot be read literally, in which case the caller makes no
    deterministic tag claim for the resource.

    Two different absences are kept apart: an explicitly referenced alias that
    no provider configuration declares is an unresolved association (required
    gap), while an undeclared implicit default is a known, implied-empty
    configuration.
    """
    entry = registry.get((provider_name, alias))
    if entry is None:
        if alias:
            gaps.append(
                f"{relative}:{address}: provider alias '{provider_name}.{alias}' is "
                "not declared in this scan; applicable provider default_tags are unknown"
            )
            return {}, True
        return {}, False
    _, state, tags = entry
    if state == "ambiguous":
        gaps.append(
            f"{relative}:{address}: multiple providers match {provider_name} alias "
            f"'{alias or 'default'}' with differing default_tags; the merge is ambiguous"
        )
        return {}, True
    if state == "unresolved":
        gaps.append(
            f"{relative}:{address}: provider {provider_name} default_tags are not "
            "resolvable literally; DG-AWS-TAG-001 not_evaluated for this resource"
        )
        return {}, True
    if state == "literal" and isinstance(tags, dict):
        if any(_is_interpolation(value) for value in tags.values()):
            gaps.append(
                f"{relative}:{address}: provider {provider_name} default_tags contain "
                "non-literal values; DG-AWS-TAG-001 not_evaluated for this resource"
            )
            return {}, True
        return dict(tags), False
    return {}, False



def scan(parsed: Any, config: Any) -> Any:
    """Evaluate the three custom rules against a :class:`ParsedTerraform`.

    ``parsed`` maps source-relative path -> list[ResourceBlock].  Returns a
    :class:`CustomScanResult`; every unresolvable construct becomes a visible
    required coverage gap.
    """
    try:
        from valid.models import CustomScanResult  # type: ignore
    except Exception as exc:  # pragma: no cover - foundation prerequisite
        raise CoverageGap(
            f"foundation models unavailable: cannot import valid.models ({exc})"
        ) from exc

    make_finding = _load_make_finding()

    taggable = set(getattr(config, "taggable_resource_types", None) or [])
    if isinstance(parsed, dict):
        blocks_by_path: dict[str, list[Any]] = dict(parsed)
    else:
        blocks_by_path = dict(getattr(parsed, "parsed", None) or {})

    findings: list[Any] = []
    required_gaps: list[str] = []
    evaluated: list[str] = sorted(blocks_by_path)

    # Parse-time gaps (malformed HCL, unresolved modules, unreadable or unsafe
    # files) are recorded on the ParsedScan; carry them through so they stay
    # visible instead of being lost between the two stages.  Optional gaps are
    # carried separately: promoting them would change the risk precedence.
    parse_coverage = getattr(parsed, "coverage", None)
    optional_gaps: list[str] = []
    if parse_coverage is not None:
        required_gaps.extend(getattr(parse_coverage, "required_gaps", []) or [])
        optional_gaps.extend(getattr(parse_coverage, "optional_gaps", []) or [])
        evaluated = list(getattr(parse_coverage, "evaluated_files", None) or evaluated)

    registry = _provider_registry(blocks_by_path)

    for relative, blocks in blocks_by_path.items():
        for block in blocks:
            if getattr(block, "block_type", None) != "resource":
                continue
            resource_type = getattr(block, "resource_type", "")
            attrs = dict(getattr(block, "literal_attributes", {}) or {})
            address = getattr(block, "address", "")

            if resource_type in NETWORK_TYPES:
                rule_findings, rule_gaps = _net_findings_for_resource(
                    block, make_finding, resource_type, attrs
                )
                findings.extend(rule_findings)
                required_gaps.extend(rule_gaps)

            if resource_type in taggable:
                provider_name, alias, alias_gaps = _applicable_provider_alias(
                    block, attrs, relative
                )
                required_gaps.extend(alias_gaps)
                if alias is not None:
                    name = provider_name or _provider_local_name(resource_type)
                    if name is None:
                        required_gaps.append(
                            f"{relative}:{address}: resource type '{resource_type}' has "
                            "no supported implicit provider mapping; applicable provider "
                            "default_tags are unknown"
                        )
                    else:
                        provider_defaults, provider_unknown = _resolve_default_tags(
                            registry, name, alias, relative, address, required_gaps
                        )
                        if not provider_unknown:
                            rule_findings, rule_gaps = _tag_findings_for_resource(
                                block,
                                make_finding,
                                resource_type,
                                attrs,
                                config,
                                provider_defaults,
                            )
                            findings.extend(rule_findings)
                            required_gaps.extend(rule_gaps)

            if resource_type == "aws_db_instance":
                rule_findings, rule_gaps = _rds_findings_for_resource(
                    block, make_finding, attrs
                )
                findings.extend(rule_findings)
                required_gaps.extend(rule_gaps)

    # Required gaps surface as explicit coverage-gap findings too.
    for reason in _dedupe(required_gaps):
        path = reason.split(":", 1)[0]
        findings.append(_coverage_finding(make_finding, path=path, reason=reason))

    findings = _sorted_findings(findings)
    return CustomScanResult(
        findings=findings,
        coverage=_coverage(
            required_gaps=_dedupe(required_gaps),
            optional_gaps=_dedupe(optional_gaps),
            evaluated=evaluated,
        ),
    )


def _dedupe(values: Iterable[str]) -> list[str]:
    """Stable de-duplication preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _sorted_findings(findings: list[Any]) -> list[Any]:
    """Order findings by path, resource address, tool, rule, id."""

    def key(finding: Any) -> tuple[str, str, str, str, str]:
        resource = getattr(finding, "resource", None)
        address = getattr(resource, "address", None) or ""
        source = getattr(finding, "source", None)
        return (
            getattr(getattr(finding, "location", None), "path", "") or "",
            address,
            getattr(source, "tool", "") or "",
            getattr(source, "rule_id", "") or "",
            getattr(finding, "finding_id", "") or "",
        )

    return sorted(findings, key=key)
