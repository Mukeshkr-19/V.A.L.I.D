"""Process-isolated HTTPS transport for advisory AI requests (stdlib only).

Each attempt runs in a short-lived child interpreter. Name resolution,
connect, TLS handshake, send, and response reads all happen inside that
child, so the deadline owner can stop every one of them — including a
blocked resolver call, which no thread can interrupt — by killing the
child's process group and reaping it before it returns.

The request (including the Authorization header) reaches the child only over
its stdin pipe; it never appears in process arguments, the child environment,
files, or logs. The child's environment is reduced to TLS trust settings, and
its stderr is discarded.

Inside the child the exchange is a single POST: the connection is opened
explicitly and automatic reopening is then disabled, so a closed socket can
never trigger a second connection, and redirects are never followed.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

READ_CHUNK_BYTES = 8192
MAX_CHILD_INPUT_BYTES = 1024 * 1024
_PASSTHROUGH_ENV = ("SSL_CERT_FILE", "SSL_CERT_DIR")
_BOOTSTRAP = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from valid import _ai_transport\n"
    "raise SystemExit(_ai_transport.child_main())\n"
)


class TransportFailure(Exception):
    """The exchange failed; the caller may retry within its budget."""


class ResponseTooLarge(Exception):
    """The response body exceeded the byte limit."""


class DeadlineExpired(Exception):
    """The supervised child was stopped at the deadline."""


# --------------------------------------------------------------------------- child side


def _connect(host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    """Open an HTTPS connection with certificate and host-name verification."""
    return http.client.HTTPSConnection(
        host, port, timeout=timeout, context=ssl.create_default_context()
    )


def perform(
    url: str, headers: dict[str, str], body: bytes, timeout: float, max_response: int
) -> tuple[int, bytes]:
    """POST once and return (status, body). Never redirects, never reconnects."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise TransportFailure("endpoint is not HTTPS")
    connection = _connect(parts.hostname, parts.port or 443, timeout)
    try:
        connection.connect()
        connection.auto_open = 0
        connection.request("POST", parts.path or "/", body=body, headers=headers)
        response = connection.getresponse()
        status = int(response.status)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_response:
                raise ResponseTooLarge("response exceeds the byte limit")
            chunks.append(chunk)
        return status, b"".join(chunks)
    except (ResponseTooLarge, TransportFailure):
        raise
    except Exception as error:
        raise TransportFailure(type(error).__name__) from error
    finally:
        connection.close()


def child_main() -> int:
    """Read one request from stdin, perform it, write one JSON result to stdout."""
    try:
        request = json.loads(sys.stdin.buffer.read(MAX_CHILD_INPUT_BYTES + 1))
        status, raw = perform(
            request["url"],
            request["headers"],
            base64.b64decode(request["body"]),
            float(request["timeout"]),
            int(request["max_response"]),
        )
        outcome: dict[str, Any] = {
            "ok": True,
            "status": status,
            "body": base64.b64encode(raw).decode("ascii"),
        }
    except ResponseTooLarge:
        outcome = {"ok": False, "error": "oversized"}
    except Exception:
        outcome = {"ok": False, "error": "transport"}
    sys.stdout.write(json.dumps(outcome))
    sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------- parent side


def worker_argv() -> list[str]:
    """Command for one isolated child, independent of the working directory."""
    package_parent = str(Path(__file__).resolve().parent.parent)
    return [sys.executable, "-I", "-B", "-c", _BOOTSTRAP, package_parent]


def _child_env() -> dict[str, str]:
    env = {"PATH": os.defpath}
    for name in _PASSTHROUGH_ENV:
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _stop(process: subprocess.Popen, reap_seconds: float) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.communicate(timeout=reap_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def supervised_post(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
    deadline: float,
    max_response: int,
    reap_seconds: float,
) -> tuple[int, bytes]:
    """Run one exchange in a child; kill and reap it if ``deadline`` passes.

    Returns only after the child has exited and been reaped.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DeadlineExpired("deadline already passed")
    message = json.dumps(
        {
            "url": url,
            "headers": headers,
            "body": base64.b64encode(body).decode("ascii"),
            "timeout": min(timeout, remaining),
            "max_response": max_response,
        }
    ).encode("utf-8")
    if len(message) > MAX_CHILD_INPUT_BYTES:
        raise TransportFailure("request exceeds the child input limit")
    process = subprocess.Popen(
        worker_argv(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_child_env(),
        cwd="/" if os.name == "posix" else None,
        start_new_session=True,
        close_fds=True,
    )
    try:
        output, _ = process.communicate(message, timeout=max(deadline - time.monotonic(), 0.001))
    except subprocess.TimeoutExpired:
        _stop(process, reap_seconds)
        raise DeadlineExpired("child stopped at the deadline") from None
    except BaseException:
        _stop(process, reap_seconds)
        raise
    if time.monotonic() > deadline:
        raise DeadlineExpired("child finished after the deadline")
    try:
        outcome = json.loads(output.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise TransportFailure("child produced no usable result") from None
    if not isinstance(outcome, dict) or outcome.get("ok") is not True:
        if isinstance(outcome, dict) and outcome.get("error") == "oversized":
            raise ResponseTooLarge("response exceeds the byte limit")
        raise TransportFailure("child exchange failed")
    try:
        status = int(outcome["status"])
        raw = base64.b64decode(outcome["body"], validate=True)
    except (KeyError, TypeError, ValueError):
        raise TransportFailure("child produced a malformed result") from None
    if len(raw) > max_response:
        raise ResponseTooLarge("response exceeds the byte limit")
    return status, raw
