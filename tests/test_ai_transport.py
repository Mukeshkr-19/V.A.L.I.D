"""Bounded transport regressions on the real, process-isolated default transport.

Every attempt runs in the production child process (valid._ai_transport).
For controlled responses the child is started through a test bootstrap that
runs the same child code but replaces its connection factory with a plain
loopback connection (or blocks the real resolver call). The parent-side
supervision — spawn, deadline, kill, reap — is the production code path.
No external network, no real credential: the key is a synthetic marker.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from valid import _ai_transport, explain, templates
from valid.models import FindingSource, Location, Recommendation, ResourceRef
from valid.normalize import make_finding

SYNTHETIC_KEY = "SYNTHETIC-NONCREDENTIAL-TRANSPORT-1"
BASE_ENV = {
    "VALID_AI_PROVIDER": "openai_compatible",
    "VALID_AI_BASE_URL": "https://ai.example.test/v1",
    "VALID_AI_MODEL": "test-model",
    "VALID_AI_API_KEY": SYNTHETIC_KEY,
}
NEBIUS_ENV = {
    "VALID_AI_PROVIDER": "nebius",
    "VALID_AI_BASE_URL": "https://api.tokenfactory.us-central1.nebius.com/v1/",
    "VALID_AI_MODEL": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
    "NEBIUS_API_KEY": SYNTHETIC_KEY,
}
SERVER_WAIT_SECONDS = 10.0
RESOLVER_BLOCK_SECONDS = 3.0
PACKAGE_PARENT = str(Path(_ai_transport.__file__).resolve().parent.parent)

# Runs the production child entry point after one test-only substitution:
#   loopback - connection factory returns a plain loopback HTTPConnection,
#   gate     - as loopback, but request() first waits for a resume file,
#   resolver - production HTTPS factory; the resolver call blocks first.
TEST_BOOTSTRAP = r'''
import sys, os, time, socket, http.client
sys.path.insert(0, sys.argv[1])
from valid import _ai_transport
port, record, mode = int(sys.argv[2]), sys.argv[3], sys.argv[4]
def note(text):
    with open(record, "a") as handle:
        handle.write(text + "\n")
note("pid %d" % os.getpid())
note("env " + ",".join(sorted(os.environ)))
if mode == "resolver":
    real_getaddrinfo = socket.getaddrinfo
    def blocked(host, *args, **kwargs):
        note("resolver-entered " + str(host))
        time.sleep(float(sys.argv[5]))
        note("resolved")
        return real_getaddrinfo("127.0.0.1", port, socket.AF_INET, socket.SOCK_STREAM)
    socket.getaddrinfo = blocked
else:
    class Loopback(http.client.HTTPConnection):
        def request(self, *args, **kwargs):
            if mode == "gate":
                note("entered")
                resume = record + ".resume"
                for _ in range(1000):
                    if os.path.exists(resume):
                        break
                    time.sleep(0.01)
                note("resumed")
            return super().request(*args, **kwargs)
    def connect(host, requested_port, timeout):
        note("connect %s:%d" % (host, requested_port))
        return Loopback("127.0.0.1", port, timeout=timeout)
    _ai_transport._connect = connect
raise SystemExit(_ai_transport.child_main())
'''


def _finding(index: int = 0):
    return make_finding(
        source=FindingSource(
            tool="valid", version="0.1.0", rule_id="DG-AWS-NET-001",
            scanner_severity="high", severity_origin="custom_rule",
        ),
        location=Location(path="file-%d.tf" % index, start_line=1, end_line=2),
        resource=ResourceRef(type="aws_security_group", address="aws_security_group.open"),
        category="security", priority="high", evidence_strength="deterministic",
        evidence_summaries=[("literal_hcl", "public ingress to port 22 (%d)" % index)],
        recommendation=Recommendation(template_id="open_ssh"),
        policy_mode="block",
    )


def _dumped(result):
    return [item.model_dump(mode="json") for item in result]


def _valid_envelope(findings) -> bytes:
    items = []
    for finding in findings:
        template = templates.explain([finding])[0]
        items.append({
            "finding_id": finding.finding_id,
            "evidence_ids": sorted(item.evidence_id for item in finding.evidence),
            "title": template.title,
            "why_it_matters": template.why_it_matters,
            "recommended_action": template.recommended_action,
            "evidence_strength": finding.evidence_strength,
        })
    return json.dumps({"choices": [{"message": {"content": json.dumps(items)}}]}).encode("utf-8")


def _attempt_workers():
    return [thread for thread in threading.enumerate() if thread.name == "valid-ai-attempt" and thread.is_alive()]


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_request(conn: socket.socket) -> dict:
    data = b""
    received = 0
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        received += len(chunk)
        data += chunk
        if not data.startswith(b"POST"[: len(data)]):
            break
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        length = 0
    while data.startswith(b"POST") and len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        received += len(chunk)
        body += chunk
    raw = head + body
    return {
        "request_line": lines[0],
        "bytes": received,
        "authorization_is_synthetic_bearer": headers.get("authorization") == "Bearer " + SYNTHETIC_KEY,
        "key_anywhere": SYNTHETIC_KEY.encode("utf-8") in raw,
        "key_in_body": SYNTHETIC_KEY.encode("utf-8") in body,
    }


class LoopbackServer:
    """Loopback HTTP server driven by a response script; records every connection."""

    def __init__(self, script):
        self.script = list(script)
        self.connections: list[dict] = []
        self.release = threading.Event()
        self.handlers: list[threading.Thread] = []
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, name="loopback-server", daemon=True)
        self.thread.start()

    @property
    def requests(self) -> list[dict]:
        return [item for item in self.connections if item["request_line"].startswith("POST ")]

    def _serve(self) -> None:
        while not self.release.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(SERVER_WAIT_SECONDS)
            handler = self.script[min(len(self.connections), len(self.script) - 1)]
            record: dict = {"request_line": "", "bytes": 0}
            self.connections.append(record)
            worker = threading.Thread(target=self._handle, args=(handler, conn, record), daemon=True)
            self.handlers.append(worker)
            worker.start()

    def _handle(self, handler, conn: socket.socket, record: dict) -> None:
        try:
            record.update(_read_request(conn))
            if record["request_line"].startswith("POST "):
                handler(self, conn)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.release.set()
        self.sock.close()
        self.thread.join(SERVER_WAIT_SECONDS)
        for worker in self.handlers:
            worker.join(SERVER_WAIT_SECONDS)
        assert not self.thread.is_alive()
        assert not [worker for worker in self.handlers if worker.is_alive()]


def respond(status: int, body: bytes = b"", headers: dict | None = None):
    def handler(server: LoopbackServer, conn: socket.socket) -> None:
        lines = ["HTTP/1.1 %d Status" % status, "Content-Length: %d" % len(body), "Connection: close"]
        lines += ["%s: %s" % item for item in (headers or {}).items()]
        conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
    return handler


def hang(server: LoopbackServer, conn: socket.socket) -> None:
    server.release.wait(SERVER_WAIT_SECONDS)


def drip(server: LoopbackServer, conn: socket.socket) -> None:
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n")
    while not server.release.is_set():
        conn.sendall(b" ")
        time.sleep(0.05)


class Harness:
    def __init__(self, server: LoopbackServer, record: Path):
        self.server = server
        self.record = record

    def notes(self) -> list[str]:
        return self.record.read_text().splitlines() if self.record.exists() else []

    def pids(self) -> list[int]:
        return [int(line.split()[1]) for line in self.notes() if line.startswith("pid ")]

    def connects(self) -> list[str]:
        return [line.split(" ", 1)[1] for line in self.notes() if line.startswith("connect ")]


@pytest.fixture
def loopback(monkeypatch, tmp_path):
    harnesses: list[Harness] = []
    threads_before = set(threading.enumerate())

    def start(*script, mode: str = "loopback") -> Harness:
        server = LoopbackServer(script)
        record = tmp_path / ("child-%d.log" % len(harnesses))
        harness = Harness(server, record)
        harnesses.append(harness)

        def argv() -> list[str]:
            return [sys.executable, "-I", "-B", "-c", TEST_BOOTSTRAP, PACKAGE_PARENT,
                    str(server.port), str(record), mode, str(RESOLVER_BLOCK_SECONDS)]

        monkeypatch.setattr(_ai_transport, "worker_argv", argv)
        return harness

    yield start
    for harness in harnesses:
        harness.server.close()
        for pid in harness.pids():
            assert not _process_exists(pid), "child %d survived" % pid
        assert SYNTHETIC_KEY not in "\n".join(harness.notes())
        for line in harness.notes():
            if line.startswith("env "):
                assert set(filter(None, line[4:].split(","))) <= {"PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    assert _attempt_workers() == []
    assert [thread for thread in threading.enumerate() if thread not in threads_before and thread.is_alive()] == []


# --------------------------------------------------------------------------- AI-01 redirects


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", [
    "https://different-host.example.test/redirect",
    "http://ai.example.test/v1/chat/completions",
])
def test_redirects_are_never_followed(loopback, status, location):
    harness = loopback(respond(status, b"", {"Location": location}), respond(200, b"{}"))
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.connections) == 1
    assert harness.connects() == ["ai.example.test:443"]
    request = harness.server.requests[0]
    assert request["request_line"] == "POST /v1/chat/completions HTTP/1.1"
    assert request["authorization_is_synthetic_bearer"]
    assert not request["key_in_body"]


def test_default_transport_returns_redirect_status_after_one_request(loopback):
    harness = loopback(respond(302, b"", {"Location": "https://different-host.example.test/"}), respond(200, b"{}"))
    status, raw = explain._default_transport(
        "https://ai.example.test/v1/chat/completions",
        {"Authorization": "Bearer " + SYNTHETIC_KEY}, b"{}", 5.0,
    )
    assert (status, raw) == (302, b"")
    assert len(harness.server.connections) == 1 and harness.connects() == ["ai.example.test:443"]


def test_default_transport_refuses_non_https_without_spawning(loopback):
    harness = loopback(respond(200, b"{}"))
    with pytest.raises(explain.TransportError):
        explain._default_transport("http://ai.example.test/v1/chat/completions", {}, b"{}", 2.0)
    assert harness.notes() == [] and harness.server.connections == []


def test_valid_response_over_the_real_transport_is_accepted(loopback):
    findings = [_finding()]
    harness = loopback(respond(200, _valid_envelope(findings)))
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.requests) == 1 and len(harness.pids()) == 1


def test_nebius_configuration_reaches_only_the_documented_endpoint(loopback):
    findings = [_finding()]
    harness = loopback(respond(200, _valid_envelope(findings)))
    assert _dumped(explain.explain(findings, env=NEBIUS_ENV)) == _dumped(templates.explain(findings))
    assert harness.connects() == ["api.tokenfactory.us-central1.nebius.com:443"]
    assert harness.server.requests[0]["request_line"] == "POST /v1/chat/completions HTTP/1.1"


def test_transient_status_retries_once_over_the_real_transport(loopback):
    findings = [_finding()]
    harness = loopback(respond(503, b"{}"), respond(200, _valid_envelope(findings)))
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.requests) == 2 and len(harness.pids()) == 2


def test_persistent_transient_status_stops_after_one_retry(loopback):
    harness = loopback(respond(503, b"{}"))
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.requests) == 2 and len(harness.pids()) == 2


def test_oversized_response_is_rejected_while_reading(loopback):
    harness = loopback(respond(200, b"x" * (explain.MAX_RESPONSE_BYTES + 4096)))
    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.requests) == 1


def test_production_child_verifies_tls_and_ignores_working_directory_and_pythonpath(monkeypatch):
    server = LoopbackServer([respond(200, b"{}")])
    try:
        monkeypatch.chdir("/")
        monkeypatch.setenv("PYTHONPATH", "/nonexistent")
        env = {**BASE_ENV, "VALID_AI_BASE_URL": "https://127.0.0.1:%d/v1" % server.port}
        findings = [_finding()]
        assert _dumped(explain.explain(findings, env=env)) == _dumped(templates.explain(findings))
        assert len(server.connections) == 2
        assert server.requests == []
        assert not any(item.get("key_anywhere") for item in server.connections)
    finally:
        server.close()
    assert _attempt_workers() == []


def test_production_child_receives_no_key_in_arguments_or_environment(monkeypatch):
    monkeypatch.setenv("VALID_AI_API_KEY", SYNTHETIC_KEY)
    argv = _ai_transport.worker_argv()
    assert argv[:4] == [sys.executable, "-I", "-B", "-c"] and SYNTHETIC_KEY not in " ".join(argv)
    env = _ai_transport._child_env()
    assert set(env) <= {"PATH", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    assert SYNTHETIC_KEY not in json.dumps(env)


# --------------------------------------------------------------------------- AI-02 cancellation


@pytest.mark.parametrize("handler", [hang, drip], ids=["non-returning", "slow-drip"])
def test_wall_deadline_stops_slow_io_without_retry(loopback, monkeypatch, handler):
    monkeypatch.setattr(explain, "SHARED_BUDGET_SECONDS", 0.8)
    monkeypatch.setattr(explain, "PER_ATTEMPT_TIMEOUT_SECONDS", 30.0)
    harness = loopback(handler, respond(200, b"{}"))
    findings = [_finding()]
    started = time.monotonic()
    result = explain.explain(findings, env=BASE_ENV)
    elapsed = time.monotonic() - started
    assert _dumped(result) == _dumped(templates.explain(findings))
    assert elapsed < 0.8 + explain.CANCEL_JOIN_SECONDS
    assert len(harness.server.connections) == 1 and len(harness.pids()) == 1
    assert not _process_exists(harness.pids()[0])


def test_cancelled_handoff_never_reconnects_or_sends(loopback, monkeypatch):
    monkeypatch.setattr(explain, "SHARED_BUDGET_SECONDS", 0.8)
    harness = loopback(respond(200, b"{}"), mode="gate")
    findings = [_finding()]
    result = explain.explain(findings, env=BASE_ENV)
    assert _dumped(result) == _dumped(templates.explain(findings))
    assert "entered" in harness.notes()
    (pid,) = harness.pids()
    assert not _process_exists(pid)
    Path(str(harness.record) + ".resume").write_text("resume")
    time.sleep(1.0)
    assert "resumed" not in harness.notes()
    assert harness.connects() == ["ai.example.test:443"]
    assert len(harness.server.connections) == 1
    assert harness.server.connections[0]["bytes"] == 0
    assert harness.server.requests == []


def test_blocked_resolver_is_stopped_before_fallback(loopback, monkeypatch):
    monkeypatch.setattr(explain, "SHARED_BUDGET_SECONDS", 0.8)
    harness = loopback(respond(200, b"{}"), mode="resolver")
    findings = [_finding()]
    started = time.monotonic()
    result = explain.explain(findings, env=BASE_ENV)
    elapsed = time.monotonic() - started
    assert _dumped(result) == _dumped(templates.explain(findings))
    assert elapsed < 0.8 + explain.CANCEL_JOIN_SECONDS
    assert "resolver-entered ai.example.test" in harness.notes()
    (pid,) = harness.pids()
    assert not _process_exists(pid)
    time.sleep(RESOLVER_BLOCK_SECONDS + 0.5)
    assert "resolved" not in harness.notes()
    assert harness.server.connections == []


def test_closed_connection_is_never_reopened(monkeypatch):
    connects, sent = [], []

    class FakeSocket:
        def sendall(self, data):
            sent.append(bytes(data))

        def close(self):
            pass

    class ClosingConnection(http.client.HTTPConnection):
        def connect(self):
            connects.append(1)
            self.sock = FakeSocket()

        def request(self, *args, **kwargs):
            self.sock = None
            return super().request(*args, **kwargs)

    monkeypatch.setattr(_ai_transport, "_connect", lambda host, port, timeout: ClosingConnection(host, port))
    with pytest.raises(_ai_transport.TransportFailure):
        _ai_transport.perform(
            "https://ai.example.test/v1/chat/completions",
            {"Authorization": "Bearer " + SYNTHETIC_KEY}, b"{}", 1.0, explain.MAX_RESPONSE_BYTES,
        )
    assert connects == [1] and sent == []


def test_non_returning_transport_double_is_abandoned_without_retry(monkeypatch):
    monkeypatch.setattr(explain, "SHARED_BUDGET_SECONDS", 0.3)
    release = threading.Event()
    calls = []
    findings = [_finding()]

    def blocking(url, headers, body, timeout):
        calls.append(timeout)
        release.wait(SERVER_WAIT_SECONDS)
        return 200, _valid_envelope(findings)

    started = time.monotonic()
    result = explain.explain(findings, env=BASE_ENV, transport=blocking)
    elapsed = time.monotonic() - started
    try:
        assert _dumped(result) == _dumped(templates.explain(findings))
        assert len(calls) == 1 and 0 < calls[0] <= 0.3
        assert elapsed < 0.3 + explain.CANCEL_JOIN_SECONDS + 0.5
    finally:
        release.set()
        for worker in _attempt_workers():
            worker.join(SERVER_WAIT_SECONDS)
    assert _attempt_workers() == []


def test_response_completing_after_the_deadline_is_never_accepted(monkeypatch):
    real_monotonic = time.monotonic
    offset = [0.0]
    monkeypatch.setattr(explain.time, "monotonic", lambda: real_monotonic() + offset[0])
    findings = [_finding()]
    calls = []

    def late(url, headers, body, timeout):
        calls.append(timeout)
        offset[0] = explain.SHARED_BUDGET_SECONDS + 10.0
        return 200, _valid_envelope(findings)

    result = explain.explain(findings, env=BASE_ENV, transport=late)
    assert _dumped(result) == _dumped(templates.explain(findings))
    assert len(calls) == 1


def test_budget_exhausted_by_first_attempt_prevents_retry(monkeypatch):
    real_monotonic = time.monotonic
    offset = [0.0]
    monkeypatch.setattr(explain.time, "monotonic", lambda: real_monotonic() + offset[0])
    calls = []

    def slow_failure(url, headers, body, timeout):
        calls.append(timeout)
        offset[0] = explain.SHARED_BUDGET_SECONDS + 1.0
        raise explain.TransportError("simulated timeout")

    findings = [_finding()]
    assert _dumped(explain.explain(findings, env=BASE_ENV, transport=slow_failure)) == _dumped(templates.explain(findings))
    assert len(calls) == 1


def test_supervised_late_completion_is_rejected_and_not_retried(loopback, monkeypatch):
    findings = [_finding()]
    harness = loopback(respond(200, _valid_envelope(findings)))
    real_post = _ai_transport.supervised_post
    real_monotonic = time.monotonic
    offset = [0.0]

    def jumping(*args, **kwargs):
        result = real_post(*args, **kwargs)
        offset[0] = explain.SHARED_BUDGET_SECONDS + 5.0
        return result

    monkeypatch.setattr(_ai_transport, "supervised_post", jumping)
    monkeypatch.setattr(explain.time, "monotonic", lambda: real_monotonic() + offset[0])
    assert _dumped(explain.explain(findings, env=BASE_ENV)) == _dumped(templates.explain(findings))
    assert len(harness.server.requests) == 1 and len(harness.pids()) == 1
