"""Printer certificate verification (services/printer_tls.py).

The certificates are generated per session in the shape of Bambu's real chain:
a CA without a keyUsage extension, and a leaf with ``CN=<serial>``, no
subjectAltName and no extensions. (The real leaf is X.509 v1, which
``cryptography`` cannot write; what makes strict verification refuse the real
chain is the CA's missing keyUsage, and that is reproduced.) ``impostor.pem`` is
a self-signed leaf with the same CN, ``wrong_ca.pem`` the same leaf signed by
another CA of the same name, and ``expired.pem`` a leaf from the right CA that
expired in 2021. All share ``leaf.key``. Nothing is committed, so no private
key sits in the repository.

The local servers record every byte a client sends after the handshake, so a
test can show that a refused printer never received the access code, and the
accepted cases are the control that the recording works.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import socket
import ssl
import threading
from pathlib import Path

import paho.mqtt.client as mqtt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from backend.app.services import print_scheduler, printer_diagnostic, printer_tls
from backend.app.services.bambu_ftp import BambuFTPClient, FtpFailureKind, ImplicitFTP_TLS
from backend.app.services.bambu_mqtt import BambuMQTTClient
from backend.app.services.camera import close_tls_proxy, create_tls_proxy

FIXTURES = Path()  # set by the session fixture _pki
SERIAL = "01P00TEST000001"
ACCESS_CODE = "12345678"

SHIPPED_BUNDLE = printer_tls.CA_BUNDLE

# BBL CA, the root a P1S presents on 8883, 990 and 6000.
BBL_CA_SHA256 = "030bca81cece18b7eff3cfd2b75d09d3efca893bc069609e37fa04257fe4d840"


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "CN")] if org else []
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def _cert(subject, key, issuer, issuer_key, *, ca=False, not_before=None, not_after=None) -> bytes:
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - datetime.timedelta(days=1))
        .not_valid_after(not_after or now + datetime.timedelta(days=3650))
    )
    if ca:
        # Like BBL CA: basicConstraints but no keyUsage.
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session", autouse=True)
def _pki(tmp_path_factory):
    global FIXTURES
    FIXTURES = tmp_path_factory.mktemp("printer_tls")
    ca_name = _name("Test Printer CA", "Test Printer Maker")
    ca_key, other_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    leaf = _name(SERIAL)
    files = {
        "ca.pem": _cert(ca_name, ca_key, ca_name, ca_key, ca=True),
        "leaf.pem": _cert(leaf, leaf_key, ca_name, ca_key),
        "expired.pem": _cert(
            leaf,
            leaf_key,
            ca_name,
            ca_key,
            not_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
            not_after=datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC),
        ),
        "impostor.pem": _cert(leaf, leaf_key, leaf, leaf_key),
        "wrong_ca.pem": _cert(leaf, leaf_key, ca_name, other_key),
        "leaf.key": leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    }
    for name, data in files.items():
        (FIXTURES / name).write_bytes(data)


class RecordingTLSServer:
    """A TLS server on 127.0.0.1 that records what clients send after the handshake.

    ``mode="ftp"`` answers like an FTP server (220 banner, then 331/230) so an
    ftplib login completes; otherwise it only reads.
    """

    def __init__(self, certfile: Path, mode: str = "raw"):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(certfile), str(FIXTURES / "leaf.key"))
        self.mode = mode
        self.received = b""
        self.handshakes = 0
        self._lock = threading.Lock()
        self._sock = socket.create_server(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        raw.settimeout(5)
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        with self._lock:
            self.handshakes += 1
        replies = [b"331 password please\r\n", b"230 logged in\r\n"]
        try:
            if self.mode == "ftp":
                conn.sendall(b"220 ready\r\n")
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                with self._lock:
                    self.received += data
                if self.mode == "ftp" and data.endswith(b"\r\n"):
                    conn.sendall(replies.pop(0) if replies else b"221 bye\r\n")
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Trust the test CA instead of Bambu's, with an empty serial registry."""
    monkeypatch.setattr(printer_tls, "CA_BUNDLE", FIXTURES / "ca.pem")
    monkeypatch.setattr(printer_tls, "_serial_by_host", {})
    monkeypatch.setattr(printer_tls, "_last_logged", {})
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "serial")
    monkeypatch.setattr(printer_tls.settings, "printer_tls_extra_ca_file", None)


@pytest.fixture
def server_factory():
    servers: list[RecordingTLSServer] = []

    def make(cert: str, mode: str = "raw") -> RecordingTLSServer:
        server = RecordingTLSServer(FIXTURES / cert, mode)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def _wait_for(server: RecordingTLSServer, needle: bytes, timeout: float = 5.0) -> bool:
    deadline = threading.Event()
    for _ in range(int(timeout / 0.05)):
        if needle in server.received:
            return True
        deadline.wait(0.05)
    return False


def _settle() -> None:
    # Gives the server thread time to record anything the client might have sent.
    threading.Event().wait(0.3)


def _mqtt_connect(port: int) -> mqtt.Client:
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id="t")
    client.username_pw_set("bblp", ACCESS_CODE)
    client.tls_set_context(printer_tls.printer_ssl_context())
    client.connect("127.0.0.1", port)
    return client


# --- The shipped bundle -----------------------------------------------------


def test_shipped_bundle_holds_bambu_cas(monkeypatch):
    monkeypatch.setattr(printer_tls, "CA_BUNDLE", SHIPPED_BUNDLE)
    ctx = printer_tls.printer_ssl_context()
    fingerprints = {hashlib.sha256(der).hexdigest() for der in ctx.get_ca_certs(binary_form=True)}
    assert BBL_CA_SHA256 in fingerprints
    assert len(fingerprints) == 8


def test_verifying_context_trusts_only_the_bundle():
    ctx = printer_tls.printer_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert not ctx.verify_flags & ssl.VERIFY_X509_STRICT
    assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    # The test CA only: no system roots, so a public-CA certificate is refused.
    assert len(ctx.get_ca_certs()) == 1


def test_off_mode_is_the_old_unverified_context(monkeypatch):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "off")
    ctx = printer_tls.printer_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert type(ctx) is ssl.SSLContext


# --- MQTT (paho, blocking socket) -------------------------------------------


@pytest.mark.parametrize("cert", ["leaf.pem", "leaf_and_ca.pem"])
def test_mqtt_real_shaped_chain_is_accepted(server_factory, cert, tmp_path):
    if cert == "leaf_and_ca.pem":
        # A P1S sends its leaf and BBL CA; newer models only the leaf.
        (tmp_path / cert).write_bytes((FIXTURES / "leaf.pem").read_bytes() + (FIXTURES / "ca.pem").read_bytes())
        server = RecordingTLSServer(tmp_path / cert)
    else:
        server = server_factory(cert)
    try:
        printer_tls.register_printer("127.0.0.1", SERIAL.lower())
        client = _mqtt_connect(server.port)
        client.disconnect()
        assert _wait_for(server, ACCESS_CODE.encode()), "control: the CONNECT packet should carry the code"
    finally:
        server.close()


def test_strict_x509_would_refuse_the_real_shaped_chain(server_factory):
    # Why VERIFY_X509_STRICT is cleared: the same chain fails with it set.
    server = server_factory("leaf.pem")
    ctx = printer_tls.printer_ssl_context()
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    with (
        socket.create_connection(("127.0.0.1", server.port)) as raw,
        pytest.raises(printer_tls.PrinterCertificateError),
    ):
        ctx.wrap_socket(raw, server_hostname="127.0.0.1")


@pytest.mark.parametrize(
    ("cert", "reason"),
    [
        ("impostor.pem", "self-signed"),
        ("wrong_ca.pem", "certificate signature failure"),
        ("expired.pem", "expired"),
    ],
)
def test_mqtt_untrusted_printer_never_gets_the_code(server_factory, cert, reason, caplog):
    server = server_factory(cert)
    with pytest.raises(printer_tls.PrinterCertificateError) as exc_info:
        _mqtt_connect(server.port)
    _settle()
    assert server.received == b""
    message = str(exc_info.value)
    assert message.startswith("TLS verification of printer 127.0.0.1 failed")
    assert reason in message
    assert "PRINTER_TLS_VERIFY" in message
    assert message in caplog.text


def test_mqtt_serial_mismatch_never_gets_the_code(server_factory):
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", "01P00OTHER00002")
    with pytest.raises(printer_tls.PrinterCertificateError, match="serial 01P00TEST000001.*01P00OTHER00002"):
        _mqtt_connect(server.port)
    _settle()
    assert server.handshakes == 1  # the chain was fine; the CN check refused it
    assert server.received == b""


def test_a_contexts_own_serial_wins_over_the_registry(server_factory):
    # How BambuMQTTClient checks: test_connection() probes a serial typed into
    # Add Printer, which must be checked but must not replace the saved one.
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", SERIAL)
    ctx = printer_tls.printer_ssl_context(expected_serial="01P00TYPO000003")
    with (
        socket.create_connection(("127.0.0.1", server.port)) as raw,
        pytest.raises(printer_tls.PrinterCertificateError, match="01P00TYPO000003"),
    ):
        ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    assert printer_tls.expected_serial("127.0.0.1") == SERIAL


def test_an_mqtt_probe_with_a_mistyped_serial_leaves_the_registry_alone(server_factory):
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", SERIAL)
    client = BambuMQTTClient(ip_address="127.0.0.1", serial_number="01P00TYPO000003", access_code=ACCESS_CODE)
    client.MQTT_PORT = server.port
    client.connect()
    try:
        _settle()
        assert server.handshakes == 1
        assert server.received == b""
    finally:
        client.disconnect()
    assert printer_tls.expected_serial("127.0.0.1") == SERIAL


def test_ca_mode_skips_the_serial_check(server_factory, monkeypatch):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "ca")
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", "01P00OTHER00002")
    _mqtt_connect(server.port).disconnect()
    assert _wait_for(server, ACCESS_CODE.encode())


def test_off_mode_still_connects_to_an_impostor(server_factory, monkeypatch):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "off")
    server = server_factory("impostor.pem")
    _mqtt_connect(server.port).disconnect()
    assert _wait_for(server, ACCESS_CODE.encode())


def test_failure_is_logged_once_per_window(server_factory, caplog):
    server = server_factory("impostor.pem")
    for _ in range(3):
        with pytest.raises(printer_tls.PrinterCertificateError):
            _mqtt_connect(server.port)
    assert caplog.text.count("TLS verification of printer 127.0.0.1 failed") == 1


def test_resumed_session_passes_the_serial_check(server_factory):
    # The FTP data channel resumes the control channel's session (prot_p); the
    # serial check must still find the leaf there.
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", SERIAL)
    ctx = printer_tls.printer_ssl_context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", server.port)) as raw:
        first = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        session = first.session
        first.close()
    with socket.create_connection(("127.0.0.1", server.port)) as raw:
        second = ctx.wrap_socket(raw, server_hostname="127.0.0.1", session=session)
        assert second.session_reused
        second.close()


# --- FTPS (ftplib) ----------------------------------------------------------


def test_ftp_login_reaches_a_verified_printer(server_factory):
    server = server_factory("leaf.pem", mode="ftp")
    printer_tls.register_printer("127.0.0.1", SERIAL)
    ftp = ImplicitFTP_TLS()
    ftp.connect("127.0.0.1", server.port, timeout=5)
    ftp.login("bblp", ACCESS_CODE)
    ftp.close()
    assert _wait_for(server, f"PASS {ACCESS_CODE}".encode())


def test_ftp_client_refuses_an_impostor_before_login(server_factory, monkeypatch):
    monkeypatch.setattr(BambuFTPClient, "_handshake_blocked_until", {})
    server = server_factory("impostor.pem", mode="ftp")
    client = BambuFTPClient("127.0.0.1", ACCESS_CODE, timeout=5)
    client.FTP_PORT = server.port
    assert client.connect() is False
    _settle()
    assert server.received == b""
    assert client.last_failure is not None
    assert client.last_failure.kind is FtpFailureKind.CERTIFICATE
    assert not BambuFTPClient.handshake_blocked("127.0.0.1")


def test_a_certificate_refusal_holds_queued_jobs():
    # Failing them would let one unrecognised printer eat the whole queue.
    assert FtpFailureKind.CERTIFICATE in print_scheduler._UPLOAD_REQUEUE_KINDS
    reason = print_scheduler._refused_upload_hold_reason("P1S", FtpFailureKind.CERTIFICATE)
    assert "certificate could not be verified" in reason
    assert "PRINTER_TLS_VERIFY" in reason


# --- asyncio: camera TLS proxy and the diagnostic ---------------------------


async def _send_through_proxy(upstream_port: int, ssl_ctx: ssl.SSLContext | None) -> None:
    port, proxy = await create_tls_proxy("127.0.0.1", upstream_port, ssl_ctx)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"DESCRIBE rtsp://bblp:{ACCESS_CODE}@127.0.0.1:{port}/streaming/live/1 RTSP/1.0\r\n\r\n".encode())
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(1), timeout=2)
        except TimeoutError:
            pass
        writer.close()
    finally:
        await close_tls_proxy(proxy)


@pytest.mark.asyncio
async def test_camera_proxy_forwards_to_a_verified_printer(server_factory):
    server = server_factory("leaf.pem")
    await _send_through_proxy(server.port, printer_tls.printer_ssl_context())
    assert await asyncio.to_thread(_wait_for, server, ACCESS_CODE.encode())


@pytest.mark.asyncio
async def test_camera_proxy_never_forwards_credentials_to_an_impostor(server_factory):
    server = server_factory("impostor.pem")
    await _send_through_proxy(server.port, printer_tls.printer_ssl_context())
    await asyncio.to_thread(_settle)
    assert server.received == b""


@pytest.mark.asyncio
async def test_asyncio_serial_mismatch_is_refused(server_factory):
    server = server_factory("leaf.pem")
    printer_tls.register_printer("127.0.0.1", "01P00OTHER00002")
    with pytest.raises(printer_tls.PrinterCertificateError, match="01P00OTHER00002"):
        await asyncio.open_connection("127.0.0.1", server.port, ssl=printer_tls.printer_ssl_context())


@pytest.mark.asyncio
@pytest.mark.parametrize(("cert", "state"), [("leaf.pem", "ok"), ("impostor.pem", "untrusted_cert")])
async def test_diagnostic_reports_an_untrusted_certificate(server_factory, monkeypatch, cert, state):
    server = server_factory(cert)
    monkeypatch.setattr(printer_diagnostic, "PORT_FTPS", server.port)
    assert await printer_diagnostic._check_ftps_tls("127.0.0.1", None) == state
