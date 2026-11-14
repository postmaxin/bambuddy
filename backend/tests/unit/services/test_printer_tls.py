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

import ast
import asyncio
import contextlib
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
from fastapi import HTTPException

from backend.app.api.routes import camera as camera_routes, printers as printers_routes
from backend.app.models.printer import Printer
from backend.app.services import camera, print_scheduler, printer_diagnostic, printer_tls
from backend.app.services.bambu_ftp import BambuFTPClient, FtpFailureKind, ImplicitFTP_TLS
from backend.app.services.bambu_mqtt import BambuMQTTClient
from backend.app.services.camera import close_tls_proxy, create_tls_proxy
from backend.app.services.printer_manager import printer_manager
from backend.app.services.virtual_printer.tcp_proxy import TLSProxy

FIXTURES = Path()  # set by the session fixture _pki
SERIAL = "01P00TEST000001"
# A different printer's serial: the test leaf is signed by the trusted CA, but
# for SERIAL, so a connection that expects OTHER_SERIAL must refuse it.
OTHER_SERIAL = "01P00OTHER00002"
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
    """Trust the test CA instead of Bambu's."""
    monkeypatch.setattr(printer_tls, "CA_BUNDLE", FIXTURES / "ca.pem")
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


def _mqtt_connect(port: int, serial: str | None = SERIAL) -> mqtt.Client:
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id="t")
    client.username_pw_set("bblp", ACCESS_CODE)
    client.tls_set_context(printer_tls.printer_ssl_context(expected_serial=serial))
    client.connect("127.0.0.1", port)
    return client


# --- The shipped bundle -----------------------------------------------------


def test_shipped_bundle_holds_bambu_cas(monkeypatch):
    monkeypatch.setattr(printer_tls, "CA_BUNDLE", SHIPPED_BUNDLE)
    ctx = printer_tls.printer_ssl_context(expected_serial=SERIAL)
    fingerprints = {hashlib.sha256(der).hexdigest() for der in ctx.get_ca_certs(binary_form=True)}
    assert BBL_CA_SHA256 in fingerprints
    assert len(fingerprints) == 8


def test_verifying_context_trusts_only_the_bundle():
    ctx = printer_tls.printer_ssl_context(expected_serial=SERIAL)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert not ctx.verify_flags & ssl.VERIFY_X509_STRICT
    assert not ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
    # The test CA only: no system roots, so a public-CA certificate is refused.
    assert len(ctx.get_ca_certs()) == 1


def test_off_mode_is_the_old_unverified_context(monkeypatch):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "off")
    ctx = printer_tls.printer_ssl_context(expected_serial=SERIAL)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert type(ctx) is ssl.SSLContext


def test_there_is_no_serial_registry_and_the_serial_is_required():
    # #8: the serial came from an address registry that only connected
    # printers were in. Every connection now names the printer it expects.
    for name in ("register_printer", "expected_serial", "_serial_by_host"):
        assert not hasattr(printer_tls, name)
    with pytest.raises(TypeError):
        printer_tls.printer_ssl_context()  # type: ignore[call-arg]


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
        client = _mqtt_connect(server.port, SERIAL.lower())
        client.disconnect()
        assert _wait_for(server, ACCESS_CODE.encode()), "control: the CONNECT packet should carry the code"
    finally:
        server.close()


def test_strict_x509_would_refuse_the_real_shaped_chain(server_factory):
    # Why VERIFY_X509_STRICT is cleared: the same chain fails with it set.
    server = server_factory("leaf.pem")
    ctx = printer_tls.printer_ssl_context(expected_serial=SERIAL)
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
    with pytest.raises(printer_tls.PrinterCertificateError, match="serial 01P00TEST000001.*01P00OTHER00002"):
        _mqtt_connect(server.port, OTHER_SERIAL)
    _settle()
    assert server.handshakes == 1  # the chain was fine; the CN check refused it
    assert server.received == b""


def test_an_mqtt_probe_with_a_mistyped_serial_never_gets_the_code(server_factory):
    # test_connection() probes the serial typed into Add Printer.
    server = server_factory("leaf.pem")
    client = BambuMQTTClient(ip_address="127.0.0.1", serial_number="01P00TYPO000003", access_code=ACCESS_CODE)
    client.MQTT_PORT = server.port
    client.connect()
    try:
        _settle()
        assert server.handshakes == 1
        assert server.received == b""
    finally:
        client.disconnect()


def test_ca_mode_skips_the_serial_check(server_factory, monkeypatch):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", "ca")
    server = server_factory("leaf.pem")
    _mqtt_connect(server.port, OTHER_SERIAL).disconnect()
    assert _wait_for(server, ACCESS_CODE.encode())


def test_no_serial_checks_the_chain_alone(server_factory):
    server = server_factory("leaf.pem")
    _mqtt_connect(server.port, None).disconnect()
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
    ctx = printer_tls.printer_ssl_context(expected_serial=SERIAL)
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
    ftp = ImplicitFTP_TLS(serial=SERIAL)
    ftp.connect("127.0.0.1", server.port, timeout=5)
    ftp.login("bblp", ACCESS_CODE)
    ftp.close()
    assert _wait_for(server, f"PASS {ACCESS_CODE}".encode())


def test_ftp_client_refuses_an_impostor_before_login(server_factory, monkeypatch):
    monkeypatch.setattr(BambuFTPClient, "_handshake_blocked_until", {})
    server = server_factory("impostor.pem", mode="ftp")
    client = BambuFTPClient("127.0.0.1", ACCESS_CODE, timeout=5, serial=SERIAL)
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


# --- A saved printer that is not connected (#8) -----------------------------
#
# Before #8 these connections looked the serial up in a registry that only
# connected printers were in, so for any other saved printer they fell back to
# the chain check alone and sent the code to whichever Bambu device answered.


def _saved_printer(serial: str, model: str = "P1S") -> Printer:
    return Printer(
        id=880001,
        name="Saved, not connected",
        serial_number=serial,
        ip_address="127.0.0.1",
        access_code=ACCESS_CODE,
        model=model,
        is_active=False,
    )


@pytest.fixture
def ftp_port(monkeypatch):
    """Point the FTP client at a test server, with fresh cool-off state."""
    monkeypatch.setattr(BambuFTPClient, "_handshake_blocked_until", {})
    monkeypatch.setattr(BambuFTPClient, "_handshake_skip_logged", {})
    monkeypatch.setattr(BambuFTPClient, "_cleartext_reply", {})

    def use(server: RecordingTLSServer) -> None:
        monkeypatch.setattr(BambuFTPClient, "FTP_PORT", server.port)

    return use


@pytest.mark.asyncio
async def test_ftp_for_an_inactive_saved_printer_refuses_another_printer(server_factory, ftp_port):
    server = server_factory("leaf.pem", mode="ftp")
    ftp_port(server)
    printer = _saved_printer(OTHER_SERIAL)
    assert printer_manager.get_client(printer.id) is None
    with pytest.raises(HTTPException) as exc_info:
        await printers_routes._download_printer_file_bytes(printer, "/cache/x.3mf")
    assert exc_info.value.status_code == 502
    await asyncio.to_thread(_settle)
    assert server.handshakes >= 1
    assert server.received == b""


@pytest.mark.asyncio
async def test_ftp_for_an_inactive_saved_printer_logs_in_to_that_printer(server_factory, ftp_port):
    # Control for the test above: the same printer with its own serial.
    server = server_factory("leaf.pem", mode="ftp")
    ftp_port(server)
    with contextlib.suppress(HTTPException):
        await printers_routes._download_printer_file_bytes(_saved_printer(SERIAL), "/cache/x.3mf")
    assert await asyncio.to_thread(_wait_for, server, f"PASS {ACCESS_CODE}".encode())


def test_ftp_client_refuses_another_printers_certificate(server_factory, ftp_port):
    server = server_factory("leaf.pem", mode="ftp")
    ftp_port(server)
    client = BambuFTPClient("127.0.0.1", ACCESS_CODE, timeout=5, serial=OTHER_SERIAL)
    assert client.connect() is False
    _settle()
    assert server.handshakes == 1
    assert server.received == b""
    assert client.last_failure is not None
    assert client.last_failure.kind is FtpFailureKind.CERTIFICATE


@pytest.mark.parametrize(("mode", "cert"), [("ca", "leaf.pem"), ("off", "impostor.pem")])
def test_ftp_modes_ca_and_off_do_not_compare_the_serial(server_factory, ftp_port, monkeypatch, mode, cert):
    monkeypatch.setattr(printer_tls.settings, "printer_tls_verify", mode)
    server = server_factory(cert, mode="ftp")
    ftp_port(server)
    client = BambuFTPClient("127.0.0.1", ACCESS_CODE, timeout=5, serial=OTHER_SERIAL)
    assert client.connect() is True
    client.disconnect()
    assert _wait_for(server, f"PASS {ACCESS_CODE}".encode())


# --- Camera: chamber image (6000) and the RTSPS proxy (322) ------------------


@pytest.fixture
def port_6000_to(monkeypatch):
    """Send the camera's connections to port 6000 to a test server instead."""
    real = asyncio.open_connection

    def use(server: RecordingTLSServer) -> None:
        async def redirected(host, port, **kwargs):
            return await real(host, server.port if port == 6000 else port, **kwargs)

        monkeypatch.setattr(asyncio, "open_connection", redirected)

    return use


@pytest.mark.asyncio
@pytest.mark.parametrize(("serial", "sent"), [(OTHER_SERIAL, False), (SERIAL, True)])
async def test_chamber_image_checks_the_printers_serial(server_factory, caplog, port_6000_to, serial, sent):
    server = server_factory("leaf.pem")
    port_6000_to(server)
    printer = _saved_printer(serial)
    await camera.capture_camera_frame_bytes(
        printer.ip_address, printer.access_code, printer.model, timeout=1, serial=printer.serial_number
    )
    if sent:
        assert await asyncio.to_thread(_wait_for, server, ACCESS_CODE.encode())
    else:
        await asyncio.to_thread(_settle)
        assert server.received == b""
        assert f"expected printer {OTHER_SERIAL}" in caplog.text


@pytest.mark.asyncio
async def test_chamber_image_stream_refuses_another_printer(server_factory, caplog, port_6000_to):
    server = server_factory("leaf.pem")
    port_6000_to(server)
    assert await camera.generate_chamber_image_stream("127.0.0.1", ACCESS_CODE, serial=OTHER_SERIAL) is None
    await asyncio.to_thread(_settle)
    assert server.received == b""
    assert f"expected printer {OTHER_SERIAL}" in caplog.text


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


class _ProxyStarted(Exception):
    pass


@pytest.fixture
def rtsps_contexts(monkeypatch):
    """The upstream context each RTSPS call site hands create_tls_proxy."""
    contexts: list[ssl.SSLContext | None] = []

    async def record(host, port, ssl_ctx=None):
        contexts.append(ssl_ctx)
        raise _ProxyStarted

    monkeypatch.setattr(camera, "create_tls_proxy", record)
    monkeypatch.setattr(camera_routes, "create_tls_proxy", record)
    monkeypatch.setattr(camera_routes, "get_ffmpeg_path", lambda: "ffmpeg")
    return contexts


@pytest.mark.asyncio
async def test_rtsps_call_sites_pass_the_printers_serial(server_factory, caplog, rtsps_contexts):
    printer = _saved_printer(OTHER_SERIAL, model="X1C")
    with pytest.raises(_ProxyStarted):
        await camera.capture_camera_frame_bytes(
            printer.ip_address, printer.access_code, printer.model, timeout=1, serial=printer.serial_number
        )
    stream = camera_routes.generate_rtsp_mjpeg_stream(
        printer.ip_address, printer.access_code, printer.model, serial=printer.serial_number
    )
    with pytest.raises(_ProxyStarted):
        await anext(stream)
    assert len(rtsps_contexts) == 2
    for ctx in rtsps_contexts:
        assert ctx is not None
        server = server_factory("leaf.pem")
        await _send_through_proxy(server.port, ctx)
        await asyncio.to_thread(_settle)
        assert server.received == b""
        assert f"expected printer {OTHER_SERIAL}" in caplog.text


@pytest.mark.asyncio
async def test_camera_proxy_forwards_to_a_verified_printer(server_factory):
    server = server_factory("leaf.pem")
    await _send_through_proxy(server.port, printer_tls.printer_ssl_context(expected_serial=SERIAL))
    assert await asyncio.to_thread(_wait_for, server, ACCESS_CODE.encode())


@pytest.mark.asyncio
async def test_camera_proxy_never_forwards_credentials_to_an_impostor(server_factory):
    server = server_factory("impostor.pem")
    await _send_through_proxy(server.port, printer_tls.printer_ssl_context(expected_serial=SERIAL))
    await asyncio.to_thread(_settle)
    assert server.received == b""


@pytest.mark.asyncio
async def test_asyncio_serial_mismatch_is_refused(server_factory):
    server = server_factory("leaf.pem")
    with pytest.raises(printer_tls.PrinterCertificateError, match=OTHER_SERIAL):
        await asyncio.open_connection(
            "127.0.0.1", server.port, ssl=printer_tls.printer_ssl_context(expected_serial=OTHER_SERIAL)
        )


# --- The diagnostic ----------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cert", "serial", "state"),
    [
        ("leaf.pem", SERIAL, "ok"),
        ("impostor.pem", SERIAL, "untrusted_cert"),
        ("leaf.pem", OTHER_SERIAL, "untrusted_cert"),
    ],
)
async def test_diagnostic_reports_an_untrusted_certificate(server_factory, monkeypatch, cert, serial, state):
    server = server_factory(cert)
    monkeypatch.setattr(printer_diagnostic, "PORT_FTPS", server.port)
    assert await printer_diagnostic._check_ftps_tls("127.0.0.1", None, serial=serial) == state
    await asyncio.to_thread(_settle)
    assert server.received == b""  # a handshake only, never a login


# --- The virtual printer's proxy ---------------------------------------------


def _free_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as sock:
        return sock.getsockname()[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(("serial", "sent"), [(OTHER_SERIAL, False), (SERIAL, True)])
async def test_vp_proxy_forwards_the_slicers_login_only_to_the_target_printer(server_factory, caplog, serial, sent):
    server = server_factory("leaf.pem")
    proxy = TLSProxy(
        name="MQTT",
        listen_port=_free_port(),
        target_host="127.0.0.1",
        target_port=server.port,
        server_cert_path=FIXTURES / "leaf.pem",
        server_key_path=FIXTURES / "leaf.key",
        bind_address="127.0.0.1",
        expected_serial=serial,
    )
    task = asyncio.create_task(proxy.start())
    try:
        for _ in range(100):
            if proxy._server is not None:
                break
            await asyncio.sleep(0.02)
        slicer_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        slicer_ctx.check_hostname = False
        slicer_ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.listen_port, ssl=slicer_ctx)
        writer.write(f"CONNECT bblp {ACCESS_CODE}".encode())
        await writer.drain()
        with contextlib.suppress(TimeoutError, ConnectionError, ssl.SSLError):
            await asyncio.wait_for(reader.read(1), timeout=2)
        writer.close()
        if sent:
            assert await asyncio.to_thread(_wait_for, server, ACCESS_CODE.encode())
        else:
            await asyncio.to_thread(_settle)
            assert server.received == b""
            assert f"expected printer {OTHER_SERIAL}" in caplog.text
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# --- Every call site names its printer ---------------------------------------

APP = Path(printer_tls.__file__).resolve().parent.parent

# What reaches a printer's TLS port, and the keyword that names the printer.
# A call that leaves the keyword out would check the chain alone, silently.
_SERIAL_KEYWORD = {
    "printer_ssl_context": "expected_serial",
    "TLSProxy": "expected_serial",
    "SlicerProxyManager": "target_serial",
    **dict.fromkeys(
        [
            "BambuFTPClient",
            "ImplicitFTP_TLS",
            "download_file_async",
            "download_file_try_paths_async",
            "upload_file_async",
            "list_files_async",
            "list_files_result_async",
            "find_remote_file_async",
            "delete_file_async",
            "download_file_bytes_async",
            "remote_file_settled",
            "delete_archived_timelapse",
            "get_storage_info_async",
            "read_chamber_image_frame",
            "generate_chamber_image_stream",
            "capture_camera_frame",
            "capture_camera_frame_bytes",
            "_capture_camera_frame_bytes_uncoalesced",
            "capture_finish_photo",
            "test_camera_connection",
            "diagnose_camera",
            "_check_first_frame",
            "capture_camera_image",
            "check_plate_empty",
            "calibrate_plate",
            "generate_rtsp_mjpeg_stream",
            "generate_chamber_mjpeg_stream",
            "_check_ftps_tls",
            "_do_upload",
        ],
        "serial",
    ),
}


def _called_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def test_every_call_that_reaches_a_printer_names_its_serial():
    missing = []
    checked = 0
    for path in sorted(APP.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            name = _called_name(node.func)
            # with_ftp_retry(op, *args, **kwargs) forwards its keywords to op.
            if name == "with_ftp_retry" and node.args:
                name = _called_name(node.args[0])
            # The stream route picks one of two generators and calls it by a
            # local name; both take the same keywords.
            if name == "stream_generator":
                name = "generate_rtsp_mjpeg_stream"
            keyword = _SERIAL_KEYWORD.get(name or "")
            if keyword is None:
                continue
            checked += 1
            if not any(kw.arg == keyword for kw in node.keywords):
                missing.append(f"{path.relative_to(APP)}:{node.lineno} {name}")
    assert missing == []
    assert checked > 50  # the walk found the call sites at all
