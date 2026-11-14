"""TLS client contexts for connections to Bambu Lab printers.

Every connection Bambuddy makes to a printer (MQTT 8883, FTPS 990, camera 322
and 6000, the virtual printer's proxy) authenticates with the printer's access
code, and that code can start, stop and re-gcode prints. So the printer's
certificate is checked in the TLS handshake, before the code is sent, against
the certificate authorities Bambu Lab signs printers with
(``backend/app/data/bambu_printer_ca.pem``, provenance in its header). Only those
are trusted here: a certificate from a public CA is refused.

Two things about Bambu's certificates rule out the usual checks:

* The leaf has no subjectAltName, only ``CN=<printer serial>``, and printers
  are reached by IP address, so hostname checking is off. In ``serial`` mode the
  CN is compared with the serial of the printer the caller is connecting to
  instead.
* ``BBL CA`` has no keyUsage extension and the leaf is X.509 v1, so
  ``VERIFY_X509_STRICT`` (on by default since Python 3.13) would refuse a real
  printer. It is cleared; chain, signatures and validity dates are still
  checked.

``PRINTER_TLS_VERIFY`` selects the mode:

* ``serial`` (default): the chain must lead to a Bambu CA, and the leaf's CN
  must match ``expected_serial``.
* ``ca``: the chain must lead to a Bambu CA; the serial is not compared.
* ``off``: no verification, as before this module existed.

Every caller passes the serial explicitly (:func:`printer_ssl_context`): a
saved printer's own ``serial_number``, or for a probe of unsaved settings the
serial the user typed. There is no lookup by address, so a printer that is
saved but not connected is checked like any other, and nothing a probe or a
stale address does can change what another connection expects. ``None``
means the chain check alone; no connection to a saved printer passes it (every
saved printer has a serial), and the test suite checks that each call names
the serial.

``PRINTER_TLS_EXTRA_CA_FILE`` adds a PEM file of further CAs, for a model whose
chain is not in the shipped bundle yet.
"""

from __future__ import annotations

import logging
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Literal

from backend.app.core.config import settings

logger = logging.getLogger(__name__)

TlsVerifyMode = Literal["off", "ca", "serial"]

CA_BUNDLE = Path(__file__).resolve().parent.parent / "data" / "bambu_printer_ca.pem"

# The same failure repeats on every reconnect (MQTT retries every 1-30s), so the
# warning is logged once per printer and reason in this window.
_LOG_INTERVAL_SECONDS = 600.0

_lock = threading.Lock()
_last_logged: dict[tuple[str, str], float] = {}


class PrinterCertificateError(ssl.SSLCertVerificationError):
    """The printer's certificate failed verification. Nothing was sent to it."""


def _normalize_serial(serial: str) -> str:
    return serial.strip().upper()


def _hint(serial_mismatch: bool) -> str:
    if serial_mismatch:
        return (
            "Check that the printer's IP address and serial number in Bambuddy are current (a DHCP change can "
            "put another device at this address). PRINTER_TLS_VERIFY=ca skips the serial check."
        )
    return (
        "If this is a genuine Bambu Lab printer, its certificate authority may not be in Bambuddy's bundle yet: "
        "add it with PRINTER_TLS_EXTRA_CA_FILE, or set PRINTER_TLS_VERIFY=off to connect without verification, "
        "and please report the printer model and firmware."
    )


def _fail(
    conn: ssl.SSLSocket | ssl.SSLObject, reason: str, *, serial_mismatch: bool = False
) -> PrinterCertificateError:
    host = conn.server_hostname or "unknown address"
    message = f"TLS verification of printer {host} failed: {reason}. Nothing was sent to it. {_hint(serial_mismatch)}"
    # (errno, strerror), as the ssl module raises it: str() is then the message.
    err = PrinterCertificateError(ssl.SSL_ERROR_SSL, message)
    err.reason = "CERTIFICATE_VERIFY_FAILED"
    err.verify_message = reason
    now = time.monotonic()
    key = (host, reason)
    with _lock:
        last = _last_logged.get(key)
        if last is None or now - last >= _LOG_INTERVAL_SECONDS:
            _last_logged[key] = now
            should_log = True
        else:
            should_log = False
    if should_log:
        logger.warning("%s", message)
    return err


def _leaf_common_name(cert: dict[str, Any]) -> str | None:
    for rdn in cert.get("subject", ()):
        for name, value in rdn:
            if name == "commonName":
                return value
    return None


def _check_handshake(conn: ssl.SSLSocket | ssl.SSLObject) -> None:
    """Runs once the handshake (and OpenSSL's chain verification) succeeded."""
    context = conn.context
    if not isinstance(context, _PrinterSSLContext) or not context.check_serial:
        return
    want = context.expected_serial
    if want is None:
        return
    cert = conn.getpeercert()
    got = _leaf_common_name(cert) if cert else None
    if got is None or _normalize_serial(got) != want:
        raise _fail(
            conn,
            f"the certificate is for serial {got or '(none)'}, but Bambuddy expected printer {want}",
            serial_mismatch=True,
        )


def _wrap_verify_error(
    conn: ssl.SSLSocket | ssl.SSLObject, exc: ssl.SSLCertVerificationError
) -> PrinterCertificateError:
    reason = exc.verify_message or str(exc)
    return _fail(conn, f"its certificate did not verify against the Bambu Lab CAs Bambuddy trusts ({reason})")


class _PrinterSSLSocket(ssl.SSLSocket):
    # Blocking sockets: paho-mqtt and ftplib.
    def do_handshake(self, block: bool = False) -> None:
        try:
            try:
                super().do_handshake(block)
            except PrinterCertificateError:
                raise
            except ssl.SSLCertVerificationError as exc:
                raise _wrap_verify_error(self, exc) from exc
            _check_handshake(self)
        except PrinterCertificateError:
            # paho calls do_handshake itself and does not close the socket when
            # it raises; nothing more may go over this connection anyway.
            self.close()
            raise


class _PrinterSSLObject(ssl.SSLObject):
    # asyncio (and uvloop) streams: camera, diagnostic, virtual printer proxy.
    def do_handshake(self) -> None:
        try:
            super().do_handshake()
        except PrinterCertificateError:
            raise
        except ssl.SSLCertVerificationError as exc:
            raise _wrap_verify_error(self, exc) from exc
        _check_handshake(self)


class _PrinterSSLContext(ssl.SSLContext):
    sslsocket_class = _PrinterSSLSocket
    sslobject_class = _PrinterSSLObject
    check_serial: bool = False
    expected_serial: str | None = None


def printer_ssl_context(*, expected_serial: str | None, mode: TlsVerifyMode | None = None) -> ssl.SSLContext:
    """A client context for a connection to a printer, verifying it per ``mode``.

    ``mode`` defaults to the ``PRINTER_TLS_VERIFY`` setting. ``expected_serial``
    is the serial of the printer this connection is for, compared with the
    certificate's CN in ``serial`` mode. It is required so that no call site can
    leave it out by accident: ``None`` (or blank) means the chain check alone,
    and a caller passing it says why. Callers add their own
    protocol-version and cipher adjustments to the returned context; this only
    decides how the printer is verified.
    """
    if mode is None:
        mode = settings.printer_tls_verify
    if mode == "off":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx = _PrinterSSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    # STRICT refuses Bambu's real chain (see the module docstring). PARTIAL_CHAIN
    # is off in a plain SSLContext already; cleared explicitly so the bundle's
    # intermediates can never act as trust anchors on their own.
    ctx.verify_flags &= ~(ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_PARTIAL_CHAIN)
    ctx.load_verify_locations(cafile=str(CA_BUNDLE))
    if settings.printer_tls_extra_ca_file:
        ctx.load_verify_locations(cafile=settings.printer_tls_extra_ca_file)
    ctx.check_serial = mode == "serial"
    if expected_serial and expected_serial.strip():
        ctx.expected_serial = _normalize_serial(expected_serial)
    return ctx
