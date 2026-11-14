"""Printer and virtual-printer access codes are encrypted at rest.

The ORM column type hands every reader plaintext; the database holds a
``fernet:`` token when an encryption key is available and plaintext otherwise.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.app.core import encryption as enc_mod
from backend.app.core.database import _migrate_encrypt_legacy_secrets
from backend.app.core.encryption import select_stored
from backend.app.models.printer import Printer
from backend.app.models.virtual_printer import VirtualPrinter

CODE = "12345678"


def _no_key(monkeypatch):
    monkeypatch.setattr(enc_mod, "_load_or_generate_key", lambda: (None, "none"))
    enc_mod._fernet_instance = None


async def _raw(engine, table: str, row_id: int) -> str | None:
    async with engine.connect() as conn:
        result = await conn.execute(text(f"SELECT access_code FROM {table} WHERE id = :i"), {"i": row_id})  # noqa: S608
        return result.scalar()


async def _insert_legacy_printer(engine, printer_id: int, code: str) -> None:
    """A row as written before encryption existed: plaintext in the column."""
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    real = enc_mod._load_or_generate_key
    enc_mod._load_or_generate_key = lambda: (None, "none")
    enc_mod._fernet_instance = None
    try:
        async with maker() as s:
            s.add(
                Printer(
                    id=printer_id,
                    name="Legacy",
                    serial_number=f"SER{printer_id}",
                    ip_address="192.168.1.50",
                    access_code=code,
                )
            )
            await s.commit()
    finally:
        enc_mod._load_or_generate_key = real
        enc_mod._fernet_instance = None
    assert await _raw(engine, "printers", printer_id) == code


@pytest.mark.asyncio
async def test_write_stores_fernet_token_and_reads_plaintext(test_engine, printer_factory):
    printer = await printer_factory(access_code=CODE)

    raw = await _raw(test_engine, "printers", printer.id)
    assert raw.startswith("fernet:")
    assert CODE not in raw
    assert len(raw) > 20  # would not have fit the old VARCHAR(20)

    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as fresh:
        assert (await fresh.get(Printer, printer.id)).access_code == CODE


@pytest.mark.asyncio
async def test_plaintext_row_is_read_as_is(test_engine):
    await _insert_legacy_printer(test_engine, 1, CODE)
    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        assert (await s.get(Printer, 1)).access_code == CODE
    assert await _raw(test_engine, "printers", 1) == CODE  # reading does not rewrite


@pytest.mark.asyncio
async def test_no_key_behaves_as_before(test_engine, printer_factory, monkeypatch):
    from backend.app.core import database as database_module

    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database_module, "async_session", maker)
    _no_key(monkeypatch)
    printer = await printer_factory(access_code=CODE)
    assert await _raw(test_engine, "printers", printer.id) == CODE
    # and the startup migration leaves everything alone
    await _migrate_encrypt_legacy_secrets()
    assert await _raw(test_engine, "printers", printer.id) == CODE


@pytest.mark.asyncio
async def test_startup_migration_encrypts_legacy_rows(test_engine, monkeypatch):
    from backend.app.core import database as database_module

    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database_module, "async_session", maker)
    await _insert_legacy_printer(test_engine, 1, CODE)
    await _insert_legacy_printer(test_engine, 2, "ABCDEFGH")
    async with test_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO virtual_printers (id, name, enabled, mode, access_code, serial_suffix, position) "
                "VALUES (1, 'VP', FALSE, 'archive', 'VPCODE12', '391800001', 1)"
            )
        )

    await _migrate_encrypt_legacy_secrets()

    assert (await _raw(test_engine, "printers", 1)).startswith("fernet:")
    assert (await _raw(test_engine, "printers", 2)).startswith("fernet:")
    assert (await _raw(test_engine, "virtual_printers", 1)).startswith("fernet:")
    first = await _raw(test_engine, "printers", 1)
    async with maker() as s:
        assert (await s.get(Printer, 1)).access_code == CODE
        assert (await s.get(Printer, 2)).access_code == "ABCDEFGH"
        assert (await s.get(VirtualPrinter, 1)).access_code == "VPCODE12"

    # Idempotent: a second run does not re-encrypt (the token would change).
    await _migrate_encrypt_legacy_secrets()
    assert await _raw(test_engine, "printers", 1) == first


@pytest.mark.asyncio
async def test_api_round_trip(async_client, test_engine):
    probe = AsyncMock(return_value={"success": True, "state": "IDLE", "model": "X1C"})
    payload = {
        "name": "Enc Printer",
        "serial_number": "00M09A222222222",
        "ip_address": "192.168.1.101",
        "access_code": CODE,
        "model": "X1C",
    }
    with patch("backend.app.services.printer_manager.printer_manager.test_connection", new=probe):
        resp = await async_client.post("/api/v1/printers/", json=payload)
    assert resp.status_code == 200, resp.text
    created = resp.json()
    assert "access_code" not in created  # create never echoes the code

    assert (await _raw(test_engine, "printers", created["id"])).startswith("fernet:")
    assert (await async_client.get(f"/api/v1/printers/{created['id']}")).json()["access_code"] == CODE

    updated = await async_client.patch(f"/api/v1/printers/{created['id']}", json={"access_code": "NEWCODE1"})
    assert updated.status_code == 200
    raw = await _raw(test_engine, "printers", created["id"])
    assert raw.startswith("fernet:")
    assert "NEWCODE1" not in raw
    assert (await async_client.get(f"/api/v1/printers/{created['id']}")).json()["access_code"] == "NEWCODE1"


@pytest.mark.asyncio
async def test_ciphertext_survives_restore_with_same_key(test_engine, printer_factory, monkeypatch):
    """Backup/restore copies the database file and the key file. The copied
    ciphertext is read with the same key, and not with another one."""
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", key)
    enc_mod._fernet_instance = None
    printer = await printer_factory(access_code=CODE)
    raw = await _raw(test_engine, "printers", printer.id)

    enc_mod._fernet_instance = None  # "restore": new process, same key
    assert enc_mod.decrypt_stored(raw) == CODE
    monkeypatch.setenv("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    enc_mod._fernet_instance = None
    with pytest.raises(RuntimeError):
        enc_mod.decrypt_stored(raw)


@pytest.mark.asyncio
async def test_vp_access_code_encrypted_and_synced_from_target(test_engine, printer_factory, monkeypatch):
    from backend.app.core import database as database_module, db_dialect
    from backend.app.core.database import run_migrations

    # Follow the engine under test (SQLite, or PostgreSQL with TEST_POSTGRES_URL).
    on_sqlite = test_engine.dialect.name == "sqlite"
    monkeypatch.setattr(db_dialect, "is_sqlite", lambda: on_sqlite)
    monkeypatch.setattr(database_module, "is_sqlite", lambda: on_sqlite)
    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database_module, "async_session", maker)

    printer = await printer_factory(access_code=CODE)
    async with test_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO virtual_printers (id, name, enabled, mode, access_code, target_printer_id, "
                "serial_suffix, position) VALUES (1, 'VP', FALSE, 'queue', 'OLDVPCDE', :t, '391800001', 1)"
            ),
            {"t": printer.id},
        )
    async with test_engine.begin() as conn:
        await run_migrations(conn)

    raw = await _raw(test_engine, "virtual_printers", 1)
    assert raw.startswith("fernet:")
    async with maker() as s:
        assert (await s.get(VirtualPrinter, 1)).access_code == CODE

    # Re-running with the codes already in sync leaves the token untouched.
    async with test_engine.begin() as conn:
        await run_migrations(conn)
    assert await _raw(test_engine, "virtual_printers", 1) == raw


@pytest.mark.asyncio
async def test_backup_export_select_keeps_ciphertext(test_engine, printer_factory):
    """The PostgreSQL backup exporter copies rows with select_stored(), which
    must not decrypt: the portable backup holds what the database holds."""
    from backend.app.core.database import Base

    printer = await printer_factory(access_code=CODE)
    stored = await _raw(test_engine, "printers", printer.id)
    table = Base.metadata.tables["printers"]
    async with test_engine.connect() as conn:
        plain_rows = (await conn.execute(table.select())).mappings().all()
        stored_rows = (await conn.execute(select_stored(table))).mappings().all()
    assert plain_rows[0]["access_code"] == CODE
    assert stored_rows[0]["access_code"] == stored
    assert stored_rows[0]["access_code"].startswith("fernet:")
    assert list(stored_rows[0].keys()) == list(plain_rows[0].keys())


LEGACY_VP_CODE = "LEGACYVP"


async def _seed_legacy_vp_settings(engine, *, with_flag: bool = False) -> None:
    """The settings rows the old single-virtual-printer UI left behind."""
    rows = {
        "virtual_printer_enabled": "false",
        "virtual_printer_access_code": LEGACY_VP_CODE,
        "virtual_printer_mode": "archive",
    }
    if with_flag:
        rows["_migrate_single_virtual_printer_done"] = "true"
    async with engine.begin() as conn:
        for key, value in rows.items():
            await conn.execute(text('INSERT INTO settings ("key", value) VALUES (:k, :v)'), {"k": key, "v": value})


async def _legacy_vp_setting(engine) -> str | None:
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT value FROM settings WHERE key = 'virtual_printer_access_code'"))
        return result.scalar()


async def _raw_everything(engine) -> str:
    """Every stored value of the tables that could hold a copy of the code."""
    async with engine.connect() as conn:
        settings = (await conn.execute(text("SELECT key, value FROM settings"))).all()
        vps = (await conn.execute(text("SELECT access_code FROM virtual_printers"))).all()
    return repr(settings) + repr(vps)


def _follow_engine(test_engine, monkeypatch):
    from backend.app.core import database as database_module, db_dialect

    on_sqlite = test_engine.dialect.name == "sqlite"
    monkeypatch.setattr(db_dialect, "is_sqlite", lambda: on_sqlite)
    monkeypatch.setattr(database_module, "is_sqlite", lambda: on_sqlite)
    maker = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database_module, "async_session", maker)
    return maker


@pytest.mark.asyncio
async def test_legacy_vp_setting_is_migrated_then_leaves_no_plaintext(test_engine, monkeypatch):
    """The legacy settings row is only a migration source: its code moves into
    the virtual printer, encrypted, and the settings copy is gone (#4)."""
    from backend.app.core.database import run_migrations

    maker = _follow_engine(test_engine, monkeypatch)
    await _seed_legacy_vp_settings(test_engine)

    async with test_engine.begin() as conn:
        await run_migrations(conn)
    await _migrate_encrypt_legacy_secrets()  # init_db runs this right after run_migrations

    assert await _legacy_vp_setting(test_engine) is None
    raw = await _raw(test_engine, "virtual_printers", 1)
    assert raw.startswith("fernet:")
    assert LEGACY_VP_CODE not in await _raw_everything(test_engine)
    async with maker() as s:
        assert (await s.get(VirtualPrinter, 1)).access_code == LEGACY_VP_CODE  # reads still work


@pytest.mark.asyncio
async def test_legacy_vp_setting_is_dropped_when_virtual_printers_already_exist(test_engine, monkeypatch):
    """Upgraded installs migrated long ago still hold the row; it goes too."""
    from backend.app.core.database import run_migrations

    _follow_engine(test_engine, monkeypatch)
    await _seed_legacy_vp_settings(test_engine, with_flag=True)

    async with test_engine.begin() as conn:
        await run_migrations(conn)

    assert await _legacy_vp_setting(test_engine) is None
    assert LEGACY_VP_CODE not in await _raw_everything(test_engine)


@pytest.mark.asyncio
async def test_legacy_vp_setting_without_key_still_migrates_as_plaintext(test_engine, monkeypatch):
    """With no encryption key nothing is encrypted, as before; the code still
    reaches the virtual printer and the settings copy is still removed."""
    from backend.app.core.database import run_migrations

    maker = _follow_engine(test_engine, monkeypatch)
    _no_key(monkeypatch)
    await _seed_legacy_vp_settings(test_engine)

    async with test_engine.begin() as conn:
        await run_migrations(conn)
    await _migrate_encrypt_legacy_secrets()  # no-op without a key

    assert await _legacy_vp_setting(test_engine) is None
    assert await _raw(test_engine, "virtual_printers", 1) == LEGACY_VP_CODE
    async with maker() as s:
        assert (await s.get(VirtualPrinter, 1)).access_code == LEGACY_VP_CODE


@pytest.mark.asyncio
async def test_unrelated_settings_survive_the_legacy_cleanup(test_engine, monkeypatch):
    from backend.app.core.database import run_migrations

    _follow_engine(test_engine, monkeypatch)
    await _seed_legacy_vp_settings(test_engine)
    async with test_engine.begin() as conn:
        await run_migrations(conn)

    async with test_engine.connect() as conn:
        mode = (await conn.execute(text("SELECT value FROM settings WHERE key = 'virtual_printer_mode'"))).scalar()
    assert mode == "archive"
