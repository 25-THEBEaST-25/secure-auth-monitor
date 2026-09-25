import sqlite3

import bcrypt
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from app.core.security import verify_password
from app.db.database import Base

# Schema of auth.db files created before migrations existed.
LEGACY_SCHEMA = """
CREATE TABLE users (
    id INTEGER NOT NULL, username VARCHAR, hashed_password VARCHAR, is_locked BOOLEAN, PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_users_username ON users (username);
CREATE INDEX ix_users_id ON users (id);
"""


def alembic_config(url):
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{tmp_path}/m.db"
    command.upgrade(alembic_config(url), "head")
    with create_engine(url).connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []


def test_downgrade_and_upgrade_again(tmp_path):
    cfg = alembic_config(f"sqlite:///{tmp_path}/m.db")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")


def test_legacy_database_upgrades_and_keeps_users(tmp_path):
    path = tmp_path / "legacy.db"
    legacy_hash = bcrypt.hashpw(b"old-password", bcrypt.gensalt(4)).decode()
    with sqlite3.connect(path) as conn:
        conn.executescript(LEGACY_SCHEMA)
        conn.execute("INSERT INTO users VALUES (1, 'aryan', ?, 0)", (legacy_hash,))
        conn.execute("INSERT INTO users VALUES (2, 'banned', ?, 1)", (legacy_hash,))

    cfg = alembic_config(f"sqlite:///{path}")
    command.stamp(cfg, "0001")
    command.upgrade(cfg, "head")

    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT username, hashed_password, is_disabled, role, token_version FROM users ORDER BY id"
        ).fetchall()
    assert rows[0][0] == "aryan" and rows[0][2:] == (0, "user", 0)
    assert rows[1][0] == "banned" and rows[1][2] == 1
    # Hashes written by the old passlib code still verify with plain bcrypt.
    assert verify_password("old-password", rows[0][1])
