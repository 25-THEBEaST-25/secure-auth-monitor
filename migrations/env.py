from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from app.core.config import settings
from app.db import models  # noqa: F401  (registers tables on Base.metadata)
from app.db.database import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def url() -> str:
    # Tests pass an explicit URL; normal runs use the app's settings.
    return config.get_main_option("sqlalchemy.url") or settings.DATABASE_URL


def run_migrations_offline():
    context.configure(url=url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(url())
    with engine.connect() as connection:
        # Batch mode lets ALTER-style changes work on SQLite.
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
