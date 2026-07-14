import json
import logging

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

_is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(settings.database_url, connect_args=connect_args)

if _is_sqlite:
    # Le scheduler (poll, escalade) et les endpoints API ouvrent des sessions concurrentes sur le
    # même fichier SQLite. WAL autorise des lecteurs pendant une écriture, et busy_timeout fait
    # attendre une connexion plutôt que de lever immédiatement "database is locked".
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_missing_columns() -> None:
    """Migration additive minimaliste (pas d'Alembic dans ce projet) : ajoute les colonnes
    manquantes sur les tables déjà existantes en base. `create_all` ne fait que créer les tables
    qui n'existent pas encore, il ne modifie jamais le schéma d'une table déjà présente - sans ce
    helper, ajouter un champ à un modèle casserait toute requête contre une base déjà peuplée
    (ex: le vulnaegis.db existant) avec `OperationalError: no such column`. Additif uniquement :
    ne renomme/altère/supprime jamais une colonne existante."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # table neuve : create_all s'en charge
        existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            with engine.begin() as conn:
                if column.name not in existing_columns:
                    ddl_type = column.type.compile(dialect=engine.dialect)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {ddl_type}'))
                    logger.info("Migration additive: colonne %s.%s ajoutée", table.name, column.name)
                # `ALTER TABLE ADD COLUMN` initialise toujours les lignes existantes à NULL, jamais
                # au default Python du modèle (ex: `default=list` ou `default=0`) - celui-ci ne
                # s'applique qu'aux futurs INSERT via l'ORM. Backfill inconditionnel (pas seulement
                # juste après l'ajout) : idempotent (no-op une fois fait), et rattrape une colonne déjà
                # ajoutée par un process concurrent avant que ce backfill n'existe. Sans lui, une CVE
                # existante lue via l'API aurait `cwe_ids: None` au lieu de `[]` (rejeté par Pydantic),
                # et un compteur comme `SourceState.last_new_count` resterait NULL au lieu de `0`.
                default_value = _column_default_value(column)
                if default_value is not None:
                    param = json.dumps(default_value) if isinstance(default_value, (list, dict)) else default_value
                    conn.execute(
                        text(f'UPDATE {table.name} SET "{column.name}" = :default WHERE "{column.name}" IS NULL'),
                        {"default": param},
                    )


def _column_default_value(column):
    """Retourne le default Python d'une colonne (scalaire comme `default=0`/`default=False`, ou
    callable comme `default=list`/`default=dict`), ou None si la colonne n'a pas de default (ex:
    `Float` nullable sans default, où NULL est la valeur voulue et ne doit jamais être backfillée)."""
    if column.default is None:
        return None
    if column.default.is_scalar:
        return column.default.arg
    if not callable(column.default.arg):
        return None
    # SQLAlchemy uniformise en interne les callables de default vers une signature `(ctx)` (même
    # pour un callable "nu" comme `default=list`, qui n'attend aucun argument) : appeler sans
    # argument lève TypeError ("missing 1 required positional argument: 'ctx'").
    try:
        return column.default.arg(None)
    except TypeError:
        try:
            return column.default.arg()
        except TypeError:
            return None


def init_db() -> None:
    from app import models  # noqa: F401  (enregistre les modèles sur Base.metadata)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
