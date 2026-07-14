"""Régression pour app/database.py::_add_missing_columns.

Contexte : un test manuel sur une copie du vulnaegis.db réel a révélé que l'ALTER TABLE ADD COLUMN
laisse les lignes existantes à NULL (jamais backfillées au default Python du modèle), ce qui
faisait planter GET /api/cves/{id} avec une ResponseValidationError (cwe_ids: None au lieu de []).
Ces tests figent le comportement correct pour ne pas régresser.
"""
from sqlalchemy import create_engine, inspect, text

import app.database as dbmod
from app.models import CVE, SourceState


def test_column_default_value_distinguishes_list_dict_scalar_and_none():
    cwe_col = CVE.__table__.columns["cwe_ids"]
    cpes_col = CVE.__table__.columns["affected_cpes"]
    threat_col = CVE.__table__.columns["threat_context"]
    epss_col = CVE.__table__.columns["epss_score"]  # Float nullable, pas de default
    new_count_col = SourceState.__table__.columns["last_new_count"]  # Integer, default=0 (scalaire)

    assert dbmod._column_default_value(cwe_col) == []
    assert dbmod._column_default_value(cpes_col) == []
    assert dbmod._column_default_value(threat_col) == {}
    assert dbmod._column_default_value(epss_col) is None
    assert dbmod._column_default_value(new_count_col) == 0


def test_add_missing_columns_adds_and_backfills_columns_on_legacy_schema(monkeypatch, tmp_path):
    db_path = tmp_path / "legacy.db"
    legacy_engine = create_engine(f"sqlite:///{db_path}")

    # Schéma "avant" : une base créée par une version antérieure du modèle, sans les colonnes
    # ajoutées depuis (cwe_ids, affected_cpes, references_meta, threat_context, epss_score...).
    with legacy_engine.begin() as conn:
        conn.execute(text("CREATE TABLE cves (cve_id VARCHAR(32) PRIMARY KEY, description TEXT)"))
        conn.execute(text("INSERT INTO cves (cve_id, description) VALUES ('CVE-2024-0001', 'legacy row')"))

    monkeypatch.setattr(dbmod, "engine", legacy_engine)
    dbmod.Base.metadata.create_all(bind=legacy_engine)  # crée les tables neuves, laisse `cves` telle quelle
    dbmod._add_missing_columns()

    cols = {c["name"] for c in inspect(legacy_engine).get_columns("cves")}
    assert {"cwe_ids", "affected_cpes", "references_meta", "threat_context", "epss_score"} <= cols

    with legacy_engine.connect() as conn:
        row = conn.execute(
            text("SELECT cwe_ids, affected_cpes, references_meta, threat_context, epss_score "
                 "FROM cves WHERE cve_id = 'CVE-2024-0001'")
        ).one()

    assert row[0] == "[]"
    assert row[1] == "[]"
    assert row[2] == "[]"
    assert row[3] == "{}"
    assert row[4] is None  # nullable sans default mutable -> NULL reste NULL, jamais forcé à autre chose


def test_add_missing_columns_backfills_scalar_default_not_just_json(monkeypatch, tmp_path):
    """Régression : le premier helper de migration ne backfillait que les defaults list/dict
    (`_mutable_json_default`), donc une colonne scalaire neuve (ex: `last_new_count: int = 0`)
    restait NULL sur les lignes existantes au lieu de `0`."""
    db_path = tmp_path / "legacy_source_state.db"
    legacy_engine = create_engine(f"sqlite:///{db_path}")

    with legacy_engine.begin() as conn:
        conn.execute(text("CREATE TABLE source_state (source_name VARCHAR(64) PRIMARY KEY)"))
        conn.execute(text("INSERT INTO source_state (source_name) VALUES ('nvd')"))

    monkeypatch.setattr(dbmod, "engine", legacy_engine)
    dbmod.Base.metadata.create_all(bind=legacy_engine)
    dbmod._add_missing_columns()

    with legacy_engine.connect() as conn:
        row = conn.execute(text("SELECT last_new_count FROM source_state WHERE source_name = 'nvd'")).one()
    assert row[0] == 0  # et non NULL


def test_add_missing_columns_is_idempotent(monkeypatch, tmp_path):
    """Un deuxième appel (ex: redémarrage suivant) ne doit ni échouer ni ré-altérer les colonnes."""
    db_path = tmp_path / "idempotent.db"
    engine = create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(dbmod, "engine", engine)

    dbmod.Base.metadata.create_all(bind=engine)
    dbmod._add_missing_columns()
    dbmod._add_missing_columns()  # ne doit pas lever "duplicate column name"

    cols = {c["name"] for c in inspect(engine).get_columns("cves")}
    assert "cwe_ids" in cols
