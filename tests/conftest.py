import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - enregistre les modèles sur Base.metadata avant create_all
from app.database import Base, get_db


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    # Import différé : app.main déclenche des imports lourds (scheduler, connecteurs...).
    # Pas de "with TestClient(app)" ici : ça éviterait de déclencher le lifespan (donc
    # start_scheduler()/init_db(), qui lanceraient de vrais polls réseau pendant les tests).
    from app.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()
