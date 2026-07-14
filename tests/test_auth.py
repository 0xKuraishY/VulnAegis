import pytest

from app.config import settings
from app.rate_limit import reset_rate_limit


@pytest.fixture(autouse=True)
def _reset_login_rate_limit():
    # Starlette TestClient rapporte toujours "testclient" comme IP cliente : sans ce reset, les
    # tentatives de connexion d'un test s'accumuleraient avec celles du suivant (le compteur est
    # un état de process global, pas réinitialisé par les fixtures db_session/client).
    reset_rate_limit("login:testclient")
    yield


def register(client, email="admin@example.com", password="correct-horse-battery", token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/api/auth/register", json={"email": email, "password": password}, headers=headers)


def login(client, email="admin@example.com", password="correct-horse-battery"):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_first_registration_becomes_admin(client):
    resp = register(client)
    assert resp.status_code == 201
    body = resp.json()
    assert body["role"] == "admin"
    assert body["email"] == "admin@example.com"


def test_second_registration_without_admin_token_is_forbidden(client):
    register(client)
    resp = register(client, email="eve@example.com")
    assert resp.status_code == 403


def test_second_registration_is_forbidden_even_with_admin_token(client):
    # Mono-admin assumé : contrairement à un modèle multi-comptes classique, un admin déjà
    # connecté ne peut pas non plus créer d'autres comptes - l'inscription est fermée pour tout
    # le monde dès qu'un premier compte existe.
    register(client)
    token = login(client).json()["access_token"]
    resp = register(client, email="eve@example.com", token=token)
    assert resp.status_code == 403


def test_auth_status_reflects_setup_state(client):
    assert client.get("/api/auth/status").json() == {"setup_required": True}
    register(client)
    assert client.get("/api/auth/status").json() == {"setup_required": False}


def test_login_wrong_password_rejected(client):
    register(client)
    resp = login(client, password="wrong password")
    assert resp.status_code == 401


def test_me_requires_bearer_token(client):
    register(client)
    assert client.get("/api/auth/me").status_code == 401
    token = login(client).json()["access_token"]
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "admin@example.com"


def test_api_key_lifecycle(client):
    register(client)
    token = login(client).json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}

    created = client.post("/api/api-keys", json={"name": "ci"}, headers=auth)
    assert created.status_code == 201
    api_key = created.json()["api_key"]
    key_id = created.json()["id"]

    # La clé fonctionne sur un endpoint protégé (X-API-Key), sans JWT.
    resp = client.post("/api/watchlist", json={"vendor": "Acme"}, headers={"X-API-Key": api_key})
    assert resp.status_code == 201

    listed = client.get("/api/api-keys", headers=auth)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["last_used_at"] is not None  # mis à jour par l'appel précédent

    revoke = client.delete(f"/api/api-keys/{key_id}", headers=auth)
    assert revoke.status_code == 204

    rejected = client.post("/api/watchlist", json={"vendor": "Acme2"}, headers={"X-API-Key": api_key})
    assert rejected.status_code == 401


def test_legacy_static_api_key_still_accepted(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "legacy-secret")
    resp = client.post("/api/watchlist", json={"vendor": "Acme"}, headers={"X-API-Key": "legacy-secret"})
    assert resp.status_code == 201
    rejected = client.post("/api/watchlist", json={"vendor": "Acme"}, headers={"X-API-Key": "wrong"})
    assert rejected.status_code == 401


def test_open_when_nothing_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    resp = client.post("/api/watchlist", json={"vendor": "Acme"})
    assert resp.status_code == 201


def test_login_is_rate_limited_after_repeated_failures(client):
    register(client)
    for _ in range(10):
        resp = login(client, password="wrong password")
        assert resp.status_code == 401
    # La 11e tentative (dans la même fenêtre) est bloquée avant même de vérifier le mot de passe.
    resp = login(client, password="wrong password")
    assert resp.status_code == 429

    # Même avec le bon mot de passe, tant que la fenêtre n'est pas passée : toujours bloqué.
    resp = login(client, password="correct-horse-battery")
    assert resp.status_code == 429


def test_login_calls_password_check_even_for_unknown_email(client, monkeypatch):
    """Défense contre l'énumération de comptes par mesure de latence : bcrypt.checkpw doit être
    appelé que l'email existe ou non, sinon le temps de réponse révèle l'existence du compte."""
    calls = []
    from app.api import routes_auth

    original = routes_auth.verify_password

    def spy(password, hashed):
        calls.append(hashed)
        return original(password, hashed)

    monkeypatch.setattr(routes_auth, "verify_password", spy)

    resp = login(client, email="does-not-exist@example.com", password="whatever")
    assert resp.status_code == 401
    assert len(calls) == 1
    assert calls[0] == routes_auth._DUMMY_PASSWORD_HASH
