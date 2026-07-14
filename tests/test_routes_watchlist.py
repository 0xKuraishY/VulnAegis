import pytest

from app.config import settings


@pytest.fixture(autouse=True)
def _open_write_endpoints(monkeypatch):
    # Ces tests exercent les endpoints d'écriture sans credentials : neutralise API_KEY (qui peut
    # être défini dans le .env local du développeur) pour retrouver le mode "ouvert" documenté
    # quand aucune authentification n'est configurée - cf. test_open_when_nothing_configured.
    monkeypatch.setattr(settings, "api_key", None)


def test_add_list_and_delete_watchlist_entry(client):
    created = client.post("/api/watchlist", json={"vendor": "Cisco", "note": "core routers"})
    assert created.status_code == 201
    entry_id = created.json()["id"]

    listed = client.get("/api/watchlist")
    assert listed.status_code == 200
    assert any(e["id"] == entry_id for e in listed.json())

    deleted = client.delete(f"/api/watchlist/{entry_id}")
    assert deleted.status_code == 204
    assert all(e["id"] != entry_id for e in client.get("/api/watchlist").json())


def test_add_watchlist_entry_requires_at_least_one_field(client):
    resp = client.post("/api/watchlist", json={})
    assert resp.status_code == 400


def test_delete_unknown_watchlist_entry_returns_404(client):
    resp = client.delete("/api/watchlist/999999")
    assert resp.status_code == 404
