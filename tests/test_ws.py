import asyncio
import threading

from app.config import settings
from app.ingest import _broadcast_cve_event
from app.models import CVE
from app.ws import ConnectionManager, broadcast_threadsafe


def test_ws_accepts_connection_regardless_of_api_key_configuration(client, monkeypatch):
    # Le flux WebSocket diffuse les mêmes données que les endpoints REST en lecture (GET
    # /api/cves, /api/status...), volontairement ouverts même quand API_KEY est configuré
    # (seuls les endpoints d'écriture sont protégés, cf. app/security.py) - donc pas
    # d'authentification à la connexion, que API_KEY soit défini ou non.
    monkeypatch.setattr(settings, "api_key", "secret")
    with client.websocket_connect("/ws") as ws:
        envelope = ws.receive_json()
        assert envelope["type"] == "connection.ack"
        assert envelope["version"] == 1


def test_ws_broadcast_reaches_connected_client_from_real_thread(client):
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()  # connection.ack

        # Reproduit le pont thread-safe réel : les jobs planifiés/l'ingestion tournent dans un
        # thread distinct de la boucle asyncio de l'app (cf. app/scheduler.py). Un simple `await`
        # direct dans le test ne suffirait pas à détecter les bugs "wrong event loop".
        t = threading.Thread(target=broadcast_threadsafe, args=("cve.created", {"cve_id": "CVE-2026-9001"}))
        t.start()
        t.join()

        envelope = ws.receive_json()
        assert envelope["type"] == "cve.created"
        assert envelope["data"]["cve_id"] == "CVE-2026-9001"


def test_ws_broadcast_fans_out_to_all_connected_clients(client):
    with client.websocket_connect("/ws") as ws1, client.websocket_connect("/ws") as ws2:
        ws1.receive_json()
        ws2.receive_json()

        t = threading.Thread(target=broadcast_threadsafe, args=("source.status", {"name": "nvd"}))
        t.start()
        t.join()

        e1, e2 = ws1.receive_json(), ws2.receive_json()
        assert e1["type"] == e2["type"] == "source.status"


def test_manager_broadcast_survives_a_dead_socket():
    manager = ConnectionManager()
    sent = []

    class FakeDeadSocket:
        async def send_json(self, message):
            raise RuntimeError("connexion fermée")

    class FakeAliveSocket:
        async def send_json(self, message):
            sent.append(message)

    manager._active = {FakeDeadSocket(), FakeAliveSocket()}
    asyncio.run(manager.broadcast({"type": "cve.updated", "version": 1, "timestamp": "now", "data": {}}))

    assert len(sent) == 1
    assert len(manager._active) == 1  # le socket mort a été retiré


def test_ingest_broadcast_cve_event_reaches_connected_client(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-9002", cvss_score=9.8, is_kev=True))
    db_session.commit()
    cve = db_session.get(CVE, "CVE-2026-9002")

    with client.websocket_connect("/ws") as ws:
        ws.receive_json()  # connection.ack

        t = threading.Thread(target=_broadcast_cve_event, args=("cve.created", cve, []))
        t.start()
        t.join()

        envelope = ws.receive_json()
        assert envelope["type"] == "cve.created"
        assert envelope["data"]["cve_id"] == "CVE-2026-9002"
        assert envelope["data"]["risk_score"] > 0
