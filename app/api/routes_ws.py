"""Endpoint WebSocket temps réel : pousse cve.created/cve.updated/alert.created/source.status.

Diffuse exactement les mêmes données que les endpoints REST en lecture (GET /api/cves,
/api/cves/stats, /api/status, /api/alerts), qui sont volontairement ouverts sans authentification
même quand API_KEY/des comptes sont configurés (seuls les endpoints d'écriture le sont, cf.
app/security.py). Ce flux temps réel suit donc la même politique : aucune authentification requise
pour se connecter, cohérent avec le reste de l'API en lecture."""
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.ws import make_envelope, manager, set_main_loop

router = APIRouter(tags=["ws"])


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    # Filet de sécurité : app.main.lifespan capture normalement la boucle asyncio au démarrage
    # (set_main_loop), mais si ce n'est pas encore fait (ex: tests qui n'exécutent pas le
    # lifespan), la première connexion WebSocket réussie la capture aussi - idempotent.
    set_main_loop(asyncio.get_running_loop())

    await manager.connect(websocket)
    await manager.send(websocket, make_envelope("connection.ack", {"server_time": datetime.now(timezone.utc).isoformat()}))
    try:
        while True:
            # Socket unidirectionnel serveur -> client : on ne traite aucun message entrant,
            # ce receive_text() sert uniquement à détecter la déconnexion du client.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
