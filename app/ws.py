"""Diffusion temps réel : registre des connexions WebSocket actives et pont thread-safe.

Les jobs planifiés (app/scheduler.py) et les fonctions d'ingestion (app/ingest.py) tournent
dans le thread `BackgroundScheduler`, pas dans la boucle asyncio d'uvicorn. `broadcast_threadsafe`
est le seul point d'entrée sûr pour ces appelants : il route l'appel vers la boucle asyncio
capturée au démarrage (`set_main_loop`, appelé depuis `app.main.lifespan`).
"""
import asyncio
import logging
from datetime import datetime, timezone

from fastapi import WebSocket

logger = logging.getLogger(__name__)

_ENVELOPE_VERSION = 1


class ConnectionManager:
    def __init__(self) -> None:
        self._active: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._active.discard(websocket)

    async def send(self, websocket: WebSocket, message: dict) -> None:
        await websocket.send_json(message)

    async def broadcast(self, message: dict) -> None:
        # Copie de l'ensemble : un socket peut se déconnecter (et donc être retiré de
        # `_active` par un autre coroutine) pendant l'itération.
        for websocket in list(self._active):
            try:
                await websocket.send_json(message)
            except Exception:
                # Un socket mort ne doit jamais empêcher la diffusion aux autres clients connectés.
                logger.debug("Échec d'envoi WebSocket, connexion retirée", exc_info=True)
                self._active.discard(websocket)


manager = ConnectionManager()

_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


def make_envelope(event_type: str, data: dict) -> dict:
    return {
        "type": event_type,
        "version": _ENVELOPE_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


def broadcast_threadsafe(event_type: str, data: dict) -> None:
    """Diffuse un événement depuis n'importe quel thread (jobs APScheduler compris).

    No-op silencieux si aucune boucle n'a été capturée (ex: tests qui n'exécutent pas le
    lifespan de l'application) - la diffusion temps réel est un bonus, jamais un prérequis
    au bon déroulement de l'ingestion.
    """
    if _main_loop is None:
        return
    envelope = make_envelope(event_type, data)
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(envelope), _main_loop)
    except RuntimeError:
        logger.debug("Boucle asyncio indisponible pour le broadcast WebSocket", exc_info=True)
