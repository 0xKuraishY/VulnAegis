"""Limiteur de débit in-process, en mémoire - pas de dépendance externe (Redis) pour un besoin
simple : freiner le brute-force sur les endpoints d'authentification depuis une seule instance.

Fenêtre glissante par clé (ex: IP + endpoint). Non persistant entre redémarrages : un redémarrage
remet les compteurs à zéro, ce qui n'aggrave pas le risque (au pire, une fenêtre de tentatives
repart à zéro, elle ne s'élargit jamais). Suffisant pour un déploiement mono-instance ; passer à un
compteur partagé (Redis) si l'app est un jour répliquée derrière un load balancer.
"""
import threading
import time
from collections import defaultdict

_lock = threading.Lock()
_attempts: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(key: str, max_attempts: int, window_seconds: float) -> bool:
    """Enregistre une tentative sous `key` et retourne False si `max_attempts` a déjà été atteint
    dans les `window_seconds` précédentes (fenêtre glissante). Retourne True (et compte la
    tentative) sinon."""
    now = time.monotonic()
    with _lock:
        history = _attempts[key]
        history[:] = [t for t in history if now - t < window_seconds]
        if len(history) >= max_attempts:
            return False
        history.append(now)
        return True


def reset_rate_limit(key: str) -> None:
    """Utilisé par les tests pour repartir d'un état propre entre deux scénarios."""
    with _lock:
        _attempts.pop(key, None)
