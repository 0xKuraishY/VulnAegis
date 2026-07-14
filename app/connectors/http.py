"""Session HTTP partagée par les connecteurs/enrichisseurs/notifieurs : retries avec backoff
exponentiel sur les erreurs transitoires (429/5xx), pour ne pas dupliquer cette logique partout.

Respecte l'en-tête `Retry-After` quand la source le fournit (ex: NVD/GitHub en cas de rate-limit).
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


def build_session(total_retries: int = 3, backoff_factor: float = 1.0) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=_RETRY_STATUS_CODES,
        allowed_methods=frozenset(["GET", "POST"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
