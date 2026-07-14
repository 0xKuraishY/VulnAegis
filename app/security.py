"""Protection des endpoints qui modifient un état ou déclenchent des appels sortants.

Trois mécanismes de credentials sont acceptés sur `require_api_key`, dans cet ordre :
1. JWT (`Authorization: Bearer <token>`) - utilisateur connecté au dashboard.
2. Clé API émise via `/api/api-keys` (`X-API-Key: <clé>`), hashée en DB (SHA-256), révocable.
3. Clé statique legacy (`API_KEY` dans `.env`) - conservée pour compat ascendante, mais dépréciée :
   à la différence d'une clé DB, elle n'est ni individuellement traçable ni révocable sans
   redéploiement. Un avertissement est loggué à chaque usage.

Si rien de tout ça n'est configuré (aucun utilisateur/clé en DB, pas d'API_KEY), les endpoints
restent ouverts - mode dev/local uniquement, voir README.md > Sécurité.
"""
import hmac
import logging
from datetime import datetime

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.auth import TokenError, decode_access_token, hash_api_key
from app.config import settings
from app.database import get_db
from app.models import APIKey, User

logger = logging.getLogger(__name__)

_warned = False


def _decode_bearer(authorization: str | None) -> dict | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    try:
        return decode_access_token(authorization[7:])
    except TokenError:
        return None


def _lookup_db_api_key(db: Session, x_api_key: str) -> APIKey | None:
    key = db.query(APIKey).filter(APIKey.hashed_key == hash_api_key(x_api_key)).first()
    if key is None or key.revoked_at is not None:
        return None
    if key.expires_at is not None and key.expires_at < datetime.utcnow():
        return None
    return key


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> None:
    global _warned

    if _decode_bearer(authorization) is not None:
        return

    if x_api_key:
        key = _lookup_db_api_key(db, x_api_key)
        if key is not None:
            key.last_used_at = datetime.utcnow()
            db.commit()
            return
        if settings.api_key and hmac.compare_digest(x_api_key, settings.api_key):
            logger.warning(
                "Authentification via API_KEY statique (legacy) - préférer une clé émise via "
                "/api/api-keys (individuellement traçable/révocable)."
            )
            return

    if not settings.api_key and db.query(APIKey).count() == 0:
        if not _warned:
            logger.warning(
                "Aucune authentification configurée (ni API_KEY, ni utilisateur/clé API en DB) : "
                "les endpoints d'écriture (watchlist, ack, poll-now, gestion des clés/comptes) ne "
                "sont PAS protégés. À définir avant toute exposition réseau."
            )
            _warned = True
        return

    raise HTTPException(
        status_code=401,
        detail="Authentification requise (en-tête Authorization: Bearer <jwt> ou X-API-Key)",
    )


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    claims = _decode_bearer(authorization)
    if claims is None:
        raise HTTPException(status_code=401, detail="Token manquant ou invalide (Authorization: Bearer <jwt>)")
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable ou désactivé")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs")
    return user


