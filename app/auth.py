"""Primitives d'authentification : mots de passe (bcrypt), JWT, et clés API.

Deux mécanismes de credentials coexistent volontairement :
- JWT (login utilisateur) : pour l'usage interactif (dashboard, gestion des clés API).
- Clé API (X-API-Key) : pour l'intégration machine-à-machine (CI, SIEM, scripts).
Voir app/security.py pour la logique qui accepte l'un ou l'autre sur les endpoints d'écriture.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings

API_KEY_PREFIX = "vla_"
JWT_ISSUER = "vulnaegis"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False  # hash malformé/legacy - jamais un mot de passe valide


def create_access_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


class TokenError(Exception):
    pass


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc


def generate_api_key() -> tuple[str, str, str]:
    """Retourne (clé en clair - à ne montrer qu'une fois, prefix affichable, hash sha256 stocké en DB)."""
    full_key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    prefix = full_key[: len(API_KEY_PREFIX) + 8]
    hashed = hash_api_key(full_key)
    return full_key, prefix, hashed


def hash_api_key(full_key: str) -> str:
    # SHA-256 (non salé) : la clé elle-même est déjà à haute entropie (256 bits aléatoires),
    # contrairement à un mot de passe utilisateur. Ça permet un lookup direct par hash en DB,
    # ce qu'un hash salé (bcrypt) empêcherait sans parcourir toutes les clés.
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()
