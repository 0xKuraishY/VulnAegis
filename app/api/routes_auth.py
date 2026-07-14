"""Compte utilisateur (JWT) : usage mono-admin. Le tout premier compte créé au premier lancement
devient l'unique administrateur (bootstrap) - l'inscription se ferme définitivement dès qu'un
compte existe, il n'y a pas de gestion multi-utilisateurs. L'intégration machine-à-machine passe
par les clés API (/api/api-keys), individuellement révocables, pas par des comptes secondaires."""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth import create_access_token, hash_password, verify_password
from app.config import settings
from app.database import get_db
from app.models import User
from app.rate_limit import check_rate_limit
from app.schemas import LoginIn, TokenOut, UserOut, UserRegisterIn
from app.security import get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Fenêtre de brute-force : au-delà de 10 tentatives/5min pour une même IP, on renvoie 429 avant
# même de toucher la base ou bcrypt. Une IP légitime qui se trompe de mot de passe reste largement
# sous ce seuil ; un script de brute-force y est, lui, immédiatement freiné.
_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_WINDOW_SECONDS = 300

# Hash bcrypt factice, calculé une fois au chargement du module : comparé au mot de passe fourni
# quand l'email n'existe pas, pour que le temps de réponse de /login ne dépende jamais de
# l'existence du compte (sans ça, un email inconnu répond "vite" - pas de bcrypt.checkpw - alors
# qu'un email connu mais mauvais mot de passe répond "lentement", ce qui permet d'énumérer les
# comptes existants par mesure de latence).
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    """Public (pas d'auth) : le frontend s'en sert pour savoir s'il doit encore proposer la
    création du compte admin (premier lancement) ou seulement le formulaire de connexion."""
    return {"setup_required": db.query(User).count() == 0}


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserRegisterIn, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(status_code=403, detail="Un compte administrateur existe déjà - l'inscription est fermée")

    user = User(email=payload.email, hashed_password=hash_password(payload.password), role="admin")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(f"login:{client_ip}", _LOGIN_MAX_ATTEMPTS, _LOGIN_WINDOW_SECONDS):
        raise HTTPException(status_code=429, detail="Trop de tentatives de connexion, réessayez plus tard")

    user = db.query(User).filter(User.email == payload.email).first()
    # bcrypt.checkpw est TOUJOURS appelé (contre un hash factice si l'utilisateur n'existe pas),
    # afin que le temps de réponse ne révèle pas si l'email correspond à un compte existant.
    password_valid = verify_password(payload.password, user.hashed_password if user else _DUMMY_PASSWORD_HASH)
    if user is None or not user.is_active or not password_valid:
        raise HTTPException(status_code=401, detail="Email ou mot de passe invalide")
    token = create_access_token(user.id, user.email, user.role)
    return TokenOut(access_token=token, expires_in=settings.jwt_expire_minutes * 60)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user
