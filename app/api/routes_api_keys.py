"""Gestion des clés API personnelles. Protégé par JWT uniquement (pas par X-API-Key) : une clé
ne doit pas pouvoir s'auto-régénérer ou en créer d'autres sans repasser par une session utilisateur."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import generate_api_key
from app.database import get_db
from app.models import APIKey, User
from app.schemas import APIKeyCreatedOut, APIKeyCreateIn, APIKeyOut
from app.security import get_current_user

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])


@router.get("", response_model=list[APIKeyOut])
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    stmt = select(APIKey).where(APIKey.owner_id == user.id).order_by(APIKey.created_at.desc())
    return db.execute(stmt).scalars().all()


@router.post("", response_model=APIKeyCreatedOut, status_code=201)
def create_key(payload: APIKeyCreateIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    full_key, prefix, hashed = generate_api_key()
    expires_at = datetime.utcnow() + timedelta(days=payload.expires_days) if payload.expires_days else None

    row = APIKey(
        name=payload.name,
        prefix=prefix,
        hashed_key=hashed,
        owner_id=user.id,
        scopes=payload.scopes,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return APIKeyCreatedOut(
        id=row.id,
        name=row.name,
        prefix=row.prefix,
        scopes=row.scopes,
        created_at=row.created_at,
        expires_at=row.expires_at,
        api_key=full_key,
    )


@router.delete("/{key_id}", status_code=204)
def revoke_key(key_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.get(APIKey, key_id)
    if row is None or row.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Clé introuvable")
    if row.revoked_at is None:
        row.revoked_at = datetime.utcnow()
        db.commit()
