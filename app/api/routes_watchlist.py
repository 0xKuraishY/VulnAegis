from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import WatchlistEntry
from app.schemas import WatchlistEntryIn, WatchlistEntryOut
from app.security import require_api_key

router = APIRouter(prefix="/api/watchlist", tags=["watchlist"])


@router.get("", response_model=list[WatchlistEntryOut])
def list_watchlist(db: Session = Depends(get_db)):
    return db.query(WatchlistEntry).all()


@router.post("", response_model=WatchlistEntryOut, status_code=201, dependencies=[Depends(require_api_key)])
def add_watchlist_entry(entry: WatchlistEntryIn, db: Session = Depends(get_db)):
    if not any([entry.vendor, entry.product, entry.keyword]):
        raise HTTPException(status_code=400, detail="Fournir au moins vendor, product ou keyword")
    row = WatchlistEntry(**entry.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.delete("/{entry_id}", status_code=204, dependencies=[Depends(require_api_key)])
def delete_watchlist_entry(entry_id: int, db: Session = Depends(get_db)):
    row = db.get(WatchlistEntry, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Entrée introuvable")
    db.delete(row)
    db.commit()
