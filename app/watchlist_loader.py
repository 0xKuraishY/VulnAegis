"""Charge watchlist.yaml en base au démarrage (source de vérité éditable en fichier,
modifiable ensuite à chaud via l'API /api/watchlist)."""
import logging
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.config import settings
from app.models import WatchlistEntry

logger = logging.getLogger(__name__)


def seed_watchlist(db: Session) -> None:
    path = Path(settings.watchlist_path)
    if not path.exists():
        logger.info("Pas de watchlist.yaml trouvé (%s), watchlist vide au démarrage", path)
        return
    if db.query(WatchlistEntry).count() > 0:
        return  # déjà seedée, on n'écrase pas les entrées ajoutées via l'API

    data = yaml.safe_load(path.read_text()) or []
    for item in data:
        db.add(WatchlistEntry(
            vendor=item.get("vendor"),
            product=item.get("product"),
            keyword=item.get("keyword"),
            note=item.get("note"),
        ))
    db.commit()
    logger.info("Watchlist initialisée avec %s entrée(s) depuis %s", len(data), path)
