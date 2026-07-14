from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CVE(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    # Text plutôt qu'un String borné : certaines entrées CISA KEV concatènent une longue liste
    # de produits (ex. familles Snapdragon) qui dépasse largement 128 caractères et faisait
    # échouer l'insertion sous Postgres (SQLite, lui, n'applique pas la limite de VARCHAR(n)).
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    product: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    published_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_modified_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(16), nullable=True)
    has_poc: Mapped[bool] = mapped_column(Boolean, default=False)
    poc_links: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, default=list)  # connecteurs ayant vu cette CVE
    raw: Mapped[dict] = mapped_column(JSON, default=dict)  # dernière charge brute reçue (debug/audit)
    # Contexte menace agrégé (OTX/MISP/Mastodon) : {"otx": {"pulse_count": N, "tags": [...]}, "misp": {...}}
    threat_context: Mapped[dict] = mapped_column(JSON, default=dict)

    # Score prédictif d'exploitation (FIRST.org EPSS, gratuit) : probabilité (0-1) qu'un exploit
    # soit utilisé dans les 30 jours, et percentile relatif à toutes les CVE notées.
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    # CWE (type de faiblesse) et CPE affectés complets - extraits du payload NVD déjà récupéré,
    # sans requête réseau supplémentaire. cwe_ids: ["CWE-79", ...]. affected_cpes: liste de critères
    # CPE bruts (plafonnée, cf. commentaire sur les listes vendor Snapdragon trop longues).
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    affected_cpes: Mapped[list] = mapped_column(JSON, default=list)
    # Références catégorisées par tag NVD (Patch/Exploit/Third Party Advisory...) : [{"url":..., "tags":[...]}]
    references_meta: Mapped[list] = mapped_column(JSON, default=list)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    alerts: Mapped[list["AlertLog"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    cvss_history: Mapped[list["CVSSHistory"]] = relationship(back_populates="cve", cascade="all, delete-orphan")
    poc_link_records: Mapped[list["PocLink"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", order_by="PocLink.discovered_at.desc()"
    )


class WatchlistEntry(Base):
    __tablename__ = "watchlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    keyword: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str | None] = mapped_column(String(256), nullable=True)


class AlertLog(Base):
    __tablename__ = "alert_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"), index=True)
    channel: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)

    cve: Mapped["CVE"] = relationship(back_populates="alerts")


class SourceState(Base):
    """Suivi du dernier polling réussi par source, pour ne récupérer que les deltas."""

    __tablename__ = "source_state"

    source_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Nombre d'éléments récupérés au dernier cycle (ex: taille de tout le jeu de données EPSS,
    # potentiellement énorme) - distinct de last_new_count, bien plus parlant pour un analyste.
    last_success_count: Mapped[int] = mapped_column(Integer, default=0)
    last_new_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class CVSSHistory(Base):
    """Historique des scores CVSS : permet de détecter une réévaluation à la hausse et de ré-alerter."""

    __tablename__ = "cvss_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    cve: Mapped["CVE"] = relationship(back_populates="cvss_history")


class PocLink(Base):
    """PoC (preuve de concept d'exploitation) découvert pour une CVE, avec métadonnées riches.

    Distinct de `CVE.poc_links` (liste de simples URLs, conservée pour la compatibilité avec le
    moteur de règles et Exploit-DB) : cette table permet un flux "Radar PoC" ordonné par date de
    découverte (`ORDER BY discovered_at DESC`), ce qu'un blob JSON par CVE ne sert pas bien.
    """

    __tablename__ = "poc_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("cves.cve_id"), index=True)
    url: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(32))  # "github_poc", "nomi_sec", "exploitdb"...
    repo_full_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    stars: Mapped[int | None] = mapped_column(Integer, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    cve: Mapped["CVE"] = relationship(back_populates="poc_link_records")


class User(Base):
    """Compte permettant de se connecter au dashboard/API (JWT) et de gérer ses clés API."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # "admin" ou "viewer"
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class APIKey(Base):
    """Clé API émise pour un utilisateur. Seul le hash SHA-256 est stocké - la valeur en clair
    n'est montrée qu'une fois, à la création (comme un token GitHub/Stripe)."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(16), index=True)  # affiché dans l'UI pour identifier la clé
    hashed_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256 hex
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scopes: Mapped[list] = mapped_column(JSON, default=lambda: ["read", "write"])
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    owner: Mapped["User"] = relationship(back_populates="api_keys")
