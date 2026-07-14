"""Schémas Pydantic : format pivot utilisé par tous les connecteurs (normalisation des sources)."""
import re
from datetime import datetime

from pydantic import BaseModel, Field, StringConstraints, field_validator
from typing import Annotated

_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,19}$")


def normalize_cve_id(value: str) -> str | None:
    """Normalise (strip+upper) et valide un identifiant CVE, ou retourne None s'il est invalide.

    Point de vérité unique réutilisé par `NormalizedCVE._normalize_cve_id` (connecteurs
    structurés) et par les sources texte-libre/regex (ex: app.connectors.github_poc) qui extraient
    un ID CVE d'un nom de repo ou d'une description - garde-fou anti-doublon central."""
    normalized = value.strip().upper()
    return normalized if _CVE_ID_PATTERN.match(normalized) else None

ShortStr = Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)]
NoteStr = Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)]
# Validation de forme uniquement (pas de vérification de délivrabilité/TLD réservé comme
# pydantic.EmailStr, qui rejette par exemple les domaines internes en .local) : cet email sert
# d'identifiant de connexion, pas de destinataire SMTP réel.
EmailStr = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=256, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class NormalizedCVE(BaseModel):
    cve_id: str
    source: str  # nom du connecteur d'origine (nvd, cisa_kev, github_advisories, osv...)
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None  # LOW / MEDIUM / HIGH / CRITICAL
    vendor: str | None = None
    product: str | None = None
    published_date: datetime | None = None
    last_modified_date: datetime | None = None
    references: list[str] = Field(default_factory=list)
    is_kev: bool = False
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None
    kev_ransomware_use: str | None = None
    has_poc: bool = False
    poc_links: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)
    cwe_ids: list[str] = Field(default_factory=list)
    affected_cpes: list[str] = Field(default_factory=list)
    references_meta: list[dict] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, value: str) -> str:
        """Verrou central anti-doublon : toute source passe par ce validateur avant `upsert_cve`
        (clé primaire de `CVE`). Les 3 connecteurs structurés (NVD/KEV/GHSA) émettent déjà des ID
        en majuscules - ce garde-fou protège surtout les futures sources texte-libre/regex
        (repos GitHub, posts sociaux) où la casse n'est jamais garantie."""
        normalized = normalize_cve_id(value)
        if normalized is None:
            raise ValueError(f"cve_id invalide: {value!r}")
        return normalized


class RiskBreakdownItemOut(BaseModel):
    factor: str
    points: float
    value: float | bool | None = None

    model_config = {"from_attributes": True}


class CVEOut(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    vendor: str | None
    product: str | None
    published_date: datetime | None
    last_modified_date: datetime | None
    references: list[str]
    is_kev: bool
    kev_date_added: datetime | None
    kev_due_date: datetime | None = None
    kev_ransomware_use: str | None = None
    has_poc: bool
    poc_links: list[str]
    sources: list[str]
    first_seen: datetime
    last_seen: datetime
    is_flagged: bool = False
    flag_reasons: list[str] = Field(default_factory=list)
    # Score de risque composite (app/scoring.py), calculé à la volée en lecture - non persisté.
    risk_score: int = 0
    risk_level: str = "info"
    risk_breakdown: list[RiskBreakdownItemOut] = Field(default_factory=list)
    is_weaponization_risk: bool = False

    model_config = {"from_attributes": True}


class PocLinkOut(BaseModel):
    url: str
    source: str
    repo_full_name: str | None
    stars: int | None
    discovered_at: datetime

    model_config = {"from_attributes": True}


class CVSSHistoryOut(BaseModel):
    cvss_score: float | None
    severity: str | None
    recorded_at: datetime

    model_config = {"from_attributes": True}


class CVEDetailOut(CVEOut):
    """Fiche CVE complète (style CVE Radar) - utilisée uniquement par GET /api/cves/{id}.
    CVEOut reste léger pour list/export/stats (pas de N+1 sur les relations ci-dessous)."""
    epss_score: float | None
    epss_percentile: float | None
    cwe_ids: list[str]
    affected_cpes: list[str]
    references_meta: list[dict]
    threat_context: dict
    cvss_history: list[CVSSHistoryOut]
    poc_link_records: list[PocLinkOut] = Field(serialization_alias="poc_links_detailed")
    unconfirmed: bool = False


class WatchlistEntryIn(BaseModel):
    vendor: ShortStr | None = None
    product: ShortStr | None = None
    keyword: ShortStr | None = None
    note: NoteStr | None = None


class WatchlistEntryOut(WatchlistEntryIn):
    id: int

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: int
    cve_id: str
    channel: str
    reasons: list[str]
    sent_at: datetime
    acknowledged: bool
    acknowledged_at: datetime | None
    escalated: bool

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_cves: int
    kev_count: int
    by_severity: dict[str, int]
    by_day: dict[str, int]
    top_vendors: dict[str, int]
    weaponization_risk_count: int = 0
    epss_high_risk_count: int = 0
    unconfirmed_count: int = 0
    top_cwe: dict[str, int] = Field(default_factory=dict)
    epss_distribution: dict[str, int] = Field(default_factory=dict)
    weaponization_by_day: dict[str, int] = Field(default_factory=dict)
    kev_by_day: dict[str, int] = Field(default_factory=dict)
    risk_distribution: dict[str, int] = Field(default_factory=dict)


PasswordStr = Annotated[str, StringConstraints(min_length=8, max_length=256)]


class UserRegisterIn(BaseModel):
    email: EmailStr
    password: PasswordStr


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class APIKeyCreateIn(BaseModel):
    name: ShortStr
    scopes: list[str] = Field(default_factory=lambda: ["read", "write"])
    expires_days: int | None = Field(default=None, ge=1, le=3650)


class APIKeyCreatedOut(BaseModel):
    id: int
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    api_key: str  # valeur en clair - affichée une seule fois, jamais recalculable après coup


class APIKeyOut(BaseModel):
    id: int
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None

    model_config = {"from_attributes": True}
