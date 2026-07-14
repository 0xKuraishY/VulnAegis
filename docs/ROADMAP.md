# Roadmap VulnAegis

VulnAegis est un détecteur/remonteur de CVE - pas un outil de corrélation avec
un inventaire d'équipements. La watchlist (vendor/produit/mot-clé, voir
`app/alerting/rules.py`) reste le cœur du moteur d'alerte : elle sert à
prioriser *quelles* CVE remonter, pas à faire de l'inventaire d'assets.
L'authentification (comptes/JWT/clés API) reste également en place. Seule
l'escalade SMS (Twilio) a été retirée, jugée peu utile.

## Phase 0 - MVP (livré dans ce dépôt)

- [x] Connecteurs NVD, CISA KEV, GitHub Advisories (polling)
- [x] Enrichisseur OSV (à la demande, packages/écosystèmes affectés)
- [x] Pipeline d'ingestion avec upsert multi-sources (une même CVE peut être vue par plusieurs connecteurs, jamais dupliquée)
- [x] Moteur de règles : CVSS ≥ seuil, KEV, watchlist (vendor/product/keyword)
- [x] Dédoublonnage des alertes (fenêtre 24h configurable)
- [x] Escalade automatique Slack (CVE critique/KEV non acquittée après N heures)
- [x] Notifications Slack, Email (SMTP), Webhook générique (SIEM/SOAR)
- [x] API REST (filtrage, recherche, export CSV/JSON, stats)
- [x] Dashboard temps réel (polling 30s), watchlist éditable via l'UI/API
- [x] Docker Compose (app + Postgres + Redis prêt pour la suite)
- [x] Tests unitaires (moteur de règles, connecteurs)

## Phase 1 - Consolidation

- [x] Connecteur Exploit-DB (export CSV public officiel, croisé avec les CVE en base) pour peupler `has_poc` (`app/connectors/exploitdb.py`)
- [x] Intégration MISP / AlienVault OTX pour enrichissement contexte menace (`app/enrichment/`)
- [x] Interface de gestion de la watchlist dans le dashboard (CRUD sans passer par l'API brute)
- [x] Authentification API (comptes + JWT, clés API individuellement révocables/traçables) - `app/auth.py`, `/api/auth`, `/api/api-keys`
- [x] Rate-limiting et retries exponentiels génériques sur tous les connecteurs (`app/connectors/http.py`)
- [x] Historisation des changements de score CVSS (une CVE réévaluée à la hausse doit ré-alerter) (`CVSSHistory`, `app/ingest.py`)

## Phase 1.5 - Radar PoC temps réel + fiche CVE enrichie (livré dans ce dépôt)

Fonctionnalité phare : détecter en continu les nouveaux PoC publics liés à des
CVE très récentes et sévères, sans jamais dupliquer une CVE, et afficher un
niveau de détail comparable à des outils type CVE Radar au clic sur une CVE.
Toutes les sources ajoutées ici sont gratuites, sans clé API payante.

- [x] **Radar PoC GitHub temps réel** (`app/connectors/github_poc.py`) : recherche GitHub (API Search, gratuite, cadence ~4 min, découplée du poll principal) des repos récemment mis à jour mentionnant une CVE de l'année courante/précédente. Crée une fiche CVE "stub" si le PoC apparaît avant que NVD/KEV/GHSA n'aient ingéré la CVE (rattrapée automatiquement ensuite, jamais dégradée).
- [x] **Table `PocLink` dédiée** (métadonnées riches : repo, étoiles, date de découverte) pour un flux "plus récent en premier", en plus de `CVE.poc_links` (conservé pour compat avec le moteur de règles/Exploit-DB).
- [x] **Raison d'alerte "risque d'exploitation imminente"** distincte de "PoC public disponible" quand un PoC apparaît sur une CVE déjà KEV ou CVSS ≥ 9 (`app/alerting/rules.py`).
- [x] **Verrou anti-doublon central** : `NormalizedCVE.cve_id` valide/normalise (strip+upper) tout identifiant avant `upsert_cve` - nécessaire dès qu'une source texte-libre/regex (repos GitHub) alimente le pipeline, contrairement aux 3 connecteurs structurés historiques qui émettaient déjà des ID propres.
- [x] **EPSS** (`app/enrichment/epss.py`, FIRST.org, gratuit sans clé) : score prédictif d'exploitation (probabilité + percentile), republié quotidiennement.
- [x] **Parsing NVD approfondi** (déjà présent dans la réponse existante, aucune requête réseau en plus) : CWE (type de faiblesse), liste complète des CPE affectés, références catégorisées par tag (Patch/Exploit/Advisory...).
- [x] **Fiche CVE détaillée** (`GET /api/cves/{id}` → `CVEDetailOut`) : EPSS, CWE, CPE affectés, références catégorisées, PoC enrichis, contexte menace OTX/MISP et historique CVSS - ces deux derniers étaient déjà collectés en base mais jamais exposés avant cette phase.
- [x] **Dashboard** : page "Radar PoC" (flux temps réel), stat "PoC découverts (24h)", badge "non confirmée" sur les CVE stub, fiche CVE enrichie en conséquence.
- [x] Migration additive (`app/database.py`) : ajout de colonnes sur une base SQLite/Postgres déjà peuplée, sans Alembic (limite connue - pas de down-migration, à réévaluer si le schéma continue de grossir).
- [x] Suppression de l'escalade SMS (Twilio).

## Phase 2 - Passage à l'échelle

- [ ] Redis en cache actif pour l'API (`/api/cves/stats`, requêtes filtrées fréquentes)
- [ ] Elasticsearch en complément de Postgres pour la recherche full-text/facettes
- [ ] Passage du dashboard en WebSockets pour un vrai temps réel (fin du polling 30s)
- [ ] Déploiement Kubernetes (Helm chart), health checks, autoscaling horizontal de l'API
- [ ] CI/CD (GitHub Actions) : lint, tests, build image, scan de vulnérabilités de l'image elle-même

## Phase 3 - Fonctionnalités avancées (au-delà)

- [ ] File Kafka pour découpler ingestion/traitement (voir `ARCHITECTURE.md` §2)
- [ ] Bulletins éditeurs additionnels (Microsoft MSRC, Cisco PSIRT, Adobe PSIRT...) via connecteurs dédiés
- [ ] `nomi-sec/PoC-in-GitHub` comme source de backfill complémentaire au radar GitHub temps réel (mêmes garanties anti-doublon)
- [ ] Signal social Mastodon (`infosec.exchange`, hashtags `#CVE`/`#0day`) comme enrichissement purement informatif du contexte menace, jamais comme déclencheur d'alerte ni créateur de CVE - API publique gratuite sans clé, contrairement à l'API de recherche X/Twitter qui est désormais payante. Signal volontairement faible (comme OTX/MISP), à ne pas confondre avec le radar PoC GitHub qui, lui, alerte.

## Ce qui n'est volontairement pas priorisé

- **Scraping direct de X/Twitter** (Nitter, HTML) : fragile, contraire aux ToS, cassé régulièrement par les mesures anti-scraping - pas de solution gratuite fiable identifiée. Le substitut retenu est Mastodon (voir Phase 3), pas un contournement de X lui-même.
- **VulnDB commercial** : coût significatif, non prioritaire tant que NVD/KEV/GHSA/OSV/EPSS/radar PoC couvrent le besoin (voir `SOURCES_BENCHMARK.md`).
- **Corrélation avec un inventaire d'équipements/assets** : hors périmètre de l'outil - la watchlist vendor/produit/mot-clé (déjà en place) couvre le besoin de priorisation sans qu'il soit nécessaire de modéliser un parc matériel.
