# Benchmark des sources CVE

Évaluation des sources intégrées (ou envisagées) pour VulnAegis, du point de
vue d'un SOC qui doit prioriser où investir en premier.

| Source | Latence de mise à jour | Complétude | Fiabilité | Auth requise | Coût | Statut dans VulnAegis |
|---|---|---|---|---|---|---|
| **NVD (NIST)** | Historiquement lente à l'enrichissement (CVSS/CPE peut prendre plusieurs jours après publication MITRE), mais c'est la source de référence pour le scoring CVSS officiel | Très élevée (référence de facto) | Très élevée | Non (clé API optionnelle pour quota) | Gratuit | ✅ Intégré (poller) |
| **CISA KEV** | Quasi temps réel dès confirmation d'exploitation active | Faible en volume (~1000-1500 CVE), mais critique en pertinence | Très élevée (source gouvernementale, criticité vérifiée) | Non | Gratuit | ✅ Intégré (poller) - priorité maximale dans le moteur de règles |
| **GitHub Advisories** | Rapide (souvent avant NVD pour les dépendances open source) | Élevée pour l'écosystème open source (npm, PyPI, Go, Maven...), nulle pour le reste (OS, matériel réseau) | Élevée | Non (token recommandé pour quota) | Gratuit | ✅ Intégré (poller) |
| **OSV.dev** | Rapide, agrège plusieurs sources par écosystème | Élevée pour open source, avec plages de versions précises (meilleur que NVD sur ce point) | Élevée | Non | Gratuit | ✅ Intégré (enrichissement à la demande - pas de flux "récent" en API publique) |
| **MITRE CVE** | Source primaire d'attribution des IDs, souvent la première à publier une CVE (avant enrichissement NVD) | Élevée mais données brutes peu structurées pour le scoring | Très élevée | Non | Gratuit | ⏳ Roadmap - CVE List v5 (GitHub) comme alternative au site web |
| **Exploit-DB** | Variable | Bonne pour les PoC publics | Moyenne (PoC non vérifiés, à sandboxer avant usage) | Non (pas d'API officielle stable) | Gratuit | ✅ Intégré (enrichissement, croisement CSV) |
| **Radar PoC GitHub** (`app/connectors/github_poc.py`) | Quasi temps réel (cadence ~4 min, dès qu'un repo GitHub est créé/mis à jour avec une CVE dans le nom/la description) | Variable (dépend de l'activité GitHub), mais souvent en avance sur Exploit-DB pour les CVE très récentes | Moyenne (heuristique nom/description, PoC non vérifié - mais l'ID CVE est toujours revalidé par regex avant toute écriture) | Non (token existant recommandé pour le quota de recherche : 10→30 req/min) | Gratuit | ✅ Intégré (poller dédié, fonctionnalité phare) |
| **EPSS (FIRST.org)** | Republié quotidiennement | Couvre la quasi-totalité des CVE notées | Élevée (modèle public, largement utilisé par l'industrie) | Non | Gratuit | ✅ Intégré (enrichissement quotidien) |
| **VulnDB** | Rapide, inclut des vulnérabilités non-CVE / pré-divulgation | Très élevée (valeur ajoutée principale : couverture au-delà du CVE) | Élevée | Oui (commercial) | **Payant** (contrat entreprise) | ❌ Non retenu - outil gratuit uniquement |
| **Bulletins éditeurs (MSRC, Cisco PSIRT, Adobe...)** | Rapide, souvent day-0 avec le patch | Élevée mais fragmentée (un connecteur par éditeur) | Très élevée | Variable | Gratuit | ⏳ Roadmap Phase 3, au cas par cas selon le parc surveillé |
| **nomi-sec/PoC-in-GitHub** (dataset communautaire) | Mise à jour ~quotidienne par leur propre CI | Bon complément/backfill au radar PoC GitHub temps réel | Moyenne (dataset communautaire, non garanti) | Non | Gratuit | ⏳ Roadmap Phase 3 - recoupe en grande partie ce que le radar temps réel couvre déjà |
| **CVE Details / SecurityFocus (scraping)** | Dépend du site, pas de garantie de fraîcheur | Redondant avec NVD/MITRE | Moyenne (pas de contrat d'API, casse à chaque refonte de site) | Non | Gratuit mais fragile | ❌ Non retenu - le rapport effort/valeur est mauvais quand NVD/KEV/GHSA/OSV couvrent déjà le signal structuré |
| **X/Twitter (API officielle)** | Très rapide sur le "buzz" mais non structuré | Faible signal/bruit | Faible (rumeurs, non vérifié) | Oui, **désormais payante** pour la recherche | Payant | ❌ Non retenu - outil gratuit uniquement, voir Mastodon ci-dessous pour un substitut |
| **Mastodon (`infosec.exchange`, hashtags publics)** | Temps réel sur le hashtag, mais signal faible | Faible en couverture, dépend de qui poste | Faible (comme OTX/MISP : contexte informatif, jamais vérifié) | Non (timeline publique, sans clé) | Gratuit | ⏳ Roadmap Phase 3 - substitut gratuit à X/Twitter, informatif uniquement (jamais un déclencheur d'alerte) |

## Recommandation priorisation (si budget/temps limité)

1. **CISA KEV** - le signal le plus actionnable (exploitation confirmée), volume faible donc peu de bruit.
2. **NVD** - la référence pour le scoring CVSS et la couverture générale.
3. **GitHub Advisories** - indispensable si l'infrastructure surveillée inclut des dépendances open source (quasi systématique).
4. **Radar PoC GitHub** - le signal le plus utile pour anticiper une exploitation de masse (CVE sévère + PoC public = fenêtre de risque immédiate).
5. **EPSS** - contextualise la priorité sans configuration ni coût.
6. **OSV** - en complément de GitHub Advisories pour les écosystèmes non-GitHub (PyPI direct, crates.io...).
