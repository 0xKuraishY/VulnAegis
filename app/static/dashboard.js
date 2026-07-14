(() => {
  "use strict";

  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const SEV_SET = new Set(SEV_ORDER);
  const SEV_VAR = { CRITICAL: "--critical-text", HIGH: "--high-text", MEDIUM: "--medium-text", LOW: "--low-text" };
  const PAGE_SIZE = 50;

  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const sevClass = (s) => (SEV_SET.has(s) ? s : "UNKNOWN");
  const isWatchlistReason = (r) => r.startsWith("asset surveillé") || r.startsWith("mot-clé surveillé");

  function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // Toutes les URLs rendues en <a href> proviennent de sources externes (références NVD/GHSA,
  // repos GitHub du radar PoC...) : esc() empêche de casser l'attribut HTML mais n'empêche pas un
  // schéma "javascript:" d'exécuter du code au clic. On n'autorise que http(s), sinon on retombe
  // sur "#" (lien inerte) plutôt que de refuser d'afficher toute la ligne.
  function safeUrl(url) {
    if (typeof url === "string" && /^https?:\/\//i.test(url)) return url;
    return "#";
  }

  // ---------- Internationalisation (FR/EN) ----------

  const I18N = {
    fr: {
      "nav.overview": "Vue d'ensemble", "nav.cves": "CVE", "nav.radar": "Radar PoC",
      "nav.watchlist": "Watchlist", "nav.alerts": "Alertes", "nav.settings": "Paramètres",
      "sidebar.connecting": "Connexion…", "sidebar.apiDocs": "Documentation API",
      "toast.newAlert": "Nouvelle alerte : {cveId}",
      "theme.light": "Thème clair", "theme.system": "Suivre le système", "theme.dark": "Thème sombre",
      "topbar.search": "Rechercher", "topbar.pollNow": "Forcer un poll", "topbar.pollingNow": "Poll en cours…",
      "topbar.updatedAt": "Mis à jour à {time}", "status.connectionError": "Erreur de connexion",
      "bell.title": "Alertes récentes", "bell.unacked": "Alertes non acquittées", "bell.viewAll": "Voir toutes les alertes",

      "page.overview.title": "Vue d'ensemble", "page.overview.desc": "Panorama des vulnérabilités suivies et de leur criticité",
      "page.cves.title": "CVE", "page.cves.desc": "Recherche et filtrage de l'ensemble des vulnérabilités ingérées",
      "page.radar.title": "Radar PoC", "page.radar.desc": "Repos GitHub et exploits découverts en temps réel, CVE la plus récente en premier",
      "page.watchlist.title": "Watchlist", "page.watchlist.desc": "Assets et mots-clés qui déclenchent une alerte prioritaire",
      "page.alerts.title": "Alertes", "page.alerts.desc": "Notifications envoyées et leur statut d'acquittement",
      "page.settings.title": "Paramètres", "page.settings.desc": "Clé API et statut des sources de données",

      "stat.total": "CVE suivies", "stat.kev": "Exploitées (KEV)", "stat.critical": "Critiques",
      "stat.alerts": "Alertes non acquittées", "stat.poc24h": "PoC découverts (24h)",
      "stat.weaponization": "Risque d'exploitation imminente", "stat.epssHigh": "EPSS élevé (≥50%)",
      "stat.unconfirmed": "Non confirmées",

      "chart.byDay": "CVE détectées par jour", "chart.byDay.hint": "14 derniers jours",
      "chart.severity": "Répartition par sévérité",
      "chart.weaponization": "Risque d'exploitation imminente par jour", "chart.weaponization.hint": "PoC + CVE critique/exploitée",
      "chart.epss": "Distribution des scores EPSS",
      "chart.vendors": "Vendeurs les plus représentés", "chart.cwe": "Types de faiblesse (CWE) les plus fréquents",
      "chart.kevByDay": "CVE ajoutées au KEV par jour", "chart.riskDistribution": "Distribution du score de risque",

      "table.risk": "Risque",

      "risk.level.critical": "Critique", "risk.level.high": "Élevé", "risk.level.medium": "Moyen",
      "risk.level.low": "Faible", "risk.level.info": "Info",
      "risk.factor.cvss": "Score CVSS", "risk.factor.kev": "Exploitée activement (KEV)",
      "risk.factor.kev_overdue": "KEV, échéance de remédiation dépassée", "risk.factor.epss": "Probabilité d'exploitation (EPSS)",
      "risk.factor.poc": "PoC public disponible", "risk.factor.poc_severe": "PoC public + CVE critique/exploitée",
      "risk.factor.threat_otx": "Signalée dans des pulses de menace (OTX)", "risk.factor.threat_misp": "Corrélée à des événements MISP",
      "risk.factor.staleness": "Ancienne, sans signal actif récent",

      "filter.search": "Rechercher un ID, un mot-clé…", "filter.allSeverities": "Toutes sévérités",
      "filter.vendor": "Vendeur", "filter.epssMin": "EPSS min (0-1)", "filter.kevOnly": "KEV uniquement",
      "filter.pocOnly": "PoC uniquement", "filter.watchlistOnly": "Watchlist uniquement",
      "filter.apply": "Filtrer", "filter.exportCsv": "Exporter CSV",

      "table.cve": "CVE", "table.severity": "Sévérité", "table.vendorProduct": "Vendeur / Produit",
      "table.seen": "Vu", "table.loadMore": "Charger plus",

      "radar.title": "Découvertes de PoC en temps réel", "radar.hint": "GitHub (radar), Exploit-DB - plus récent en premier",

      "watchlist.title": "Assets et mots-clés surveillés", "watchlist.vendor": "Vendeur (ex: cisco)",
      "watchlist.product": "Produit (ex: ios xe)", "watchlist.keyword": "Mot-clé (ex: log4j)",
      "watchlist.note": "Note", "watchlist.asset": "Asset", "watchlist.keywordTag": "Mot-clé",
      "watchlist.entrySingular": "entrée", "watchlist.entryPlural": "entrées", "watchlist.empty": "Watchlist vide",

      "alerts.title": "Historique des alertes", "alerts.showAck": "Afficher les alertes acquittées",
      "alerts.hideAck": "Masquer les alertes acquittées", "alerts.empty": "Aucune alerte en attente",
      "alerts.acknowledge": "Acquitter", "alerts.acknowledged": "Acquittée", "alerts.escalated": "Escaladée",

      "settings.account": "Compte", "settings.login": "Se connecter", "settings.register": "Créer un compte",
      "settings.registerHint": "Le premier lancement crée l'unique compte administrateur - aucune autre inscription n'est possible ensuite.",
      "settings.registerClosedHint": "L'inscription est fermée : un compte administrateur existe déjà. Utilisez vos identifiants pour vous connecter.",
      "settings.logout": "Se déconnecter", "settings.apiKeys": "Clés API",
      "settings.apiKeys.hint": "Recommandé - individuellement traçable/révocable",
      "settings.apiKeys.loggedOut": "Connectez-vous pour gérer vos clés API.",
      "settings.apiKeyName": "Nom (ex: ci-pipeline)", "settings.apiKeyExpiry": "Expiration (jours, optionnel)",
      "settings.generate": "Générer", "settings.legacyKey": "Clé API statique (legacy)",
      "settings.pasteKey": "Coller la clé API",
      "settings.legacyKeyHint": "Ancien mécanisme à clé unique partagée (<code>API_KEY</code> côté serveur). Préférer les clés API ci-dessus. Stockée uniquement dans ce navigateur (localStorage).",
      "settings.sourceStatus": "Statut des sources", "settings.sync": "Synchroniser", "settings.syncing": "Synchronisation…",
      "settings.sourcesOk": "Toutes les sources OK", "settings.sourceError": "Une source en erreur",
      "settings.neverPolled": "jamais interrogée", "settings.lastPollCount": "CVE au dernier poll",
      "settings.statusOk": "OK", "settings.statusErrShort": "Erreur", "settings.statusPending": "En attente",
      "settings.fetchedNewCounts": "{fetched} récupérées, {new} nouvelles",
      "toast.pollSummary": "{fetched} CVE récupérées, {new} nouvelles, {alerts} alerte(s) envoyée(s)",
      "toast.pollSummaryWithErrors": "{fetched} CVE récupérées, {new} nouvelles - {errors} source(s) en erreur",
      "toast.syncSummary": "\"{name}\" : {fetched} récupérés, {new} nouveaux",
      "toast.syncSummaryError": "\"{name}\" a échoué : {error}",
      "settings.keySaved": "Clé API enregistrée dans ce navigateur", "settings.keyCleared": "Clé API effacée",
      "apiKey.revoked": "révoquée", "apiKey.expired": "expirée", "apiKey.active": "active",
      "apiKey.neverUsed": "jamais utilisée", "apiKey.usedAgo": "utilisée il y a {t}",
      "apiKey.revoke": "Révoquer", "apiKey.empty": "Aucune clé API pour le moment.",
      "apiKey.revokedToast": "Clé révoquée", "apiKey.revokeFailed": "Échec de révocation",
      "apiKey.createFailed": "Échec de création de la clé",
      "apiKey.createdToast": "Clé créée et copiée dans le presse-papier : {key}",

      "common.email": "Email", "common.password": "Mot de passe", "common.save": "Enregistrer",
      "common.clear": "Effacer", "common.add": "Ajouter", "common.loading": "Chargement…",
      "common.copyId": "Copier l'ID", "common.viewJson": "Voir en JSON", "common.addToWatchlist": "Ajouter à la watchlist",
      "common.unauthorized": "Authentification manquante ou invalide - connectez-vous dans Paramètres",
      "common.other": "Autre", "common.delete": "Supprimer",

      "palette.search": "Rechercher une CVE, une page, une action…", "palette.escape": "Échap",
      "palette.noResults": "Aucun résultat", "palette.page": "Page", "palette.action": "Action",

      "drawer.riskScore": "Score de risque", "drawer.riskScoreEmpty": "Données insuffisantes pour un score fiable.",
      "drawer.why": "Pourquoi cette CVE est signalée", "drawer.description": "Description",
      "drawer.noDescription": "Aucune description disponible.", "drawer.details": "Détails",
      "drawer.cvss": "CVSS", "drawer.epssScore": "Score EPSS", "drawer.vendorProduct": "Vendeur / Produit",
      "drawer.published": "Publiée", "drawer.modified": "Modifiée", "drawer.sources": "Sources",
      "drawer.firstSeen": "Vue pour la première fois", "drawer.vector": "Vecteur CVSS",
      "drawer.cwe": "Type de faiblesse (CWE)", "drawer.affectedProducts": "Produits affectés",
      "drawer.affectedProductsCount": "configuration(s) affectée(s)",
      "drawer.kevTitle": "CISA KEV - exploitation active", "drawer.kevAdded": "Ajoutée au catalogue",
      "drawer.kevDue": "Échéance de remédiation", "drawer.kevRansomware": "Usage ransomware connu",
      "drawer.unknown": "Inconnu", "drawer.knownPocs": "PoC connus", "drawer.threatContext": "Contexte menace",
      "drawer.cvssHistory": "Historique CVSS", "drawer.references": "Références",
      "drawer.notFound": "CVE introuvable.",

      "vector.attackVector": "Vecteur d'attaque", "vector.network": "Réseau", "vector.adjacent": "Adjacent",
      "vector.local": "Local", "vector.physical": "Physique",
      "vector.complexity": "Complexité", "vector.low": "Faible", "vector.high": "Élevée",
      "vector.privileges": "Privilèges requis", "vector.none": "Aucun", "vector.lowPriv": "Faibles", "vector.highPriv": "Élevés",
      "vector.userInteraction": "Interaction utilisateur", "vector.noneInteraction": "Aucune", "vector.required": "Requise",
      "vector.scope": "Périmètre", "vector.unchanged": "Inchangé", "vector.changed": "Changé",
      "vector.confidentiality": "Confidentialité", "vector.integrity": "Intégrité", "vector.availability": "Disponibilité",
      "vector.impactNone": "Aucun", "vector.impactLow": "Faible", "vector.impactHigh": "Élevé",

      "badge.new": "Nouveau", "badge.watchlist": "Watchlist", "badge.unconfirmed": "Non confirmée",
      "badge.risk": "Exploitation imminente", "badge.poc": "PoC", "badge.kev": "KEV",
      "badge.overdue": "En retard {n}j", "badge.due": "Échéance {n}j", "severity.unknown": "Inconnue",

      "relTime.now": "à l'instant", "relTime.min": "min", "relTime.hour": "h", "relTime.day": "j", "relTime.ago": "il y a {t}",

      "empty.cves": "Aucune CVE ne correspond à ces filtres", "empty.pocs": "Aucun PoC découvert pour le moment",
      "empty.chart": "Aucune donnée", "empty.watchlistField": "Renseigner au moins un vendeur, un produit ou un mot-clé",
      "empty.loginField": "Renseigner email et mot de passe",

      "toast.watchlistAdded": "Entrée ajoutée à la watchlist", "toast.watchlistDeleted": "Entrée supprimée",
      "toast.alertAcked": "Alerte acquittée", "toast.accountCreated": "Compte créé, vous pouvez vous connecter",
      "toast.loggedIn": "Connecté", "toast.loggedOut": "Déconnecté",
      "toast.syncTriggered": "Synchronisation \"{name}\" déclenchée",
      "toast.loginFailed": "Échec de connexion", "toast.registerFailed": "Échec de création du compte",
      "toast.watchlistAddedVendor": "{vendor} ajouté à la watchlist",
      "drawer.noVendor": "Pas de vendeur identifié pour cette CVE",
      "drawer.copiedToast": "ID copié dans le presse-papiers", "drawer.copyFailed": "Impossible de copier automatiquement",

      "reason.kev": "exploitée activement (CISA KEV)", "reason.poc": "PoC public disponible",
      "reason.weaponization": "PoC public + CVE critique/exploitée = risque d'exploitation imminente",
      "reason.watchlistAsset": "asset surveillé", "reason.watchlistKeyword": "mot-clé surveillé",
      "reason.cvssThreshold": "CVSS {score} >= seuil {threshold}",

      "tooltip.cveOnDay": "{value} CVE le {label}", "tooltip.cveSeverity": "{value} CVE {label}",
      "tooltip.riskOnDay": "{value} CVE à risque le {label}", "tooltip.epssScore": "{value} CVE avec un score EPSS {label}",
      "tooltip.vendorCount": "{label}: {value} CVE", "tooltip.cweCount": "{label}: {value} CVE",
      "tooltip.kevOnDay": "{value} CVE ajoutées au KEV le {label}", "tooltip.riskLevelCount": "{value} CVE de niveau {label}",
    },
    en: {
      "nav.overview": "Overview", "nav.cves": "CVEs", "nav.radar": "PoC Radar",
      "nav.watchlist": "Watchlist", "nav.alerts": "Alerts", "nav.settings": "Settings",
      "sidebar.connecting": "Connecting…", "sidebar.apiDocs": "API Docs",
      "toast.newAlert": "New alert: {cveId}",
      "theme.light": "Light theme", "theme.system": "Follow system", "theme.dark": "Dark theme",
      "topbar.search": "Search", "topbar.pollNow": "Force a poll", "topbar.pollingNow": "Polling…",
      "topbar.updatedAt": "Updated at {time}", "status.connectionError": "Connection error",
      "bell.title": "Recent alerts", "bell.unacked": "Unacknowledged alerts", "bell.viewAll": "View all alerts",

      "page.overview.title": "Overview", "page.overview.desc": "Snapshot of tracked vulnerabilities and their severity",
      "page.cves.title": "CVEs", "page.cves.desc": "Search and filter across every ingested vulnerability",
      "page.radar.title": "PoC Radar", "page.radar.desc": "GitHub repos and exploits discovered in real time, newest CVE first",
      "page.watchlist.title": "Watchlist", "page.watchlist.desc": "Assets and keywords that trigger a priority alert",
      "page.alerts.title": "Alerts", "page.alerts.desc": "Notifications sent and their acknowledgement status",
      "page.settings.title": "Settings", "page.settings.desc": "API key and live source status",

      "stat.total": "Tracked CVEs", "stat.kev": "Exploited (KEV)", "stat.critical": "Critical",
      "stat.alerts": "Unacknowledged alerts", "stat.poc24h": "PoCs discovered (24h)",
      "stat.weaponization": "Imminent exploitation risk", "stat.epssHigh": "High EPSS (≥50%)",
      "stat.unconfirmed": "Unconfirmed",

      "chart.byDay": "CVEs detected per day", "chart.byDay.hint": "last 14 days",
      "chart.severity": "Breakdown by severity",
      "chart.weaponization": "Imminent exploitation risk per day", "chart.weaponization.hint": "PoC + critical/exploited CVE",
      "chart.epss": "EPSS score distribution",
      "chart.vendors": "Most represented vendors", "chart.cwe": "Most frequent weakness types (CWE)",
      "chart.kevByDay": "CVEs added to KEV per day", "chart.riskDistribution": "Risk score distribution",

      "table.risk": "Risk",

      "risk.level.critical": "Critical", "risk.level.high": "High", "risk.level.medium": "Medium",
      "risk.level.low": "Low", "risk.level.info": "Info",
      "risk.factor.cvss": "CVSS score", "risk.factor.kev": "Actively exploited (KEV)",
      "risk.factor.kev_overdue": "KEV, remediation due date overdue", "risk.factor.epss": "Exploitation probability (EPSS)",
      "risk.factor.poc": "Public PoC available", "risk.factor.poc_severe": "Public PoC + critical/exploited CVE",
      "risk.factor.threat_otx": "Reported in threat pulses (OTX)", "risk.factor.threat_misp": "Correlated to MISP events",
      "risk.factor.staleness": "Old, no recent active signal",

      "filter.search": "Search an ID, a keyword…", "filter.allSeverities": "All severities",
      "filter.vendor": "Vendor", "filter.epssMin": "Min EPSS (0-1)", "filter.kevOnly": "KEV only",
      "filter.pocOnly": "PoC only", "filter.watchlistOnly": "Watchlist only",
      "filter.apply": "Filter", "filter.exportCsv": "Export CSV",

      "table.cve": "CVE", "table.severity": "Severity", "table.vendorProduct": "Vendor / Product",
      "table.seen": "Seen", "table.loadMore": "Load more",

      "radar.title": "Real-time PoC discoveries", "radar.hint": "GitHub (radar), Exploit-DB - newest first",

      "watchlist.title": "Monitored assets and keywords", "watchlist.vendor": "Vendor (e.g. cisco)",
      "watchlist.product": "Product (e.g. ios xe)", "watchlist.keyword": "Keyword (e.g. log4j)",
      "watchlist.note": "Note", "watchlist.asset": "Asset", "watchlist.keywordTag": "Keyword",
      "watchlist.entrySingular": "entry", "watchlist.entryPlural": "entries", "watchlist.empty": "Watchlist is empty",

      "alerts.title": "Alert history", "alerts.showAck": "Show acknowledged alerts",
      "alerts.hideAck": "Hide acknowledged alerts", "alerts.empty": "No alerts pending",
      "alerts.acknowledge": "Acknowledge", "alerts.acknowledged": "Acknowledged", "alerts.escalated": "Escalated",

      "settings.account": "Account", "settings.login": "Log in", "settings.register": "Create an account",
      "settings.registerHint": "The first launch creates the single admin account - no further sign-up is possible afterwards.",
      "settings.registerClosedHint": "Sign-up is closed: an admin account already exists. Use your credentials to log in.",
      "settings.logout": "Log out", "settings.apiKeys": "API keys",
      "settings.apiKeys.hint": "Recommended - individually traceable/revocable",
      "settings.apiKeys.loggedOut": "Log in to manage your API keys.",
      "settings.apiKeyName": "Name (e.g. ci-pipeline)", "settings.apiKeyExpiry": "Expiry (days, optional)",
      "settings.generate": "Generate", "settings.legacyKey": "Static API key (legacy)",
      "settings.pasteKey": "Paste the API key",
      "settings.legacyKeyHint": "Legacy single shared-key mechanism (server-side <code>API_KEY</code>). Prefer the API keys above. Stored only in this browser (localStorage).",
      "settings.sourceStatus": "Source status", "settings.sync": "Sync", "settings.syncing": "Syncing…",
      "settings.sourcesOk": "All sources OK", "settings.sourceError": "A source is in error",
      "settings.neverPolled": "never polled", "settings.lastPollCount": "CVEs on last poll",
      "settings.statusOk": "OK", "settings.statusErrShort": "Error", "settings.statusPending": "Pending",
      "settings.fetchedNewCounts": "{fetched} fetched, {new} new",
      "toast.pollSummary": "{fetched} CVEs fetched, {new} new, {alerts} alert(s) sent",
      "toast.pollSummaryWithErrors": "{fetched} CVEs fetched, {new} new - {errors} source(s) in error",
      "toast.syncSummary": "\"{name}\": {fetched} fetched, {new} new",
      "toast.syncSummaryError": "\"{name}\" failed: {error}",
      "settings.keySaved": "API key saved in this browser", "settings.keyCleared": "API key cleared",
      "apiKey.revoked": "revoked", "apiKey.expired": "expired", "apiKey.active": "active",
      "apiKey.neverUsed": "never used", "apiKey.usedAgo": "used {t} ago",
      "apiKey.revoke": "Revoke", "apiKey.empty": "No API key yet.",
      "apiKey.revokedToast": "Key revoked", "apiKey.revokeFailed": "Revocation failed",
      "apiKey.createFailed": "Key creation failed",
      "apiKey.createdToast": "Key created and copied to clipboard: {key}",

      "common.email": "Email", "common.password": "Password", "common.save": "Save",
      "common.clear": "Clear", "common.add": "Add", "common.loading": "Loading…",
      "common.copyId": "Copy ID", "common.viewJson": "View as JSON", "common.addToWatchlist": "Add to watchlist",
      "common.unauthorized": "Missing or invalid authentication - log in from Settings",
      "common.other": "Other", "common.delete": "Delete",

      "palette.search": "Search a CVE, a page, an action…", "palette.escape": "Esc",
      "palette.noResults": "No results", "palette.page": "Page", "palette.action": "Action",

      "drawer.riskScore": "Risk score", "drawer.riskScoreEmpty": "Not enough data for a reliable score.",
      "drawer.why": "Why this CVE is flagged", "drawer.description": "Description",
      "drawer.noDescription": "No description available.", "drawer.details": "Details",
      "drawer.cvss": "CVSS", "drawer.epssScore": "EPSS score", "drawer.vendorProduct": "Vendor / Product",
      "drawer.published": "Published", "drawer.modified": "Modified", "drawer.sources": "Sources",
      "drawer.firstSeen": "First seen", "drawer.vector": "CVSS vector",
      "drawer.cwe": "Weakness type (CWE)", "drawer.affectedProducts": "Affected products",
      "drawer.affectedProductsCount": "affected configuration(s)",
      "drawer.kevTitle": "CISA KEV - actively exploited", "drawer.kevAdded": "Added to catalog",
      "drawer.kevDue": "Remediation due date", "drawer.kevRansomware": "Known ransomware use",
      "drawer.unknown": "Unknown", "drawer.knownPocs": "Known PoCs", "drawer.threatContext": "Threat context",
      "drawer.cvssHistory": "CVSS history", "drawer.references": "References",
      "drawer.notFound": "CVE not found.",

      "vector.attackVector": "Attack vector", "vector.network": "Network", "vector.adjacent": "Adjacent",
      "vector.local": "Local", "vector.physical": "Physical",
      "vector.complexity": "Complexity", "vector.low": "Low", "vector.high": "High",
      "vector.privileges": "Privileges required", "vector.none": "None", "vector.lowPriv": "Low", "vector.highPriv": "High",
      "vector.userInteraction": "User interaction", "vector.noneInteraction": "None", "vector.required": "Required",
      "vector.scope": "Scope", "vector.unchanged": "Unchanged", "vector.changed": "Changed",
      "vector.confidentiality": "Confidentiality", "vector.integrity": "Integrity", "vector.availability": "Availability",
      "vector.impactNone": "None", "vector.impactLow": "Low", "vector.impactHigh": "High",

      "badge.new": "New", "badge.watchlist": "Watchlist", "badge.unconfirmed": "Unconfirmed",
      "badge.risk": "Imminent exploitation", "badge.poc": "PoC", "badge.kev": "KEV",
      "badge.overdue": "{n}d overdue", "badge.due": "Due in {n}d", "severity.unknown": "Unknown",

      "relTime.now": "just now", "relTime.min": "min", "relTime.hour": "h", "relTime.day": "d", "relTime.ago": "{t} ago",

      "empty.cves": "No CVE matches these filters", "empty.pocs": "No PoC discovered yet",
      "empty.chart": "No data", "empty.watchlistField": "Provide at least a vendor, a product, or a keyword",
      "empty.loginField": "Enter an email and a password",

      "toast.watchlistAdded": "Entry added to the watchlist", "toast.watchlistDeleted": "Entry deleted",
      "toast.alertAcked": "Alert acknowledged", "toast.accountCreated": "Account created, you can now log in",
      "toast.loggedIn": "Logged in", "toast.loggedOut": "Logged out",
      "toast.syncTriggered": "\"{name}\" sync triggered",
      "toast.loginFailed": "Login failed", "toast.registerFailed": "Account creation failed",
      "toast.watchlistAddedVendor": "{vendor} added to the watchlist",
      "drawer.noVendor": "No vendor identified for this CVE",
      "drawer.copiedToast": "ID copied to clipboard", "drawer.copyFailed": "Could not copy automatically",

      "reason.kev": "actively exploited (CISA KEV)", "reason.poc": "Public PoC available",
      "reason.weaponization": "Public PoC + critical/exploited CVE = imminent exploitation risk",
      "reason.watchlistAsset": "monitored asset", "reason.watchlistKeyword": "monitored keyword",
      "reason.cvssThreshold": "CVSS {score} >= threshold {threshold}",

      "tooltip.cveOnDay": "{value} CVEs on {label}", "tooltip.cveSeverity": "{value} {label} CVEs",
      "tooltip.riskOnDay": "{value} at-risk CVEs on {label}", "tooltip.epssScore": "{value} CVEs with an EPSS score of {label}",
      "tooltip.vendorCount": "{label}: {value} CVEs", "tooltip.cweCount": "{label}: {value} CVEs",
      "tooltip.kevOnDay": "{value} CVEs added to KEV on {label}", "tooltip.riskLevelCount": "{value} {label} CVEs",
    },
  };

  const LANG_STORAGE = "vulnaegis_lang";
  let currentLang = localStorage.getItem(LANG_STORAGE) || "fr";

  function t(key, vars) {
    let str = (I18N[currentLang] && I18N[currentLang][key]) || I18N.fr[key] || key;
    if (vars) Object.entries(vars).forEach(([k, v]) => { str = str.replace(new RegExp(`\\{${k}\\}`, "g"), v); });
    return str;
  }

  const dateLocale = () => (currentLang === "en" ? "en-GB" : "fr-FR");

  // Traduit une raison d'alerte générée côté serveur (toujours en français, cf. app/alerting/rules.py)
  // vers la langue d'affichage courante. Les patterns paramétrés (CVSS, watchlist) sont reconnus par
  // préfixe/regex ; une raison qui ne correspond à aucun pattern connu est affichée telle quelle.
  function translateReason(reason) {
    if (currentLang === "fr") return reason;
    if (reason === "exploitée activement (CISA KEV)") return t("reason.kev");
    if (reason === "PoC public disponible") return t("reason.poc");
    if (reason === "PoC public + CVE critique/exploitée = risque d'exploitation imminente") return t("reason.weaponization");
    let m = reason.match(/^CVSS ([\d.]+) >= seuil ([\d.]+)$/);
    if (m) return t("reason.cvssThreshold", { score: m[1], threshold: m[2] });
    m = reason.match(/^asset surveillé: (.+)$/);
    if (m) return `${t("reason.watchlistAsset")}: ${m[1]}`;
    m = reason.match(/^mot-clé surveillé: (.+)$/);
    if (m) return `${t("reason.watchlistKeyword")}: ${m[1]}`;
    return reason;
  }

  function applyLanguage(lang) {
    currentLang = lang;
    localStorage.setItem(LANG_STORAGE, lang);
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.innerHTML = t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.querySelectorAll("[data-i18n-title]").forEach((el) => { el.title = t(el.dataset.i18nTitle); });
    document.querySelectorAll("#lang-toggle button").forEach((b) => {
      b.classList.toggle("active", b.dataset.langValue === lang);
    });
    const activeNav = document.querySelector(".nav-item[data-page].active");
    if (activeNav) goToPage(activeNav.dataset.page);
    refreshAll().catch(() => {});
    if (currentDrawerCve) renderDrawer(currentDrawerCve);
    if (!getJwt()) refreshRegisterAvailability().catch(() => {});
  }

  // ---------- Theme ----------

  const THEME_STORAGE = "vulnaegis_theme";

  function applyTheme(value) {
    if (value === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", value);
    document.querySelectorAll("#theme-toggle button").forEach((b) => {
      b.classList.toggle("active", b.dataset.themeValue === value);
    });
  }
  applyTheme(localStorage.getItem(THEME_STORAGE) || "system");
  document.querySelectorAll("#theme-toggle button").forEach((btn) => {
    btn.addEventListener("click", () => {
      localStorage.setItem(THEME_STORAGE, btn.dataset.themeValue);
      applyTheme(btn.dataset.themeValue);
    });
  });

  document.querySelectorAll("#lang-toggle button").forEach((btn) => {
    btn.addEventListener("click", () => applyLanguage(btn.dataset.langValue));
  });

  // ---------- Pages / navigation ----------

  // Sources "structurées" qui complètent une fiche CVE (métadonnées officielles) - même logique
  // que app.ingest.STRUCTURED_SOURCES côté serveur. Une CVE vue uniquement par une source de
  // découverte de PoC est une "stub" en attente de confirmation par une vraie source.
  const STRUCTURED_SOURCES = new Set(["nvd", "cisa_kev", "github_advisories"]);
  const isUnconfirmed = (c) => !(c.sources || []).some((s) => STRUCTURED_SOURCES.has(s));

  const PAGE_STORAGE = "vulnaegis_page";
  const VALID_PAGES = new Set(["overview", "cves", "radar", "watchlist", "alerts", "settings"]);

  function goToPage(page) {
    document.querySelectorAll(".nav-item[data-page]").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
    document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${page}`));
    document.getElementById("page-title").textContent = t(`page.${page}.title`);
    document.getElementById("page-desc").textContent = t(`page.${page}.desc`);
    localStorage.setItem(PAGE_STORAGE, page);
  }

  document.querySelectorAll(".nav-item[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => goToPage(btn.dataset.page));
  });
  document.querySelectorAll("[data-goto-page]").forEach((el) => {
    el.addEventListener("click", (e) => { e.preventDefault(); closeBell(); goToPage(el.dataset.gotoPage); });
  });

  // Restaure l'onglet actif au chargement (survit à un F5) plutôt que de revenir sur Vue
  // d'ensemble à chaque rafraîchissement - le HTML marque "overview" actif par défaut, donc ce
  // n'est utile que si un autre onglet était mémorisé.
  const savedPage = localStorage.getItem(PAGE_STORAGE);
  if (savedPage && VALID_PAGES.has(savedPage)) goToPage(savedPage);

  // ---------- Auth (JWT + clé API legacy) ----------

  const KEY_STORAGE = "vulnaegis_api_key";
  const JWT_STORAGE = "vulnaegis_jwt";
  const getApiKey = () => localStorage.getItem(KEY_STORAGE) || "";
  const getJwt = () => localStorage.getItem(JWT_STORAGE) || "";
  const setJwt = (token) => localStorage.setItem(JWT_STORAGE, token);
  const clearJwt = () => localStorage.removeItem(JWT_STORAGE);

  // JWT prioritaire sur la clé API statique legacy si les deux sont présents.
  const authHeaders = () => {
    const token = getJwt();
    if (token) return { Authorization: `Bearer ${token}` };
    const key = getApiKey();
    return key ? { "X-API-Key": key } : {};
  };
  document.getElementById("key-input").value = getApiKey();

  // ---------- Toasts ----------

  function toast(message, kind = "info") {
    const stack = document.getElementById("toast-stack");
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  // ---------- Fetch helpers ----------

  // FastAPI renvoie `detail` sous deux formes différentes selon l'origine de l'erreur : une
  // chaîne pour les HTTPException levées explicitement par nos routes (ex: "Email ou mot de passe
  // invalide"), mais un tableau d'objets {msg, loc, type...} pour les erreurs de validation
  // Pydantic (422, ex: email mal formé). Sans cette distinction, `new Error(detail)` stringifie
  // le tableau en "[object Object]" - illisible pour l'utilisateur.
  function extractErrorMessage(body, fallback) {
    const detail = body && body.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length) {
      return detail.map((d) => (d && typeof d === "object" && d.msg) ? d.msg : String(d)).join(" ; ");
    }
    return fallback;
  }

  async function apiGet(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`${url} -> ${resp.status}`);
    return resp.json();
  }

  async function apiWrite(url, options = {}) {
    const resp = await fetch(url, {
      ...options,
      headers: { "Content-Type": "application/json", ...authHeaders(), ...(options.headers || {}) },
    });
    if (resp.status === 401) {
      toast(t("common.unauthorized"), "error");
      throw new Error("unauthorized");
    }
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(extractErrorMessage(body, `${url} -> ${resp.status}`));
    }
    return resp.status === 204 ? null : resp.json();
  }

  // ---------- Time helpers ----------

  function relativeTime(iso) {
    if (!iso) return "–";
    const diffMs = Date.now() - new Date(iso + "Z").getTime();
    const s = Math.max(0, Math.floor(diffMs / 1000));
    if (s < 60) return t("relTime.now");
    const m = Math.floor(s / 60);
    if (m < 60) return `${m} ${t("relTime.min")}`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} ${t("relTime.hour")}`;
    const d = Math.floor(h / 24);
    return `${d} ${t("relTime.day")}`;
  }

  function daysUntil(iso) {
    if (!iso) return null;
    const diffMs = new Date(iso + "Z").getTime() - Date.now();
    return Math.ceil(diffMs / 86400000);
  }

  function kevDueBadge(cve) {
    if (!cve.is_kev) return "";
    if (!cve.kev_due_date) return `<span class="badge UNKNOWN">${t("badge.kev")}</span>`;
    const days = daysUntil(cve.kev_due_date);
    if (days < 0) return `<span class="badge due-overdue">${t("badge.overdue", { n: Math.abs(days) })}</span>`;
    if (days <= 3) return `<span class="badge due-soon">${t("badge.due", { n: days })}</span>`;
    return `<span class="badge due-ok">${t("badge.due", { n: days })}</span>`;
  }

  function isNew(cve) {
    return (Date.now() - new Date(cve.first_seen + "Z").getTime()) < 24 * 3600 * 1000;
  }

  // ---------- Tooltip ----------

  const tooltipEl = document.getElementById("tooltip");
  function showTooltip(evt, text) {
    tooltipEl.textContent = text;
    tooltipEl.style.display = "block";
    tooltipEl.style.left = `${evt.clientX + 12}px`;
    tooltipEl.style.top = `${evt.clientY + 12}px`;
  }
  function hideTooltip() { tooltipEl.style.display = "none"; }

  // ---------- Bar charts ----------

  function renderBarChart(el, entries, { colorFor, tooltipFor, onClick } = {}) {
    el.innerHTML = "";
    if (!entries.length) {
      el.innerHTML = `<div class="muted" style="align-self:center;margin:auto;font-size:13px;">${t("empty.chart")}</div>`;
      return;
    }
    const max = Math.max(1, ...entries.map(([, v]) => v));
    entries.forEach(([label, value]) => {
      const col = document.createElement("div");
      col.className = onClick ? "bar-col clickable" : "bar-col";
      const heightPct = Math.max(3, Math.round((value / max) * 100));
      const color = colorFor ? colorFor(label) : cssVar("--accent");

      const count = document.createElement("div");
      count.className = "bar-count tabular";
      count.textContent = value;

      const bar = document.createElement("div");
      bar.className = "bar";
      bar.style.height = `${heightPct}%`;
      bar.style.background = color;

      const lbl = document.createElement("div");
      lbl.className = "bar-label";
      lbl.textContent = label;

      col.append(count, bar, lbl);
      col.addEventListener("mousemove", (e) => showTooltip(e, tooltipFor ? tooltipFor(label, value) : `${label}: ${value}`));
      col.addEventListener("mouseleave", hideTooltip);
      if (onClick) col.addEventListener("click", () => onClick(label));
      el.appendChild(col);
    });
  }

  // ---------- Stats ----------

  const EPSS_BUCKET_VAR = {
    "0-1%": "--low-text", "1-10%": "--low-text", "10-50%": "--medium-text",
    "50-90%": "--high-text", "90-100%": "--critical-text",
  };

  const RISK_LEVEL_ORDER = ["critical", "high", "medium", "low", "info"];
  const RISK_LEVEL_VAR = {
    critical: "--critical-text", high: "--high-text", medium: "--medium-text",
    low: "--low-text", info: "--unknown-text",
  };

  // Rendu pur (aucun fetch) : sépare la récupération des données (loadStats) de leur affichage,
  // pour que d'autres sources - notamment les patches poussés par WebSocket - puissent
  // rafraîchir les graphiques sans refaire un appel réseau complet.
  function applyStats(stats) {
    document.getElementById("stat-total").textContent = stats.total_cves;
    document.getElementById("stat-kev").textContent = stats.kev_count;
    document.getElementById("stat-critical").textContent = stats.by_severity.CRITICAL || 0;
    document.getElementById("stat-weaponization").textContent = stats.weaponization_risk_count;
    document.getElementById("stat-epss-high").textContent = stats.epss_high_risk_count;
    document.getElementById("stat-unconfirmed").textContent = stats.unconfirmed_count;

    const byDayEntries = Object.entries(stats.by_day).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([d, v]) => [d.slice(5), v]);
    renderBarChart(document.getElementById("chart-by-day"), byDayEntries, {
      tooltipFor: (label, value) => t("tooltip.cveOnDay", { value, label }),
    });

    const severityEntries = SEV_ORDER.filter((k) => stats.by_severity[k]).map((k) => [k, stats.by_severity[k]]);
    renderBarChart(document.getElementById("chart-severity"), severityEntries, {
      colorFor: (label) => cssVar(SEV_VAR[label] || "--unknown-text"),
      tooltipFor: (label, value) => t("tooltip.cveSeverity", { value, label: label.toLowerCase() }),
      onClick: (label) => {
        goToPage("cves");
        document.getElementById("f-severity").value = label;
        loadCves().catch((e) => toast(e.message, "error"));
      },
    });

    const weaponizationEntries = Object.entries(stats.weaponization_by_day).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([d, v]) => [d.slice(5), v]);
    renderBarChart(document.getElementById("chart-weaponization"), weaponizationEntries, {
      colorFor: () => cssVar("--critical-text"),
      tooltipFor: (label, value) => t("tooltip.riskOnDay", { value, label }),
    });

    const epssEntries = Object.entries(stats.epss_distribution);
    renderBarChart(document.getElementById("chart-epss"), epssEntries, {
      colorFor: (label) => cssVar(EPSS_BUCKET_VAR[label] || "--accent"),
      tooltipFor: (label, value) => t("tooltip.epssScore", { value, label }),
    });

    const vendorEntries = Object.entries(stats.top_vendors).slice(0, 10);
    renderBarChart(document.getElementById("chart-vendors"), vendorEntries, {
      tooltipFor: (label, value) => t("tooltip.vendorCount", { value, label }),
      onClick: (label) => {
        goToPage("cves");
        document.getElementById("f-vendor").value = label;
        loadCves().catch((e) => toast(e.message, "error"));
      },
    });

    const cweEntries = Object.entries(stats.top_cwe);
    renderBarChart(document.getElementById("chart-cwe"), cweEntries, {
      tooltipFor: (label, value) => t("tooltip.cweCount", { value, label }),
    });

    const kevByDayEntries = Object.entries(stats.kev_by_day || {}).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([d, v]) => [d.slice(5), v]);
    renderBarChart(document.getElementById("chart-kev-by-day"), kevByDayEntries, {
      colorFor: () => cssVar("--critical-text"),
      tooltipFor: (label, value) => t("tooltip.kevOnDay", { value, label }),
    });

    const riskDistribution = stats.risk_distribution || {};
    const riskLevelByLabel = {};
    const riskEntries = RISK_LEVEL_ORDER.filter((k) => riskDistribution[k]).map((k) => {
      const label = t(`risk.level.${k}`);
      riskLevelByLabel[label] = k;
      return [label, riskDistribution[k]];
    });
    renderBarChart(document.getElementById("chart-risk-distribution"), riskEntries, {
      colorFor: (label) => cssVar(RISK_LEVEL_VAR[riskLevelByLabel[label]] || "--accent"),
      tooltipFor: (label, value) => t("tooltip.riskLevelCount", { value, label }),
      onClick: () => {
        goToPage("cves");
        sortField = "risk_score";
        sortDir = "desc";
        loadCves().catch((e) => toast(e.message, "error"));
      },
    });
  }

  async function loadStats() {
    applyStats(await apiGet("/api/cves/stats"));
  }

  // ---------- CVE table ----------

  let sortField = "last_seen";
  let sortDir = "desc";
  let cveOffset = 0;

  function updateSortIndicators() {
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.querySelector(".sort-arrow")?.remove();
      if (th.dataset.sort === sortField) {
        const arrow = document.createElement("span");
        arrow.className = "sort-arrow";
        arrow.textContent = sortDir === "asc" ? "↑" : "↓";
        th.appendChild(arrow);
      }
    });
  }

  function cveParams(offset) {
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset), sort: sortField, direction: sortDir });
    const q = document.getElementById("f-q").value.trim();
    const severity = document.getElementById("f-severity").value;
    const vendor = document.getElementById("f-vendor").value.trim();
    const epssMin = document.getElementById("f-epss-min").value.trim();
    const kevOnly = document.getElementById("f-kev").checked;
    const pocOnly = document.getElementById("f-poc").checked;
    const watchlistOnly = document.getElementById("f-watchlist").checked;
    if (q) params.set("q", q);
    if (severity) params.set("severity", severity);
    if (vendor) params.set("vendor", vendor);
    if (epssMin) params.set("epss_min", epssMin);
    if (kevOnly) params.set("is_kev", "true");
    if (pocOnly) params.set("has_poc", "true");
    if (watchlistOnly) params.set("watchlist_only", "true");
    return params;
  }

  // Le niveau de risque réutilise les classes de badge de sévérité existantes
  // (CRITICAL/HIGH/MEDIUM/LOW), "info" retombe sur le style neutre UNKNOWN.
  const RISK_LEVEL_CLASS = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "UNKNOWN" };

  function riskBreakdownText(c) {
    if (!c.risk_breakdown || !c.risk_breakdown.length) return "";
    return c.risk_breakdown
      .map((item) => `${t(`risk.factor.${item.factor}`)}: ${item.points > 0 ? "+" : ""}${item.points}`)
      .join("\n");
  }

  function riskBadgeHtml(c) {
    const cls = RISK_LEVEL_CLASS[c.risk_level] || "UNKNOWN";
    return `<span class="badge ${cls} risk-score-badge" data-risk-breakdown="${esc(riskBreakdownText(c))}">${c.risk_score}</span>`;
  }

  function cveRowHtml(c) {
    const sev = sevClass(c.severity);
    const vp = [c.vendor, c.product].filter(Boolean).join(" / ") || "–";
    const flags = [];
    if (isNew(c)) flags.push(`<span class="badge new">${t("badge.new")}</span>`);
    if (c.is_weaponization_risk) flags.push(`<span class="badge risk">${t("badge.risk")}</span>`);
    else if (c.has_poc) flags.push(`<span class="badge watchlist">${t("badge.poc")}</span>`);
    if (c.is_flagged && c.flag_reasons.some(isWatchlistReason)) flags.push(`<span class="badge watchlist">${t("badge.watchlist")}</span>`);
    if (isUnconfirmed(c)) flags.push(`<span class="badge unconfirmed">${t("badge.unconfirmed")}</span>`);
    return `
      <tr data-cve-id="${esc(c.cve_id)}">
        <td class="id-cell">${esc(c.cve_id)}</td>
        <td><span class="badge ${sev}">${esc(c.severity) || t("severity.unknown")}</span></td>
        <td class="tabular">${c.cvss_score ?? "–"}</td>
        <td class="tabular">${riskBadgeHtml(c)}</td>
        <td>${esc(vp)}</td>
        <td>${kevDueBadge(c)}</td>
        <td><div class="row-flags">${flags.join("")}</div></td>
        <td class="muted" title="${esc(c.last_seen)}">${relativeTime(c.last_seen)}</td>
      </tr>`;
  }

  function bindSingleRowEvents(tr) {
    tr.addEventListener("click", () => openDrawer(tr.dataset.cveId));
    tr.querySelectorAll(".risk-score-badge").forEach((badge) => {
      const text = badge.dataset.riskBreakdown;
      if (!text) return;
      badge.addEventListener("mouseenter", (e) => { e.stopPropagation(); showTooltip(e, text); });
      badge.addEventListener("mousemove", (e) => { e.stopPropagation(); showTooltip(e, text); });
      badge.addEventListener("mouseleave", (e) => { e.stopPropagation(); hideTooltip(); });
    });
  }

  function bindRowClicks(tbody) {
    tbody.querySelectorAll("tr[data-cve-id]").forEach(bindSingleRowEvents);
  }

  async function loadCves() {
    cveOffset = 0;
    const severity = document.getElementById("f-severity").value;
    const kevOnly = document.getElementById("f-kev").checked;
    document.getElementById("export-csv").href =
      `/api/cves/export?format=csv${severity ? `&severity=${severity}` : ""}${kevOnly ? "&is_kev=true" : ""}`;

    const cves = await apiGet(`/api/cves?${cveParams(0).toString()}`);
    const tbody = document.getElementById("cve-rows");

    if (!cves.length) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="8">${t("empty.cves")}</td></tr>`;
      document.getElementById("load-more-row").style.display = "none";
      return;
    }

    tbody.innerHTML = cves.map(cveRowHtml).join("");
    bindRowClicks(tbody);
    updateSortIndicators();
    document.getElementById("load-more-row").style.display = cves.length === PAGE_SIZE ? "flex" : "none";
  }

  document.getElementById("load-more").addEventListener("click", async () => {
    cveOffset += PAGE_SIZE;
    const cves = await apiGet(`/api/cves?${cveParams(cveOffset).toString()}`);
    const tbody = document.getElementById("cve-rows");
    const tmp = document.createElement("tbody");
    tmp.innerHTML = cves.map(cveRowHtml).join("");
    bindRowClicks(tmp);
    Array.from(tmp.children).forEach((tr) => tbody.appendChild(tr));
    document.getElementById("load-more-row").style.display = cves.length === PAGE_SIZE ? "flex" : "none";
  });

  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (sortField === field) sortDir = sortDir === "asc" ? "desc" : "asc";
      else { sortField = field; sortDir = "desc"; }
      loadCves().catch((e) => toast(e.message, "error"));
    });
  });

  document.getElementById("apply-filters").addEventListener("click", () => loadCves().catch((e) => toast(e.message, "error")));
  document.getElementById("f-q").addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadCves().catch((err) => toast(err.message, "error"));
  });

  // ---------- CVE detail drawer ----------

  const CHECK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M4 12l6 6L20 6"/></svg>';

  function cvssMetricLabels() {
    return {
      AV: { name: t("vector.attackVector"), N: t("vector.network"), A: t("vector.adjacent"), L: t("vector.local"), P: t("vector.physical") },
      AC: { name: t("vector.complexity"), L: t("vector.low"), H: t("vector.high") },
      PR: { name: t("vector.privileges"), N: t("vector.none"), L: t("vector.lowPriv"), H: t("vector.highPriv") },
      UI: { name: t("vector.userInteraction"), N: t("vector.noneInteraction"), R: t("vector.required") },
      S: { name: t("vector.scope"), U: t("vector.unchanged"), C: t("vector.changed") },
      C: { name: t("vector.confidentiality"), N: t("vector.impactNone"), L: t("vector.impactLow"), H: t("vector.impactHigh") },
      I: { name: t("vector.integrity"), N: t("vector.impactNone"), L: t("vector.impactLow"), H: t("vector.impactHigh") },
      A: { name: t("vector.availability"), N: t("vector.impactNone"), L: t("vector.impactLow"), H: t("vector.impactHigh") },
    };
  }

  function renderVectorChips(vector) {
    if (!vector) return "";
    const labels = cvssMetricLabels();
    const parts = vector.replace(/^CVSS:[\d.]+\//, "").split("/");
    return parts.map((part) => {
      const [key, val] = part.split(":");
      const meta = labels[key];
      if (!meta || !meta[val]) return "";
      return `<span class="vector-chip">${esc(meta.name)}: <b>${esc(meta[val])}</b></span>`;
    }).join("");
  }

  function renderCweChips(cweIds) {
    if (!cweIds || !cweIds.length) return "";
    return cweIds.map((id) => `<span class="vector-chip">${esc(id)}</span>`).join("");
  }

  function renderCpeList(cpes) {
    if (!cpes || !cpes.length) return "";
    const items = cpes.map((c) => `<div>${esc(c)}</div>`).join("");
    return `<details><summary>${cpes.length} ${t("drawer.affectedProductsCount")}</summary><div class="cpe-list">${items}</div></details>`;
  }

  function renderReferencesGrouped(referencesMeta, fallbackRefs) {
    if (referencesMeta && referencesMeta.length) {
      const groups = new Map();
      referencesMeta.forEach((r) => {
        const tags = r.tags && r.tags.length ? r.tags : [t("common.other")];
        tags.forEach((tag) => {
          if (!groups.has(tag)) groups.set(tag, []);
          groups.get(tag).push(r.url);
        });
      });
      return Array.from(groups.entries()).map(([tag, urls]) => `
        <div class="ref-group">
          <div class="ref-tag">${esc(tag)}</div>
          <div class="ref-list">${urls.map((u) => `<a href="${esc(safeUrl(u))}" target="_blank" rel="noopener">${esc(u)}</a>`).join("")}</div>
        </div>`).join("");
    }
    if (fallbackRefs && fallbackRefs.length) {
      return `<div class="ref-list">${fallbackRefs.map((r) => `<a href="${esc(safeUrl(r))}" target="_blank" rel="noopener">${esc(r)}</a>`).join("")}</div>`;
    }
    return "";
  }

  function renderPocList(pocLinksDetailed, legacyLinks) {
    if (pocLinksDetailed && pocLinksDetailed.length) {
      return pocLinksDetailed.map((p) => `
        <div class="poc-row">
          <span class="tag">${esc(p.source)}</span>
          <a href="${esc(safeUrl(p.url))}" target="_blank" rel="noopener">${esc(p.repo_full_name || p.url)}</a>
          ${p.stars != null ? `<span class="stars">★ ${p.stars}</span>` : ""}
          <span class="muted" style="margin-left:auto;font-size:11.5px;">${relativeTime(p.discovered_at)}</span>
        </div>`).join("");
    }
    if (legacyLinks && legacyLinks.length) {
      return legacyLinks.map((u) => `<div class="poc-row"><a href="${esc(safeUrl(u))}" target="_blank" rel="noopener">${esc(u)}</a></div>`).join("");
    }
    return "";
  }

  function renderThreatContext(threatContext) {
    if (!threatContext || !Object.keys(threatContext).length) return "";
    const rows = Object.entries(threatContext).map(([source, data]) => {
      const parts = Object.entries(data || {}).map(([k, v]) => `${esc(k)}: ${esc(Array.isArray(v) ? v.join(", ") : v)}`);
      return `<dt>${esc(source)}</dt><dd>${parts.join(" · ") || "–"}</dd>`;
    }).join("");
    return `<div class="drawer-section"><h3>${t("drawer.threatContext")}</h3><dl class="kv-grid">${rows}</dl></div>`;
  }

  function renderCvssHistory(history) {
    if (!history || history.length < 2) return "";
    const rows = history.map((h) => `<dt>${new Date(h.recorded_at + "Z").toLocaleDateString(dateLocale())}</dt><dd>${h.cvss_score ?? "–"} (${esc(h.severity) || t("severity.unknown")})</dd>`).join("");
    return `<div class="drawer-section"><h3>${t("drawer.cvssHistory")}</h3><dl class="kv-grid">${rows}</dl></div>`;
  }

  let currentDrawerCve = null;

  async function openDrawer(cveId) {
    const overlay = document.getElementById("drawer-overlay");
    const drawer = document.getElementById("drawer");
    overlay.classList.add("open");
    drawer.classList.add("open");
    document.getElementById("drawer-title").textContent = cveId;
    document.getElementById("drawer-body").innerHTML = `<div class="muted">${t("common.loading")}</div>`;
    document.getElementById("drawer-json").href = `/api/cves/${cveId}`;

    try {
      const c = await apiGet(`/api/cves/${cveId}`);
      currentDrawerCve = c;
      renderDrawer(c);
    } catch (e) {
      document.getElementById("drawer-body").innerHTML = `<div class="muted">${t("drawer.notFound")}</div>`;
    }
  }

  function renderDrawer(c) {
    const sev = sevClass(c.severity);
    const unconfirmedBadge = isUnconfirmed(c) ? ` <span class="badge unconfirmed">${t("badge.unconfirmed")}</span>` : "";
    document.getElementById("drawer-title").innerHTML =
      `${esc(c.cve_id)} <span class="badge ${sev}">${esc(c.severity) || t("severity.unknown")}</span>${unconfirmedBadge}`;

    const reasons = c.flag_reasons.map((r) => `<div class="reason-item">${CHECK_ICON}<span>${esc(translateReason(r))}</span></div>`).join("");
    const vectorChips = renderVectorChips(c.cvss_vector);
    const cweChips = renderCweChips(c.cwe_ids);
    const cpeList = renderCpeList(c.affected_cpes);
    const refsHtml = renderReferencesGrouped(c.references_meta, c.references);
    const pocHtml = renderPocList(c.poc_links_detailed, c.poc_links);

    let kevSection = "";
    if (c.is_kev) {
      const badge = kevDueBadge(c);
      kevSection = `
        <div class="drawer-section">
          <h3>${t("drawer.kevTitle")}</h3>
          <dl class="kv-grid">
            <dt>${t("drawer.kevAdded")}</dt><dd>${c.kev_date_added ? new Date(c.kev_date_added + "Z").toLocaleDateString(dateLocale()) : "–"}</dd>
            <dt>${t("drawer.kevDue")}</dt><dd>${badge || "–"}</dd>
            <dt>${t("drawer.kevRansomware")}</dt><dd>${esc(c.kev_ransomware_use) || t("drawer.unknown")}</dd>
          </dl>
        </div>`;
    }

    const riskItems = (c.risk_breakdown || [])
      .map((item) => `<div class="reason-item">${CHECK_ICON}<span>${esc(t(`risk.factor.${item.factor}`))} (${item.points > 0 ? "+" : ""}${item.points})</span></div>`)
      .join("");
    const riskSection = `
      <div class="drawer-section">
        <h3>${t("drawer.riskScore")} <span class="badge ${RISK_LEVEL_CLASS[c.risk_level] || "UNKNOWN"}" style="margin-left:6px;">${c.risk_score}/100 · ${t(`risk.level.${c.risk_level}`)}</span></h3>
        ${riskItems ? `<div class="reason-list">${riskItems}</div>` : `<div class="muted">${t("drawer.riskScoreEmpty")}</div>`}
      </div>`;

    document.getElementById("drawer-body").innerHTML = `
      ${riskSection}
      ${reasons ? `<div class="drawer-section"><h3>${t("drawer.why")}</h3><div class="reason-list">${reasons}</div></div>` : ""}

      <div class="drawer-section">
        <h3>${t("drawer.description")}</h3>
        <div class="drawer-desc">${esc(c.description) || t("drawer.noDescription")}</div>
      </div>

      <div class="drawer-section">
        <h3>${t("drawer.details")}</h3>
        <dl class="kv-grid">
          <dt>${t("drawer.cvss")}</dt><dd>${c.cvss_score ?? "–"}</dd>
          <dt>${t("drawer.epssScore")}</dt><dd>${c.epss_score != null ? `${(c.epss_score * 100).toFixed(1)}% (percentile ${(c.epss_percentile * 100).toFixed(0)})` : "–"}</dd>
          <dt>${t("drawer.vendorProduct")}</dt><dd>${esc([c.vendor, c.product].filter(Boolean).join(" / ") || "–")}</dd>
          <dt>${t("drawer.published")}</dt><dd>${c.published_date ? new Date(c.published_date + "Z").toLocaleDateString(dateLocale()) : "–"}</dd>
          <dt>${t("drawer.modified")}</dt><dd>${c.last_modified_date ? new Date(c.last_modified_date + "Z").toLocaleDateString(dateLocale()) : "–"}</dd>
          <dt>${t("drawer.sources")}</dt><dd>${esc(c.sources.join(", ") || "–")}</dd>
          <dt>${t("drawer.firstSeen")}</dt><dd>${relativeTime(c.first_seen)}</dd>
        </dl>
      </div>

      ${vectorChips ? `<div class="drawer-section"><h3>${t("drawer.vector")}</h3><div class="vector-chips">${vectorChips}</div></div>` : ""}

      ${cweChips ? `<div class="drawer-section"><h3>${t("drawer.cwe")}</h3><div class="cwe-list">${cweChips}</div></div>` : ""}

      ${cpeList ? `<div class="drawer-section"><h3>${t("drawer.affectedProducts")}</h3>${cpeList}</div>` : ""}

      ${kevSection}

      ${pocHtml ? `<div class="drawer-section"><h3>${t("drawer.knownPocs")}</h3>${pocHtml}</div>` : ""}

      ${renderThreatContext(c.threat_context)}

      ${renderCvssHistory(c.cvss_history)}

      ${refsHtml ? `<div class="drawer-section"><h3>${t("drawer.references")}</h3>${refsHtml}</div>` : ""}
    `;
  }

  function closeDrawer() {
    document.getElementById("drawer-overlay").classList.remove("open");
    document.getElementById("drawer").classList.remove("open");
    currentDrawerCve = null;
  }

  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("drawer-overlay").addEventListener("click", closeDrawer);

  document.getElementById("drawer-copy").addEventListener("click", async () => {
    if (!currentDrawerCve) return;
    try {
      await navigator.clipboard.writeText(currentDrawerCve.cve_id);
      toast(t("drawer.copiedToast"), "success");
    } catch {
      toast(t("drawer.copyFailed"), "error");
    }
  });

  document.getElementById("drawer-watch").addEventListener("click", async () => {
    if (!currentDrawerCve || !currentDrawerCve.vendor) {
      toast(t("drawer.noVendor"), "error");
      return;
    }
    try {
      await apiWrite("/api/watchlist", {
        method: "POST",
        body: JSON.stringify({ vendor: currentDrawerCve.vendor, product: currentDrawerCve.product || null }),
      });
      toast(t("toast.watchlistAddedVendor", { vendor: currentDrawerCve.vendor }), "success");
      loadWatchlist().catch(() => {});
    } catch (e) {
      if (e.message !== "unauthorized") toast(e.message, "error");
    }
  });

  // ---------- Watchlist ----------

  const TRASH_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h16M9 7V4h6v3M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/></svg>';

  async function loadWatchlist() {
    const entries = await apiGet("/api/watchlist");
    document.getElementById("watchlist-count").textContent =
      `${entries.length} ${entries.length > 1 ? t("watchlist.entryPlural") : t("watchlist.entrySingular")}`;
    const container = document.getElementById("watchlist-rows");

    if (!entries.length) {
      container.innerHTML = `<div class="muted" style="padding:10px 0;font-size:13px;">${t("watchlist.empty")}</div>`;
      return;
    }

    container.innerHTML = entries.map((e) => {
      const parts = [e.vendor, e.product].filter(Boolean).join(" / ") || (e.keyword ? `#${e.keyword}` : "?");
      return `
        <div class="list-row">
          <span class="tag">${e.keyword ? t("watchlist.keywordTag") : t("watchlist.asset")}</span>
          <span class="main">${esc(parts)}${e.note ? ` <span class="note">- ${esc(e.note)}</span>` : ""}</span>
          <button class="icon-btn" data-del-watchlist="${e.id}" title="${t("common.delete")}">${TRASH_ICON}</button>
        </div>`;
    }).join("");

    container.querySelectorAll("[data-del-watchlist]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await apiWrite(`/api/watchlist/${btn.dataset.delWatchlist}`, { method: "DELETE" });
          toast(t("toast.watchlistDeleted"), "success");
          await loadWatchlist();
        } catch (e) {
          if (e.message !== "unauthorized") toast(e.message, "error");
        }
      });
    });
  }

  document.getElementById("watchlist-form").addEventListener("submit", async (evt) => {
    evt.preventDefault();
    const form = evt.target;
    const payload = Object.fromEntries(new FormData(form).entries());
    Object.keys(payload).forEach((k) => { if (!payload[k]) delete payload[k]; });
    if (!payload.vendor && !payload.product && !payload.keyword) {
      toast(t("empty.watchlistField"), "error");
      return;
    }
    try {
      await apiWrite("/api/watchlist", { method: "POST", body: JSON.stringify(payload) });
      form.reset();
      toast(t("toast.watchlistAdded"), "success");
      await loadWatchlist();
    } catch (e) {
      if (e.message !== "unauthorized") toast(e.message, "error");
    }
  });

  // ---------- Alerts ----------

  let showAcknowledged = false;
  let latestUnackAlerts = [];

  function alertRowHtml(a) {
    return `
      <div class="list-row">
        <span class="tag">${esc(a.channel)}</span>
        <span class="main">
          <a href="#" data-open-cve="${esc(a.cve_id)}">${esc(a.cve_id)}</a>
          ${a.escalated ? `<span class="badge escalated">${t("alerts.escalated")}</span>` : ""}
          <div class="reasons">${esc(a.reasons.map(translateReason).join(", "))}</div>
        </span>
        ${a.acknowledged
          ? `<span class="muted" style="font-size:11.5px;">${t("alerts.acknowledged")}</span>`
          : `<button class="btn small" data-ack="${a.id}">${t("alerts.acknowledge")}</button>`}
      </div>`;
  }

  function bindAlertRowActions(container) {
    container.querySelectorAll("[data-open-cve]").forEach((el) => {
      el.addEventListener("click", (e) => { e.preventDefault(); closeBell(); openDrawer(el.dataset.openCve); });
    });
    container.querySelectorAll("[data-ack]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await apiWrite(`/api/alerts/${btn.dataset.ack}/ack`, { method: "POST" });
          toast(t("toast.alertAcked"), "success");
          await loadAlerts();
        } catch (e) {
          if (e.message !== "unauthorized") toast(e.message, "error");
        }
      });
    });
  }

  async function loadAlerts() {
    const alerts = await apiGet(`/api/alerts?limit=200${showAcknowledged ? "" : "&acknowledged=false"}`);
    const unack = showAcknowledged ? alerts.filter((a) => !a.acknowledged) : alerts;
    latestUnackAlerts = unack;
    document.getElementById("stat-alerts").textContent = unack.length;

    const navBadge = document.getElementById("nav-alert-badge");
    const bellDot = document.getElementById("bell-dot");
    if (unack.length > 0) {
      navBadge.style.display = "inline-flex";
      navBadge.textContent = unack.length > 99 ? "99+" : unack.length;
      bellDot.classList.add("show");
    } else {
      navBadge.style.display = "none";
      bellDot.classList.remove("show");
    }

    const container = document.getElementById("alert-rows");
    if (!alerts.length) {
      container.innerHTML = `<div class="muted" style="padding:10px 0;font-size:13px;">${t("alerts.empty")}</div>`;
    } else {
      container.innerHTML = alerts.slice(0, 40).map(alertRowHtml).join("");
      bindAlertRowActions(container);
    }

    const bellContainer = document.getElementById("bell-alert-rows");
    if (!unack.length) {
      bellContainer.innerHTML = `<div class="muted" style="padding:14px;font-size:13px;">${t("alerts.empty")}</div>`;
    } else {
      bellContainer.innerHTML = unack.slice(0, 8).map(alertRowHtml).join("");
      bindAlertRowActions(bellContainer);
    }
  }

  document.getElementById("show-all-alerts").addEventListener("click", (evt) => {
    evt.preventDefault();
    showAcknowledged = !showAcknowledged;
    evt.target.textContent = showAcknowledged ? t("alerts.hideAck") : t("alerts.showAck");
    loadAlerts().catch((e) => toast(e.message, "error"));
  });

  // ---------- Notification bell ----------

  function closeBell() { document.getElementById("bell-dropdown").classList.remove("open"); }

  document.getElementById("bell-btn").addEventListener("click", (e) => {
    e.stopPropagation();
    document.getElementById("bell-dropdown").classList.toggle("open");
  });
  document.addEventListener("click", (e) => {
    if (!document.getElementById("bell-dropdown").contains(e.target)) closeBell();
  });

  // ---------- Radar PoC ----------

  function pocRowHtml(r) {
    const sev = sevClass(r.severity);
    const badges = [`<span class="badge ${sev}">${esc(r.severity) || t("severity.unknown")}</span>`];
    if (r.is_kev) badges.push(`<span class="badge kev">${t("badge.kev")}</span>`);
    if (r.weaponization_risk) badges.push(`<span class="badge risk">${t("badge.risk")}</span>`);
    if (r.unconfirmed) badges.push(`<span class="badge unconfirmed">${t("badge.unconfirmed")}</span>`);
    const detail = [r.repo_full_name || r.url, r.stars != null ? `★ ${r.stars}` : null].filter(Boolean).join(" · ");
    return `
      <div class="list-row">
        <span class="tag">${esc(r.source)}</span>
        <span class="main">
          <a href="#" data-open-cve="${esc(r.cve_id)}">${esc(r.cve_id)}</a>
          ${badges.join(" ")}
          <div class="reasons">${esc(detail)}</div>
        </span>
        <span class="muted" style="font-size:11.5px;white-space:nowrap;">${relativeTime(r.discovered_at)}</span>
      </div>`;
  }

  async function loadPocRadar() {
    const rows = await apiGet("/api/pocs/recent?limit=100");
    const dayAgo = Date.now() - 24 * 3600 * 1000;
    const recentCount = rows.filter((r) => new Date(r.discovered_at + "Z").getTime() >= dayAgo).length;
    document.getElementById("stat-poc-24h").textContent = recentCount;

    const container = document.getElementById("radar-rows");
    if (!rows.length) {
      container.innerHTML = `<div class="muted" style="padding:10px 0;font-size:13px;">${t("empty.pocs")}</div>`;
      return;
    }
    container.innerHTML = rows.map(pocRowHtml).join("");
    container.querySelectorAll("[data-open-cve]").forEach((el) => {
      el.addEventListener("click", (e) => { e.preventDefault(); openDrawer(el.dataset.openCve); });
    });
  }

  // ---------- Source status ----------

  // Sources pour lesquelles un déclenchement manuel a du sens (cadence longue/quotidienne) et
  // dispose d'un endpoint dédié - le poll principal a déjà son propre bouton "Forcer un poll".
  const SYNC_ENDPOINTS = {
    epss: "/api/cves/sync-epss",
    github_poc: "/api/pocs/sync-now",
  };

  async function loadStatus() {
    const data = await apiGet("/api/status");
    const anyError = data.sources.some((s) => s.last_error);

    document.getElementById("status-dot").className = `status-dot${anyError ? " err" : ""}`;
    document.getElementById("status-text").textContent = anyError ? t("settings.sourceError") : t("settings.sourcesOk");

    const container = document.getElementById("source-rows");
    container.innerHTML = data.sources.map((s) => {
      // Badge texte plutôt qu'un simple point de couleur : "OK"/"Erreur"/"En attente" reste
      // lisible même quand la différence de teinte entre deux couleurs est difficile à percevoir.
      const sevClassForState = s.last_error ? "CRITICAL" : (s.last_polled_at ? "LOW" : "UNKNOWN");
      const stateLabel = s.last_error ? t("settings.statusErrShort") : (s.last_polled_at ? t("settings.statusOk") : t("settings.statusPending"));
      const when = s.last_polled_at ? t("relTime.ago", { t: relativeTime(s.last_polled_at) }) : t("settings.neverPolled");
      const counts = t("settings.fetchedNewCounts", { fetched: s.last_success_count, new: s.last_new_count });
      const detail = s.last_error ? `${when} - ${esc(s.last_error)}` : `${when} - ${counts}`;
      const syncBtn = SYNC_ENDPOINTS[s.name]
        ? `<button class="btn small" data-sync-source="${esc(s.name)}" style="margin-left:auto;">${t("settings.sync")}</button>` : "";
      return `
        <div class="source-row">
          <span class="badge ${sevClassForState}">${stateLabel}</span>
          <span class="name">${esc(s.name)}</span>
          <span class="muted">${detail}</span>
          ${syncBtn}
        </div>`;
    }).join("");

    container.querySelectorAll("[data-sync-source]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const url = SYNC_ENDPOINTS[btn.dataset.syncSource];
        btn.disabled = true;
        const original = btn.textContent;
        btn.textContent = t("settings.syncing");
        try {
          const summary = await apiWrite(url, { method: "POST" });
          if (summary && summary.error) {
            toast(t("toast.syncSummaryError", { name: btn.dataset.syncSource, error: summary.error }), "error");
          } else if (summary) {
            toast(t("toast.syncSummary", { name: btn.dataset.syncSource, fetched: summary.fetched, new: summary.new }), "success");
          } else {
            toast(t("toast.syncTriggered", { name: btn.dataset.syncSource }), "success");
          }
          await Promise.allSettled([loadStats(), loadStatus()]);
        } catch (e) {
          if (e.message !== "unauthorized") toast(e.message, "error");
        } finally {
          btn.disabled = false;
          btn.textContent = original;
        }
      });
    });
  }

  // ---------- Poll now ----------

  document.getElementById("poll-now").addEventListener("click", async () => {
    const btn = document.getElementById("poll-now");
    btn.disabled = true;
    btn.textContent = t("topbar.pollingNow");
    try {
      const result = await apiWrite("/api/alerts/poll-now", { method: "POST" });
      const summaries = (result && result.summaries) || [];
      const fetched = summaries.reduce((sum, s) => sum + (s.fetched || 0), 0);
      const newCount = summaries.reduce((sum, s) => sum + (s.new || 0), 0);
      const alerts = summaries.reduce((sum, s) => sum + (s.alerts_sent || 0), 0);
      const errors = summaries.filter((s) => s.error).length;
      if (errors > 0) {
        toast(t("toast.pollSummaryWithErrors", { fetched, new: newCount, errors }), "error");
      } else {
        toast(t("toast.pollSummary", { fetched, new: newCount, alerts }), "success");
      }
      await refreshAll();
    } catch (e) {
      if (e.message !== "unauthorized") toast(e.message, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = t("topbar.pollNow");
    }
  });

  // ---------- Settings: API key ----------

  document.getElementById("key-save").addEventListener("click", () => {
    const value = document.getElementById("key-input").value;
    if (value) localStorage.setItem(KEY_STORAGE, value);
    else localStorage.removeItem(KEY_STORAGE);
    toast(t("settings.keySaved"), "success");
  });
  document.getElementById("key-clear").addEventListener("click", () => {
    localStorage.removeItem(KEY_STORAGE);
    document.getElementById("key-input").value = "";
    toast(t("settings.keyCleared"), "success");
  });

  // ---------- Settings: compte (JWT) ----------

  // Mono-admin : la création de compte ne doit être proposée qu'au tout premier lancement (aucun
  // utilisateur en base). Une fois l'admin créé, l'inscription est fermée côté serveur (POST
  // /api/auth/register -> 403) - inutile d'afficher un bouton qui échouerait à coup sûr. Pas géré
  // via data-i18n (le texte dépend d'un état serveur, pas seulement de la langue) : réappliqué
  // explicitement à chaque changement de langue, cf. applyLanguage().
  async function refreshRegisterAvailability() {
    try {
      const { setup_required } = await apiGet("/api/auth/status");
      document.getElementById("register-btn").style.display = setup_required ? "" : "none";
      document.getElementById("register-hint").textContent = t(setup_required ? "settings.registerHint" : "settings.registerClosedHint");
    } catch { /* endpoint public, silencieux si l'API est momentanément injoignable */ }
  }

  async function refreshAccount() {
    const token = getJwt();
    if (!token) {
      document.getElementById("account-logged-out").style.display = "";
      document.getElementById("account-logged-in").style.display = "none";
      document.getElementById("api-keys-logged-out").style.display = "";
      document.getElementById("api-keys-logged-in").style.display = "none";
      await refreshRegisterAvailability();
      return;
    }
    try {
      const resp = await fetch("/api/auth/me", { headers: authHeaders() });
      if (!resp.ok) throw new Error("unauthorized");
      const me = await resp.json();
      document.getElementById("account-logged-out").style.display = "none";
      document.getElementById("account-logged-in").style.display = "";
      document.getElementById("account-email").textContent = me.email;
      document.getElementById("account-role").textContent = `(${me.role})`;
      document.getElementById("api-keys-logged-out").style.display = "none";
      document.getElementById("api-keys-logged-in").style.display = "";
      await loadApiKeys();
    } catch {
      clearJwt();
      document.getElementById("account-logged-out").style.display = "";
      document.getElementById("account-logged-in").style.display = "none";
    }
  }

  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    try {
      const resp = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(extractErrorMessage(body, t("toast.loginFailed")));
      }
      const { access_token } = await resp.json();
      setJwt(access_token);
      e.target.reset();
      toast(t("toast.loggedIn"), "success");
      await refreshAccount();
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.getElementById("register-btn").addEventListener("click", async () => {
    const form = document.getElementById("login-form");
    const email = form.email.value, password = form.password.value;
    if (!email || !password) { toast(t("empty.loginField"), "error"); return; }
    try {
      const resp = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({ email, password }),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(extractErrorMessage(body, t("toast.registerFailed")));
      }
      toast(t("toast.accountCreated"), "success");
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.getElementById("logout-btn").addEventListener("click", () => {
    clearJwt();
    toast(t("toast.loggedOut"), "success");
    refreshAccount();
  });

  // ---------- Settings: clés API ----------

  async function loadApiKeys() {
    const resp = await fetch("/api/api-keys", { headers: authHeaders() });
    if (!resp.ok) return;
    const keys = await resp.json();
    document.getElementById("api-keys-rows").innerHTML = keys.length
      ? keys.map((k) => {
          const revoked = k.revoked_at != null;
          const status = revoked ? t("apiKey.revoked") : (k.expires_at && new Date(k.expires_at + "Z") < new Date() ? t("apiKey.expired") : t("apiKey.active"));
          const usage = k.last_used_at ? t("apiKey.usedAgo", { t: relativeTime(k.last_used_at) }) : t("apiKey.neverUsed");
          return `
            <div class="source-row">
              <span class="dot ${revoked ? "err" : "ok"}"></span>
              <span class="name">${esc(k.name)} <code>${esc(k.prefix)}…</code></span>
              <span class="muted">${status} - ${usage}</span>
              ${revoked ? "" : `<button class="btn small" data-revoke-key="${k.id}" style="margin-left:auto;">${t("apiKey.revoke")}</button>`}
            </div>`;
        }).join("")
      : `<div class="muted">${t("apiKey.empty")}</div>`;

    document.querySelectorAll("[data-revoke-key]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const resp2 = await fetch(`/api/api-keys/${btn.dataset.revokeKey}`, { method: "DELETE", headers: authHeaders() });
          if (!resp2.ok && resp2.status !== 204) throw new Error(t("apiKey.revokeFailed"));
          toast(t("apiKey.revokedToast"), "success");
          await loadApiKeys();
        } catch (err) {
          toast(err.message, "error");
        }
      });
    });
  }

  document.getElementById("api-key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    const payload = { name: form.get("name") };
    if (form.get("expires_days")) payload.expires_days = Number(form.get("expires_days"));
    try {
      const resp = await fetch("/api/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(extractErrorMessage(body, t("apiKey.createFailed")));
      }
      const created = await resp.json();
      e.target.reset();
      await loadApiKeys();
      await navigator.clipboard.writeText(created.api_key).catch(() => {});
      toast(t("apiKey.createdToast", { key: created.api_key }), "success");
    } catch (err) {
      toast(err.message, "error");
    }
  });

  refreshAccount();

  // ---------- Command palette ----------

  function staticCommands() {
    return [
      { label: t("nav.overview"), meta: t("palette.page"), action: () => goToPage("overview"), icon: "grid" },
      { label: t("nav.cves"), meta: t("palette.page"), action: () => goToPage("cves"), icon: "list" },
      { label: t("nav.radar"), meta: t("palette.page"), action: () => goToPage("radar"), icon: "radar" },
      { label: t("nav.watchlist"), meta: t("palette.page"), action: () => goToPage("watchlist"), icon: "bookmark" },
      { label: t("nav.alerts"), meta: t("palette.page"), action: () => goToPage("alerts"), icon: "bell" },
      { label: t("nav.settings"), meta: t("palette.page"), action: () => goToPage("settings"), icon: "settings" },
      { label: t("topbar.pollNow"), meta: t("palette.action"), action: () => document.getElementById("poll-now").click(), icon: "refresh" },
    ];
  }

  const PALETTE_ICONS = {
    grid: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    list: '<path d="M4 5h16M4 12h16M4 19h10"/>',
    bookmark: '<path d="M12 3 4 6v5c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V6l-8-3Z"/>',
    bell: '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0"/>',
    settings: '<circle cx="12" cy="12" r="3"/>',
    refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/>',
    cve: '<path d="M12 9v4"/><circle cx="12" cy="16.5" r=".6" fill="currentColor" stroke="none"/><path d="M10.3 3.9 2.7 17a1.8 1.8 0 0 0 1.5 2.7h15.6a1.8 1.8 0 0 0 1.5-2.7L13.7 3.9a1.8 1.8 0 0 0-3.4 0Z"/>',
    radar: '<circle cx="12" cy="12" r="2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9 17 7M7 17l-2.1 2.1"/>',
  };

  function paletteIcon(name) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${PALETTE_ICONS[name] || ""}</svg>`;
  }

  let paletteItems = [];
  let paletteActiveIndex = 0;
  let paletteSearchToken = 0;

  function renderPalette() {
    const results = document.getElementById("palette-results");
    if (!paletteItems.length) {
      results.innerHTML = `<div class="palette-empty">${t("palette.noResults")}</div>`;
      return;
    }
    results.innerHTML = paletteItems.map((item, i) => `
      <div class="palette-item ${i === paletteActiveIndex ? "active" : ""}" data-idx="${i}">
        ${paletteIcon(item.icon)}
        <span class="label">${esc(item.label)}</span>
        <span class="meta">${esc(item.meta)}</span>
      </div>`).join("");
    results.querySelectorAll(".palette-item").forEach((el) => {
      el.addEventListener("click", () => runPaletteItem(Number(el.dataset.idx)));
      el.addEventListener("mousemove", () => { paletteActiveIndex = Number(el.dataset.idx); renderPalette(); });
    });
  }

  function runPaletteItem(i) {
    const item = paletteItems[i];
    if (!item) return;
    closePalette();
    item.action();
  }

  async function searchPalette(query) {
    const token = ++paletteSearchToken;
    if (!query) {
      paletteItems = staticCommands();
      paletteActiveIndex = 0;
      renderPalette();
      return;
    }
    const matchingCommands = staticCommands().filter((c) => c.label.toLowerCase().includes(query.toLowerCase()));
    try {
      const cves = await apiGet(`/api/cves?q=${encodeURIComponent(query)}&limit=6`);
      if (token !== paletteSearchToken) return;
      const cveItems = cves.map((c) => ({
        label: c.cve_id,
        meta: [c.vendor, c.product].filter(Boolean).join(" / ") || c.severity || t("table.cve"),
        icon: "cve",
        action: () => openDrawer(c.cve_id),
      }));
      paletteItems = [...cveItems, ...matchingCommands];
    } catch {
      paletteItems = matchingCommands;
    }
    paletteActiveIndex = 0;
    renderPalette();
  }

  let paletteDebounce = null;
  const paletteInput = document.getElementById("palette-input");
  paletteInput.addEventListener("input", () => {
    clearTimeout(paletteDebounce);
    paletteDebounce = setTimeout(() => searchPalette(paletteInput.value.trim()), 150);
  });
  paletteInput.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); paletteActiveIndex = Math.min(paletteActiveIndex + 1, paletteItems.length - 1); renderPalette(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); paletteActiveIndex = Math.max(paletteActiveIndex - 1, 0); renderPalette(); }
    else if (e.key === "Enter") { e.preventDefault(); runPaletteItem(paletteActiveIndex); }
    else if (e.key === "Escape") closePalette();
  });

  function openPalette() {
    document.getElementById("palette-overlay").classList.add("open");
    paletteInput.value = "";
    paletteInput.focus();
    searchPalette("");
  }
  function closePalette() {
    document.getElementById("palette-overlay").classList.remove("open");
  }

  document.getElementById("open-palette").addEventListener("click", openPalette);
  document.getElementById("palette-overlay").addEventListener("click", (e) => {
    if (e.target.id === "palette-overlay") closePalette();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette();
    } else if (e.key === "Escape") {
      closePalette();
      closeDrawer();
    }
  });

  // ---------- Realtime (WebSocket) ----------

  // Le polling 30s (setInterval(refreshAll, ...) ci-dessous) reste actif en permanence, même
  // avec le WebSocket connecté : filet de sécurité qui rattrape tout événement manqué (message
  // perdu, coupure non détectée...) sans dépendre de la fiabilité du temps réel.
  let ws = null;
  let wsReconnectTimer = null;
  let wsReconnectDelay = 1000;
  const WS_MAX_RECONNECT_DELAY = 30000;

  function wsUrl() {
    // Même politique que les endpoints REST en lecture (GET /api/cves, /api/status...) : ouvert
    // sans authentification, cf. app/api/routes_ws.py.
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${location.host}/ws`;
  }

  function patchCveRow(c) {
    const tr = document.querySelector(`tr[data-cve-id="${CSS.escape(c.cve_id)}"]`);
    if (!tr) return;
    const tmp = document.createElement("tbody");
    tmp.innerHTML = cveRowHtml(c);
    const newTr = tmp.firstElementChild;
    bindSingleRowEvents(newTr);
    tr.replaceWith(newTr);
  }

  function maybePrependCveRow(c) {
    const onCvesPage = document.getElementById("page-cves").classList.contains("active");
    const noFilters = !document.getElementById("f-q").value.trim() && !document.getElementById("f-severity").value &&
      !document.getElementById("f-vendor").value.trim() && !document.getElementById("f-epss-min").value.trim() &&
      !document.getElementById("f-kev").checked && !document.getElementById("f-poc").checked && !document.getElementById("f-watchlist").checked;
    if (!(onCvesPage && noFilters && sortField === "last_seen" && sortDir === "desc" && cveOffset === 0)) return;
    const tbody = document.getElementById("cve-rows");
    tbody.querySelector(".empty-row")?.remove();
    const tmp = document.createElement("tbody");
    tmp.innerHTML = cveRowHtml(c);
    const newTr = tmp.firstElementChild;
    bindSingleRowEvents(newTr);
    tbody.prepend(newTr);
  }

  function bumpStatTotal(delta) {
    const el = document.getElementById("stat-total");
    const current = parseInt(el.textContent, 10);
    if (!Number.isNaN(current)) el.textContent = current + delta;
  }

  function handleWsMessage(envelope) {
    switch (envelope.type) {
      case "cve.created":
        bumpStatTotal(1);
        maybePrependCveRow(envelope.data);
        break;
      case "cve.updated":
        patchCveRow(envelope.data);
        if (currentDrawerCve && currentDrawerCve.cve_id === envelope.data.cve_id) {
          currentDrawerCve = envelope.data;
          renderDrawer(envelope.data);
        }
        break;
      case "alert.created":
        toast(t("toast.newAlert", { cveId: envelope.data.cve_id }), "info");
        loadAlerts().catch(() => {});
        break;
      case "source.status":
        loadStatus().catch(() => {});
        break;
    }
  }

  function scheduleWsReconnect() {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = setTimeout(() => {
      wsReconnectDelay = Math.min(wsReconnectDelay * 2, WS_MAX_RECONNECT_DELAY);
      connectWebSocket();
    }, wsReconnectDelay);
  }

  function connectWebSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    clearTimeout(wsReconnectTimer);
    try {
      ws = new WebSocket(wsUrl());
    } catch (e) {
      scheduleWsReconnect();
      return;
    }
    ws.onopen = () => { wsReconnectDelay = 1000; };
    ws.onmessage = (evt) => {
      try { handleWsMessage(JSON.parse(evt.data)); } catch (e) { /* message malformé, ignoré */ }
    };
    ws.onclose = () => {
      scheduleWsReconnect();
    };
  }

  // ---------- Refresh loop ----------

  function setUpdatedAt() {
    const now = new Date();
    const time = now.toLocaleTimeString(dateLocale(), { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    document.getElementById("updated-at").textContent = t("topbar.updatedAt", { time });
  }

  async function refreshAll() {
    const results = await Promise.allSettled([loadStats(), loadCves(), loadPocRadar(), loadWatchlist(), loadAlerts(), loadStatus()]);
    setUpdatedAt();
    const failed = results.find((r) => r.status === "rejected");
    if (failed) {
      document.getElementById("status-dot").className = "status-dot err";
      document.getElementById("status-text").textContent = t("status.connectionError");
    }
  }

  applyLanguage(currentLang);
  setInterval(refreshAll, 30000);
  connectWebSocket();
})();
