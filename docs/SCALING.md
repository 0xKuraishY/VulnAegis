# Stratégie de scaling

## Tenir 10 000 requêtes/minute sur l'API

10 000 req/min ≈ 167 req/s. La stack MVP (1 instance FastAPI + Postgres) tient
difficilement ce débit avec des filtres full-text (`ilike`) sur une table qui
grossit. Chemin de montée en charge, par ordre de coût/complexité croissant :

1. **Cache Redis en lecture** - la majorité des requêtes du dashboard sont
   identiques à quelques secondes près (`/api/cves/stats`, listes filtrées
   fréquentes). Un cache avec TTL de 15-30s absorbe l'essentiel du trafic
   sans changer la fraîcheur perçue (le poll d'ingestion est lui-même à 5-10 min).
2. **Réplicas horizontaux de l'API** - FastAPI est stateless (le scheduler
   d'ingestion doit alors tourner sur **un seul** réplica dédié, ou être
   déplacé vers un worker séparé, pour éviter les polls dupliqués). Un load
   balancer (Nginx/HAProxy, ou l'ingress K8s) répartit le trafic.
3. **Lecture/écriture séparées côté DB** - un réplica PostgreSQL en lecture
   seule pour l'API, écriture réservée au pipeline d'ingestion.
4. **Elasticsearch pour la recherche** - dès que le volume de CVE et la
   fréquence de recherche full-text dépassent ce que `ilike` PostgreSQL peut
   tenir (typiquement au-delà de quelques centaines de milliers de lignes
   avec recherche libre concurrente), déporter la recherche/filtrage vers un
   index ES alimenté en continu (CDC ou double-écriture depuis le pipeline
   d'ingestion).
5. **Kubernetes + autoscaling** - une fois l'API stateless et le cache en
   place, l'autoscaling horizontal (HPA sur CPU ou sur la latence P99) devient
   mécanique.

Le point structurant : **découpler l'ingestion (faible débit, contrainte par
les quotas des APIs sources) de la lecture (haut débit, consultée par les
analystes et les intégrations SIEM)**. Le MVP les héberge dans le même
process pour la simplicité opérationnelle ; la Phase 2 (`ROADMAP.md`) les
sépare explicitement.

## Ajouter une nouvelle source sans tout recoder

C'est le critère de conception principal de `app/connectors/` :

```python
class MonNouveauConnecteur(BaseConnector):
    name = "mon_editeur"

    def fetch_since(self, since: datetime | None) -> list[NormalizedCVE]:
        # 1. Appeler l'API/flux de la source
        # 2. Retourner une liste de NormalizedCVE (le format pivot, cf. app/schemas.py)
        ...
```

Puis l'enregistrer dans `app/connectors/__init__.py::CONNECTOR_REGISTRY`.

Tout le reste (upsert en base avec fusion multi-sources, moteur de règles,
dédoublonnage, notifications, API, dashboard) fonctionne immédiatement avec
la nouvelle source, sans modification. C'est ce découplage - connecteur qui
ne connaît que sa source, pipeline qui ne connaît que `NormalizedCVE` - qui
permet d'ajouter un bulletin éditeur ou un flux RSS en quelques dizaines de
lignes plutôt qu'en touchant à l'ingestion, aux règles ou à l'API.

Pour une source à très haut volume ou nécessitant un traitement asynchrone
lourd (scraping avec rendu JS via Playwright, par exemple), le même connecteur
peut être invoqué par un worker Celery dédié au lieu du scheduler in-process,
sans changer son interface.

## Limites connues du MVP à garder en tête

- Le scheduler `APScheduler` est in-process : en cas de scaling horizontal de
  l'API, il faut le confiner à un seul réplica (variable d'env dédiée ou
  worker séparé) sous peine de polls dupliqués et d'alertes en double.
- Le dédoublonnage d'alertes (`app/alerting/dedupe.py`) interroge Postgres à
  chaque évaluation - suffisant à l'échelle du MVP, à migrer vers Redis
  (`SETNX` avec TTL) si le volume d'alertes/minute augmente significativement.
- `ilike` sur SQLite/PostgreSQL n'a pas la pertinence ni la performance d'un
  vrai moteur full-text au-delà de quelques centaines de milliers de CVE.
