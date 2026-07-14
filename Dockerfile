FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY watchlist.yaml .

# Ne pas tourner en root dans le conteneur (durcissement standard) : le process n'a besoin
# d'aucun privilège root pour servir l'API ou écrire le SQLite de dev (/app reste writable).
RUN useradd --no-create-home --shell /usr/sbin/nologin appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
