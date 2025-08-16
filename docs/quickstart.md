# Guia Rápido de Uso (Quickstart) — Omni Writer

## 1. Geração de Artigo via API
```bash
curl -X POST http://localhost:5000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Tema do artigo", "model_type": "openai"}'
```

## 2. Download de Artigos em ZIP
```bash
curl -O http://localhost:5000/download_zip
```

## 3. Consulta de Status
```bash
curl http://localhost:5000/status/<trace_id>
```

## 4. Exemplo de Payload de Geração
```json
{
  "prompt": "Como aplicar Clean Architecture em Python",
  "model_type": "openai",
  "language": "pt-BR",
  "max_tokens": 1024
}
```

## 5. Execução Local
```bash
export FLASK_APP=app/app_factory.py
flask run
celery -A app.celery_worker worker --loglevel=info
``` 