"""
/tests/integration/test_status_integration.spec.py
Fluxo: Status de Geração
Camadas tocadas: App (Flask) → Status Repository → Sistema de arquivos/DB
Tipos de lógica: Consulta, leitura, rastreabilidade, CRUD
Dependências externas: Sistema de arquivos/DB (status.db)
"""

import os
import pytest
from app.app_factory import create_app
from shared.status_repository import init_db
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.mark.integration
def test_status_endpoint_fluxo_real(tmp_path):
    """
    Teste de integração do endpoint de status de geração:
    - Gera artigo real (via /generate)
    - Consulta status via /status/<trace_id>
    - Valida progresso, estados e finalização
    """
    init_db()
    client = client()
    # Gera artigo e obtém trace_id
    data = {
        "api_key": "sk-teste",
        "model_type": "openai",
        "prompts": "prompt status"
    }
    resp = client.post("/generate", data=data, follow_redirects=True)
    assert resp.status_code == 200
    # Extrai trace_id do status.db (último registro)
    import sqlite3
    conn = sqlite3.connect("status.db")
    cur = conn.cursor()
    cur.execute("SELECT trace_id FROM status ORDER BY rowid DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    assert row, "Nenhum trace_id encontrado no status.db"
    trace_id = row[0]
    # Consulta status via endpoint
    status_resp = client.get(f"/status/{trace_id}")
    assert status_resp.status_code == 200
    status_json = status_resp.get_json()
    assert status_json["trace_id"] == trace_id
    assert status_json["status"] in ("in_progress", "done")
    assert status_json["total"] >= 1
    assert status_json["current"] >= 0
    # Se finalizado, current == total
    if status_json["status"] == "done":
        assert status_json["current"] == status_json["total"] 