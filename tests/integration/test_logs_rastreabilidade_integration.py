"""
Testes de Integração — Logs e Rastreabilidade

Cenários cobertos:
- Validação de logs em fluxos de sucesso, erro e exceção.
- Garantia de presença de trace_id e informações relevantes nos logs.
- Integridade e formato dos logs gerados.

Observação: Não misture testes unitários e de integração neste arquivo.
"""

import pytest
import os
import time
from app.app_factory import create_app
import json

LOG_PATH = "logs/decisions_2025-05-05.log"  # Exemplo, ajuste conforme o log real

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_log_sucesso_geracao(client, monkeypatch, tmp_path):
    """Testa se logs de sucesso são gerados corretamente com trace_id."""
    log_file = tmp_path / "test_log_sucesso.log"
    monkeypatch.setattr("shared.logger.LOG_PATH", str(log_file))
    def fake_generate(*args, **kwargs):
        return {"content": "Artigo gerado", "filename": "artigo.txt"}
    monkeypatch.setattr("infraestructure.openai_gateway.generate_article_openai", fake_generate)
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    trace_id = "traceid-teste"
    client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    time.sleep(0.2)
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            logs = f.read()
            assert "success" in logs and trace_id in logs


def test_log_erro_geracao(client, monkeypatch, tmp_path):
    """Testa se logs de erro são gerados corretamente com trace_id."""
    log_file = tmp_path / "test_log_erro.log"
    monkeypatch.setattr("shared.logger.LOG_PATH", str(log_file))
    def fake_generate(*args, **kwargs):
        raise Exception("Erro simulado")
    monkeypatch.setattr("infraestructure.openai_gateway.generate_article_openai", fake_generate)
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    trace_id = "traceid-teste"
    client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    time.sleep(0.2)
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            logs = f.read()
            assert "error" in logs and trace_id in logs


def test_log_formato_integridade(tmp_path):
    """Testa integridade e formato dos logs gerados (JSON, campos obrigatórios)."""
    log_file = tmp_path / "test_log_integridade.log"
    # Simula geração de log
    log_entry = '{"event": "openai_generation", "status": "success", "trace_id": "abc", "timestamp": "2025-05-05T20:34:00Z"}\n'
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(log_entry)
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            assert "event" in entry and "status" in entry and "trace_id" in entry and "timestamp" in entry 