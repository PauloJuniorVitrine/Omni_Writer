import time
import pytest
from app.app_factory import create_app
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_tempo_resposta_geracao(client):
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    inicio = time.time()
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    fim = time.time()
    assert resp.status_code == 200
    tempo = fim - inicio
    assert tempo < 10, f"Tempo de resposta excessivo: {tempo:.2f}s"

def test_logs_gerados(client, caplog):
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    with caplog.at_level("INFO"):
        resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert any("gerado" in m.lower() or "sucesso" in m.lower() for m in caplog.messages) 