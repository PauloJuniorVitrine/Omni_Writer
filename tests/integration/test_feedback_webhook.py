import pytest
from app.app_factory import create_app
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_feedback_valido(client):
    # Gera artigo para garantir existência
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {"instancias_json": json.dumps(instancias), "prompts": "prompt 1"}
    client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    feedback = {"id_artigo": "artigo_1.txt", "prompt": "prompt 1", "avaliacao": 1, "comentario": "Ótimo artigo!"}
    resp = client.post("/feedback", json=feedback)
    assert resp.status_code in (200, 201)
    assert resp.get_json().get("status") in ("ok", "duplicado")

def test_feedback_duplicado(client):
    feedback = {"id_artigo": "artigo_1.txt", "prompt": "prompt 1", "avaliacao": 1, "comentario": "Ótimo artigo!"}
    client.post("/feedback", json=feedback)
    resp = client.post("/feedback", json=feedback)
    assert resp.status_code in (200, 201)
    assert resp.get_json().get("status") == "duplicado"

def test_feedback_invalido(client):
    feedback = {"id_artigo": "", "prompt": "", "avaliacao": 5, "comentario": ""}
    resp = client.post("/feedback", json=feedback)
    assert resp.status_code in (400, 422)
    assert b"erro" in resp.data.lower() or b"invalido" in resp.data.lower()

def test_feedback_artigo_inexistente(client):
    feedback = {"id_artigo": "artigo_inexistente.txt", "prompt": "prompt 1", "avaliacao": 1, "comentario": "Teste"}
    resp = client.post("/feedback", json=feedback)
    assert resp.status_code in (404, 400)
    assert b"erro" in resp.data.lower() or b"inexistente" in resp.data.lower()

def test_webhook_registro_multiplo_disparo(client, monkeypatch):
    chamadas = []
    def fake_post(url, json=None, timeout=5):
        chamadas.append((url, json))
        class FakeResp:
            status_code = 200
        return FakeResp()
    monkeypatch.setattr("requests.post", fake_post)
    # Registra dois webhooks
    client.post("/webhook", data={"url": "http://localhost/webhook1"})
    client.post("/webhook", data={"url": "http://localhost/webhook2"})
    # Dispara geração
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {"instancias_json": json.dumps(instancias), "prompts": "prompt 1"}
    client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert any("webhook1" in url for url, _ in chamadas)
    assert any("webhook2" in url for url, _ in chamadas)

def test_webhook_falha_timeout(client, monkeypatch):
    def fake_post(url, json=None, timeout=5):
        raise Exception("Timeout")
    monkeypatch.setattr("requests.post", fake_post)
    client.post("/webhook", data={"url": "http://localhost/webhook_timeout"})
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {"instancias_json": json.dumps(instancias), "prompts": "prompt 1"}
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200 or resp.status_code == 500
    assert b"webhook" in resp.data.lower() or b"timeout" in resp.data.lower() 