import os
import pytest
from app.app_factory import create_app
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def gerar_instancia(nome="inst1", prompts=None):
    if prompts is None:
        prompts = ["prompt 1"]
    return {"nome": nome, "modelo": "openai", "api_key": "sk-teste", "prompts": prompts}

def test_injecao_sql_payload(client):
    instancias = [gerar_instancia(nome="inst1; DROP TABLE status;--")]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    # Aceita erro controlado (status 200 ou 400), desde que não haja crash ou vazamento
    assert resp.status_code in (200, 400), f"Falha ao testar injeção SQL: {resp.status_code} - {resp.data}"
    # Não pode retornar stacktrace, SQL ou crash
    assert b"traceback" not in resp.data.lower(), "Resposta contém traceback (crash) ao testar injeção SQL"
    assert b"sql" not in resp.data.lower(), "Resposta contém SQL (vazamento) ao testar injeção SQL"

def test_payload_malicioso(client):
    # Payload com campo inesperado
    data = {
        "instancias_json": "{\"nome\":\"inst1\",\"modelo\":\"openai\",\"api_key\":\"sk-teste\",\"prompts\":[\"prompt 1\"],\"malicioso\":\"ataque\"}",
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    # Aceita erro controlado (status 200 ou 400), desde que não haja crash ou vazamento
    assert resp.status_code in (200, 400), f"Falha ao enviar payload malicioso: {resp.status_code} - {resp.data}"
    # Não pode retornar stacktrace, SQL ou crash
    assert b"traceback" not in resp.data.lower(), "Resposta contém traceback (crash) ao enviar payload malicioso"
    assert b"sql" not in resp.data.lower(), "Resposta contém SQL (vazamento) ao enviar payload malicioso"

def test_payload_json_malformado(client):
    # Payload com JSON inválido
    data = {
        "instancias_json": "{nome:inst1,modelo:openai,api_key:sk-teste,prompts:[prompt 1]}",
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200 or resp.status_code == 400, f"Falha ao enviar JSON malformado: {resp.status_code} - {resp.data}"
    # Aceita erro controlado (400) ou tratamento silencioso (200)

def test_bypass_limite_prompts(client):
    prompts = ["prompt"] * 100
    instancias = [gerar_instancia(prompts=prompts)]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "\n".join(prompts)
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200, f"Falha ao tentar burlar limite de prompts: {resp.status_code} - {resp.data}"
    assert b"limite" in resp.data or b"50" in resp.data or b"erro" in resp.data.lower(), "Não retornou mensagem de limite ao tentar burlar"

def test_i18n_ingles(client):
    # Simula envio de idioma inglês (se suportado)
    headers = {"Accept-Language": "en"}
    instancias = [gerar_instancia()]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, headers=headers, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200, f"Falha ao testar i18n inglês: {resp.status_code} - {resp.data}"
    # Aceita tanto resposta em inglês quanto português
    assert b"success" in resp.data.lower() or b"sucesso" in resp.data.lower() or b"ok" in resp.data.lower(), "Resposta não contém status esperado em inglês ou português"

def test_webhook_registro_disparo(client, monkeypatch):
    # Mock para capturar chamada de webhook
    chamadas = []
    def fake_post(url, json=None, timeout=5):
        chamadas.append((url, json))
        class FakeResp:
            status_code = 200
        return FakeResp()
    monkeypatch.setattr("requests.post", fake_post)
    # Registra webhook
    resp = client.post("/webhook", data={"url": "http://localhost/webhook_teste"})
    assert resp.status_code == 200, f"Falha ao registrar webhook: {resp.status_code} - {resp.data}"
    assert b"ok" in resp.data or b"status" in resp.data, "Resposta não contém confirmação de webhook"
    # Dispara geração para acionar webhook
    instancias = [gerar_instancia()]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert any("webhook_teste" in url for url, _ in chamadas), "Webhook não foi disparado"

def test_webhook_falha(client, monkeypatch):
    # Mock para simular falha no webhook
    def fake_post(url, json=None, timeout=5):
        class FakeResp:
            status_code = 500
        return FakeResp()
    monkeypatch.setattr("requests.post", fake_post)
    resp = client.post("/webhook", data={"url": "http://localhost/webhook_falha"})
    assert resp.status_code == 200, f"Falha ao registrar webhook de falha: {resp.status_code} - {resp.data}"
    instancias = [gerar_instancia()]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp_gen = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp_gen.status_code == 200, f"Falha ao disparar geração com webhook de falha: {resp_gen.status_code} - {resp_gen.data}"
    # O sistema deve lidar com falha de webhook sem quebrar 