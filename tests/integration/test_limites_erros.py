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

def test_limite_max_prompts(client):
    prompts = [f"prompt {i}" for i in range(1, 52)]  # 51 prompts
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": prompts}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "\n".join(prompts)
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"limite" in resp.data or b"50" in resp.data or b"erro" in resp.data.lower()

def test_limite_max_instancias(client):
    instancias = [
        {"nome": f"inst{i}", "modelo": "openai", "api_key": f"sk-teste{i}", "prompts": [f"prompt {i}"]}
        for i in range(1, 17)
    ]  # 16 instâncias
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"limite" in resp.data or b"15" in resp.data or b"erro" in resp.data.lower()

def test_prompts_vazios(client):
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": []}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": ""
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"obrigat" in resp.data.lower() or b"prompt" in resp.data.lower()

def test_campo_obrigatorio_ausente(client):
    data = {
        # "instancias_json" ausente
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"obrigat" in resp.data.lower() or b"instancia" in resp.data.lower()

def test_api_key_invalida(client):
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    assert b"api" in resp.data.lower() or b"chave" in resp.data.lower() or b"obrigat" in resp.data.lower() 