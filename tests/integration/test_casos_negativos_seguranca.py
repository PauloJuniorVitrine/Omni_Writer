import pytest
from app.app_factory import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_payload_invalido(client):
    data = {"instancias_json": "{nome:inst1}", "prompts": ""}
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code in (400, 422, 200)
    assert b"erro" in resp.data.lower() or b"invalido" in resp.data.lower()

def test_autenticacao_incorreta(client):
    headers = {"Authorization": "Bearer token_invalido"}
    resp = client.get("/api/protegido", headers=headers)
    assert resp.status_code in (401, 403)
    assert b"negado" in resp.data.lower() or b"unauthorized" in resp.data.lower()

def test_sem_permissao(client):
    headers = {"Authorization": "Bearer token_sem_permissao"}
    resp = client.get("/api/protegido", headers=headers)
    assert resp.status_code in (401, 403)
    assert b"negado" in resp.data.lower() or b"unauthorized" in resp.data.lower()

def test_timeout(client, monkeypatch):
    def fake_generate(*args, **kwargs):
        import time
        time.sleep(2)
        return {"content": "Artigo gerado", "filename": "artigo.txt"}
    monkeypatch.setattr("app.controller.generate_article", fake_generate)
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {"instancias_json": app.json.dumps(instancias), "prompts": "prompt 1"}
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200 or resp.status_code == 504

def test_acesso_nao_autorizado(client):
    resp = client.get("/admin/secret")
    assert resp.status_code in (401, 403, 404)
    assert b"negado" in resp.data.lower() or b"unauthorized" in resp.data.lower() or b"not found" in resp.data.lower() 