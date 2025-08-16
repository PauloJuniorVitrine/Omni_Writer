import pytest
from app.app_factory import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_endpoint_protegido_token_valido(client):
    # Simula token válido
    headers = {"Authorization": "Bearer token_valido"}
    resp = client.get("/api/protegido", headers=headers)
    assert resp.status_code == 200
    assert b"acesso permitido" in resp.data.lower() or b"ok" in resp.data.lower()

def test_endpoint_protegido_token_invalido(client):
    headers = {"Authorization": "Bearer token_invalido"}
    resp = client.get("/api/protegido", headers=headers)
    assert resp.status_code in (401, 403)
    assert b"negado" in resp.data.lower() or b"unauthorized" in resp.data.lower()

def test_endpoint_protegido_sem_token(client):
    resp = client.get("/api/protegido")
    assert resp.status_code in (401, 403)
    assert b"negado" in resp.data.lower() or b"unauthorized" in resp.data.lower() 