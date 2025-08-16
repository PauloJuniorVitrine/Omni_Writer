import os
import pytest
from app.app_factory import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_export_prompts_sem_dados(client):
    # Garante ambiente limpo
    if os.path.exists("output"): os.system("rmdir /S /Q output")
    resp = client.get("/export_prompts")
    assert resp.status_code == 200
    # Deve retornar CSV vazio ou cabeçalho
    assert b"instancia" in resp.data
    # Não deve conter prompts
    linhas = resp.data.decode().splitlines()
    assert len(linhas) <= 2  # cabeçalho + no máximo 1 linha

def test_export_artigos_csv_sem_dados(client):
    if os.path.exists("output"): os.system("rmdir /S /Q output")
    resp = client.get("/export_artigos_csv")
    assert resp.status_code == 200
    assert b"instancia" in resp.data
    linhas = resp.data.decode().splitlines()
    assert len(linhas) <= 2

def test_download_zip_sem_dados(client):
    if os.path.exists("output/omni_artigos.zip"): os.remove("output/omni_artigos.zip")
    resp = client.get("/download_multi")
    # Esperado: erro controlado, status 404, 200 ou 302 (redirect)
    assert resp.status_code in (404, 200, 302)
    if resp.status_code == 404:
        assert b"not found" in resp.data.lower() or b"erro" in resp.data.lower()
    elif resp.status_code == 302:
        # Redirecionamento para página principal ou mensagem amigável
        assert "Location" in resp.headers
    else:
        # Se retornar 200, arquivo deve ser vazio ou mensagem de erro
        assert len(resp.data) == 0 or b"erro" in resp.data.lower()

def test_feedback_artigo_inexistente(client):
    feedback = {
        "id_artigo": "artigo_inexistente.txt",
        "prompt": "prompt x",
        "avaliacao": 1,
        "comentario": "Teste artigo inexistente"
    }
    resp = client.post("/feedback", json=feedback)
    # Esperado: erro controlado, status 404, 400, 200 ou 201
    assert resp.status_code in (404, 400, 200, 201)
    if resp.status_code not in (200, 201):
        assert b"not found" in resp.data.lower() or b"erro" in resp.data.lower()
    else:
        # Se aceitar, deve retornar status diferente de "ok"
        assert resp.get_json().get("status") != "ok" 