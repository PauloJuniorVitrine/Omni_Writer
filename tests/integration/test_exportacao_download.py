import os
import pytest
from app.app_factory import create_app
from shared.config import ARTIGOS_ZIP, OUTPUT_BASE_DIR
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_download_zip_sucesso(client):
    # Gera artigo para garantir existência do arquivo
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200
    # Download do ZIP
    resp_zip = client.get("/download/omni_artigos.zip")
    assert resp_zip.status_code == 200
    assert resp_zip.headers.get("Content-Type", "").startswith("application/zip")
    assert resp_zip.data[:2] == b"PK", "Arquivo ZIP inválido"
    # Download de artigo TXT
    resp_txt = client.get("/download/artigo_1.txt")
    assert resp_txt.status_code == 200
    assert resp_txt.headers.get("Content-Type", "").startswith("text/plain")
    assert b"Artigo gerado" in resp_txt.data or b"prompt" in resp_txt.data

def test_download_arquivo_inexistente(client):
    resp = client.get("/download/arquivo_inexistente.txt")
    assert resp.status_code in (404, 400)
    assert b"erro" in resp.data.lower() or b"not found" in resp.data.lower() 