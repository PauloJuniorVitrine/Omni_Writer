import os
os.environ['STATUS_DB_PATH'] = os.path.abspath('status.db')
import tempfile
import shutil
import time
import pytest
from app.app_factory import create_app
from shared.config import OUTPUT_BASE_DIR, ARTIGOS_ZIP
from shared.status_repository import init_db
import json

DB_PATH = "status.db"

# Função utilitária para remover arquivos com retry

def remove_com_retry(path, tentativas=5, delay=0.3):
    for _ in range(tentativas):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
                return
            elif os.path.isfile(path):
                os.remove(path)
                return
        except PermissionError:
            time.sleep(delay)
    # Última tentativa
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.isfile(path):
            os.remove(path)
    except PermissionError:
        pass

@pytest.fixture(autouse=True)
def limpar_ambiente():
    init_db()
    remove_com_retry(DB_PATH)
    remove_com_retry(OUTPUT_BASE_DIR)
    remove_com_retry(ARTIGOS_ZIP)
    yield
    remove_com_retry(DB_PATH)
    remove_com_retry(OUTPUT_BASE_DIR)
    remove_com_retry(ARTIGOS_ZIP)

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_fluxo_geracao_instancias_prompts(client):
    instancias = [
        {"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1", "prompt 2"]},
        {"nome": "inst2", "modelo": "openai", "api_key": "sk-teste2", "prompts": ["prompt 3"]}
    ]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1\nprompt 2\nprompt 3"
    }
    resp = client.post(
        "/generate",
        data=data,
        content_type="multipart/form-data",
        follow_redirects=True
    )
    if resp.status_code != 200 or b"alert" in resp.data:
        print("/generate response status:", resp.status_code)
        print("/generate response data:\n", resp.data.decode(errors="ignore"))
    assert resp.status_code == 200
    zip_path = os.path.join(OUTPUT_BASE_DIR, "omni_artigos.zip")
    if not os.path.exists(zip_path):
        print("Arquivo ZIP não gerado. Response:", resp.data.decode(errors="ignore"))
    assert os.path.exists(zip_path)

def test_upload_prompts_via_arquivo(client):
    conteudo = "prompt 1\nprompt 2\nprompt 3"
    with tempfile.NamedTemporaryFile("w+t", suffix=".txt", delete=False) as f:
        f.write(conteudo)
        f.flush()
        f.seek(0)
        with open(f.name, "rb") as file_data:
            data = {
                "api_key": "sk-teste",
                "model_type": "openai",
                "prompts_file": (file_data, os.path.basename(f.name), "text/plain")
            }
            resp = client.post("/generate", data=data, content_type='multipart/form-data', follow_redirects=True)
            if resp.status_code != 200:
                print("/generate (upload) response status:", resp.status_code)
                print("/generate (upload) response data:", resp.data.decode(errors="ignore"))
            assert resp.status_code == 200
    os.remove(f.name)

def test_export_prompts(client):
    test_fluxo_geracao_instancias_prompts(client)
    resp = client.get("/export_prompts")
    assert resp.status_code == 200
    assert b"instancia,prompt" in resp.data or b"instancia" in resp.data

def test_export_artigos_csv(client):
    test_fluxo_geracao_instancias_prompts(client)
    resp = client.get("/export_artigos_csv")
    assert resp.status_code == 200
    assert b"instancia" in resp.data and b"arquivo" in resp.data

def test_download_zip(client):
    test_fluxo_geracao_instancias_prompts(client)
    zip_path = os.path.join(OUTPUT_BASE_DIR, "omni_artigos.zip")
    assert os.path.exists(zip_path)
    with open(zip_path, "rb") as f:
        f.read(10)
    resp = client.get("/download_multi")
    if resp.status_code != 200 or not resp.data or not (resp.headers["Content-Type"].startswith("application/zip") or resp.headers["Content-Type"].startswith("application/x-zip-compressed")):
        print("/download_multi status:", resp.status_code)
        print("/download_multi headers:", dict(resp.headers))
        print("/download_multi data size:", len(resp.data))
    assert resp.status_code == 200
    assert resp.headers["Content-Disposition"].startswith("attachment;")
    assert resp.data and len(resp.data) > 100  # ZIP não pode ser vazio
    assert resp.headers["Content-Type"].startswith("application/zip") or resp.headers["Content-Type"].startswith("application/x-zip-compressed")
    assert os.path.exists(zip_path)

def test_feedback(client):
    test_fluxo_geracao_instancias_prompts(client)
    feedback = {
        "id_artigo": "artigo_1.txt",
        "prompt": "prompt 1",
        "avaliacao": 1,
        "comentario": "Ótimo artigo!"
    }
    zip_path = os.path.join(OUTPUT_BASE_DIR, "omni_artigos.zip")
    if os.path.exists(zip_path):
        with open(zip_path, "rb") as f:
            f.read(10)
    resp = client.post("/feedback", json=feedback)
    assert resp.status_code in (200, 201)
    assert resp.get_json().get("status") in ("ok", "duplicado") 