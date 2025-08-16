"""
ATENÇÃO: Este teste de concorrência realista exige que o servidor Flask já esteja rodando em localhost:5000 com suporte a múltiplas threads.

Recomendações para execução concorrente:

1. Com Flask (modo threads):
   $env:FLASK_APP="app.main"; flask run --host=127.0.0.1 --port=5000 --with-threads

2. Com waitress (recomendado para Windows):
   pip install waitress
   python -m waitress --host=127.0.0.1 --port=5000 app.main:app

Em seguida, execute o teste manualmente:
   pytest tests/integration/test_concorrencia_stress.py::test_concorrencia_generate_manual
"""

import pytest
import requests
import threading
from app.app_factory import create_app

BASE_URL = "http://localhost:5000"

def gerar_payload(inst_idx=1, n_prompts=3):
    instancias = [
        {"nome": f"inst{inst_idx}", "modelo": "openai", "api_key": f"sk-teste{inst_idx}", "prompts": [f"prompt {i}" for i in range(1, n_prompts+1)]}
    ]
    data = {
        "instancias_json": app.json.dumps(instancias),
        "prompts": "\n".join([f"prompt {i}" for i in range(1, n_prompts+1)])
    }
    return data

def thread_generate(results, idx):
    data = gerar_payload(inst_idx=idx, n_prompts=3)
    try:
        resp = requests.post(f"{BASE_URL}/generate", data=data)
        results[idx] = resp.status_code
    except Exception as e:
        results[idx] = str(e)

def test_concorrencia_generate_manual():
    """
    Execute com o servidor Flask já rodando em localhost:5000 com threads ou waitress.
    pytest tests/integration/test_concorrencia_stress.py::test_concorrencia_generate_manual
    """
    threads = []
    results = [None] * 5
    for i in range(5):
        t = threading.Thread(target=thread_generate, args=(results, i))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    assert all(r == 200 for r in results), f"Nem todas as requisições retornaram 200: {results}"

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_stress_grande_volume(client):
    # Testa limite superior de prompts (50)
    data = gerar_payload(inst_idx=99, n_prompts=50)
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200, f"Falha ao enviar 50 prompts: {resp.status_code} - {resp.data}"
    # Testa grande número de instâncias (15)
    instancias = [
        {"nome": f"inst{i}", "modelo": "openai", "api_key": f"sk-teste{i}", "prompts": [f"prompt {i}"]}
        for i in range(1, 16)
    ]
    data = {
        "instancias_json": app.json.dumps(instancias),
        "prompts": "prompt 1"
    }
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code == 200, f"Falha ao enviar 15 instâncias: {resp.status_code} - {resp.data}" 