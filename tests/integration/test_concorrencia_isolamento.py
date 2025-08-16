import threading
import pytest
from app.app_factory import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_geracao_concorrente(client):
    results = [None] * 5
    def gerar(idx):
        instancias = [{"nome": f"inst{idx}", "modelo": "openai", "api_key": f"sk-teste{idx}", "prompts": [f"prompt {idx}"]}]
        data = {"instancias_json": app.json.dumps(instancias), "prompts": f"prompt {idx}"}
        resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
        results[idx] = resp.status_code
    threads = [threading.Thread(target=gerar, args=(i,)) for i in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert all(r == 200 for r in results)

def test_feedback_concorrente(client):
    feedbacks = [
        {"id_artigo": f"artigo_{i}.txt", "prompt": f"prompt {i}", "avaliacao": 1, "comentario": f"Comentário {i}"}
        for i in range(5)
    ]
    def enviar(idx):
        client.post("/feedback", json=feedbacks[idx])
    threads = [threading.Thread(target=enviar, args=(i,)) for i in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()
    # Não deve haver erro de integridade

def test_rollback_falha_intermediaria(client, monkeypatch):
    def fake_generate(*args, **kwargs):
        raise Exception("Falha simulada")
    monkeypatch.setattr("app.controller.generate_article", fake_generate)
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {"instancias_json": app.json.dumps(instancias), "prompts": "prompt 1"}
    resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert resp.status_code in (400, 500)
    # Verifica que não há resíduos de dados/arquivos 