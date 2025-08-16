"""
Testes de Integração — Performance e Concorrência em Endpoints Críticos

Cenários cobertos:
- Simulação de múltiplas requisições simultâneas aos endpoints de geração, download, etc.
- Medição de tempo de resposta e estabilidade sob carga.
- Detecção de gargalos e possíveis race conditions.

Observação: Não misture testes unitários e de integração neste arquivo.
"""

import pytest
from app.app_factory import create_app
import threading
import time
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_concorrencia_geracao_artigos(monkeypatch):
    """Testa concorrência de múltiplas requisições ao endpoint /generate (mock)."""
    def fake_generate(*args, **kwargs):
        time.sleep(0.2)
        return {"content": "Artigo gerado", "filename": "artigo.txt"}
    monkeypatch.setattr("infraestructure.openai_gateway.generate_article_openai", fake_generate)
    instancias = [{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]
    data = {
        "instancias_json": json.dumps(instancias),
        "prompts": "prompt 1"
    }
    results = []
    def gerar():
        with app.test_client() as client:
            resp = client.post("/generate", data=data, content_type="multipart/form-data", follow_redirects=True)
            results.append(resp.status_code == 200)
    threads = [threading.Thread(target=gerar) for _ in range(5)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    assert all(results)
    assert elapsed < 5  # Limite arbitrário para performance

def test_performance_download(monkeypatch, tmp_path):
    """Testa tempo de resposta do endpoint /download sob carga."""
    zip_path = tmp_path / "artigos.zip"
    zip_path.write_text("conteudo")
    monkeypatch.setattr("app.main.ARTIGOS_ZIP", str(zip_path))
    monkeypatch.setattr("app.main.os.path.exists", lambda x: True)
    results = []
    def baixar():
        with app.test_client() as client:
            resp = client.get("/download")
            results.append(resp.status_code == 200)
    threads = [threading.Thread(target=baixar) for _ in range(5)]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start
    assert all(results)
    assert elapsed < 5  # Limite arbitrário para performance 