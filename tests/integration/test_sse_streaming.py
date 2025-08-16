import pytest
from app.app_factory import create_app
import json

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_sse_streaming_sucesso(client):
    # Simula requisição SSE para geração de artigo
    url = "/generate_sse"
    data = {
        "instancias_json": json.dumps([{"nome": "inst1", "modelo": "openai", "api_key": "sk-teste", "prompts": ["prompt 1"]}]),
        "prompts": "prompt 1"
    }
    with client.get(url, query_string=data, buffered=True, follow_redirects=True) as resp:
        assert resp.status_code == 200
        # Deve conter headers de SSE
        assert resp.headers.get("Content-Type", "").startswith("text/event-stream")
        # Deve receber eventos incrementais
        chunks = list(resp.response)
        assert any(b"data:" in c for c in chunks), "Nenhum evento SSE recebido"
        # Deve finalizar corretamente
        assert chunks[-1].strip() == b""

def test_sse_streaming_erro(client):
    # Simula erro de requisição SSE
    url = "/generate_sse"
    data = {"instancias_json": "", "prompts": ""}
    with client.get(url, query_string=data, buffered=True, follow_redirects=True) as resp:
        assert resp.status_code in (400, 422, 500)
        # Deve retornar erro controlado
        assert b"erro" in resp.data.lower() or b"error" in resp.data.lower() 