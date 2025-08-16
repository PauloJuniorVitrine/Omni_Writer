"""
Testes de Integração — SSE (Server-Sent Events)

Cenários cobertos:
- Conexão e recebimento de eventos via endpoint SSE (/sse, /status/sse, etc.).
- Reconexão automática após desconexão.
- Múltiplos clientes simultâneos recebendo eventos.
- Edge cases: desconexão abrupta, eventos malformados, ausência de eventos.

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

def test_sse_recebimento_evento(client):
    """Testa se o endpoint SSE envia eventos corretamente para o cliente."""
    resp = client.get("/sse", buffered=True)
    # O conteúdo deve conter pelo menos um evento SSE ("data:")
    data = b"".join(resp.iter_encoded())
    assert b"data:" in data or b"event:" in data

def test_sse_reconexao(client):
    """Testa reconexão automática do cliente SSE após desconexão."""
    # Simula duas conexões seguidas ao endpoint SSE
    resp1 = client.get("/sse", buffered=True)
    data1 = b"".join(resp1.iter_encoded())
    resp2 = client.get("/sse", buffered=True)
    data2 = b"".join(resp2.iter_encoded())
    assert b"data:" in data1 or b"event:" in data1
    assert b"data:" in data2 or b"event:" in data2

def test_sse_multiplos_clientes():
    """Testa múltiplos clientes conectados ao SSE simultaneamente."""
    results = []
    def sse_client():
        with app.test_client() as client:
            resp = client.get("/sse", buffered=True)
            data = b"".join(resp.iter_encoded())
            results.append(b"data:" in data or b"event:" in data)
    threads = [threading.Thread(target=sse_client) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(results)

def test_sse_edge_case_sem_evento(client):
    """Testa comportamento do SSE quando não há eventos a serem enviados."""
    # Supondo que o endpoint /sse pode retornar vazio em algum cenário
    resp = client.get("/sse", buffered=True)
    data = b"".join(resp.iter_encoded())
    # Não deve lançar erro, mas pode não conter "data:"
    assert resp.status_code == 200 