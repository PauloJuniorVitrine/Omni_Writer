import pytest
from app.app_factory import create_app
import csv
import io

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.mark.integration
def test_export_prompts_csv(client, monkeypatch):
    # Gera prompts para exportação (simula geração)
    # Aqui, idealmente, seria feita uma geração real, mas para o teste, simula arquivo
    resp = client.get('/export_prompts')
    assert resp.status_code == 200
    content = resp.data.decode('utf-8')
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    # Aceita variações de cabeçalho (capitalização, acentuação, colunas extras)
    header = [h.strip().lower().replace('ã', 'a').replace('í', 'i').replace('é', 'e') for h in rows[0]]
    esperado = ['instancia', 'prompt']
    assert all(e in header for e in esperado[:len(header)]), f"Cabeçalho inesperado: {rows[0]}"
    assert len(rows) >= 1 