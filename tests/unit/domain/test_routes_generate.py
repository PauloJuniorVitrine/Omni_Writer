import pytest
from app import app as flask_app

def test_generate_success(client):
    # Sucesso com instâncias e prompts válidos
    data = {
        'instancias_json': '[{"api_key": "chavevalida123", "modelo": "openai", "prompts": ["Prompt válido"]}]',
        'api_key': 'chavevalida123',
        'model_type': 'openai',
        'prompts': 'Prompt válido'
    }
    resp = client.post('/generate', data=data, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code in (200, 302)
    assert b'download_link' in resp.data or b'index.html' in resp.data

def test_generate_invalid_api_key(client):
    data = {
        'instancias_json': '[{"api_key": "invalid-key", "modelo": "openai", "prompts": ["Prompt válido"]}]',
        'api_key': 'invalid-key',
        'model_type': 'openai',
        'prompts': 'Prompt válido'
    }
    resp = client.post('/generate', data=data, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 200
    assert b'API key inválida' in resp.data or b'erro_gerar_artigos' in resp.data

def test_generate_missing_fields(client):
    data = {
        'instancias_json': '',
        'api_key': '',
        'model_type': '',
        'prompts': ''
    }
    resp = client.post('/generate', data=data, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 200
    assert b'campos_obrigatorios' in resp.data or b'dados invalidos' in resp.data

def test_generate_invalid_token(client):
    data = {
        'instancias_json': '[{"api_key": "chavevalida123", "modelo": "openai", "prompts": ["Prompt válido"]}]',
        'api_key': 'chavevalida123',
        'model_type': 'openai',
        'prompts': 'Prompt válido'
    }
    resp = client.post('/generate', data=data, headers={'Authorization': 'Bearer token_invalido'})
    assert resp.status_code == 401
    assert b'Acesso negado' in resp.data 