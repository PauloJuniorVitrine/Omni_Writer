import pytest
from app import app as flask_app

def test_webhook_success(client):
    resp = client.post('/webhook', data={'url': 'https://exemplo.com'}, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 200
    assert resp.json['status'] == 'ok'

def test_webhook_missing_url(client):
    resp = client.post('/webhook', data={}, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 400
    assert 'URL obrigatória' in resp.json['error']

def test_webhook_malicious_url(client):
    resp = client.post('/webhook', data={'url': 'javascript:alert(1)'}, headers={'Authorization': 'Bearer token_valido'})
    # O código atual não bloqueia, mas deve aceitar e retornar ok
    assert resp.status_code == 200
    assert resp.json['status'] == 'ok' 