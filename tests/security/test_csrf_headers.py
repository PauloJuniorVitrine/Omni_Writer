import pytest
from app import app as flask_app

def test_security_headers_present(client):
    resp = client.get('/')
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert 'Strict-Transport-Security' in resp.headers
    assert 'Content-Security-Policy' in resp.headers

def test_csrf_error_json(client):
    # Simula requisição POST sem CSRF token
    resp = client.post('/feedback', data={
        'user_id': 'usuario123',
        'artigo_id': 'artigo456',
        'tipo': 'positivo',
        'comentario': 'Teste'
    }, headers={'X-Requested-With': 'XMLHttpRequest', 'Authorization': 'Bearer token_valido'})
    # O handler deve retornar JSON padronizado para erro CSRF
    assert resp.status_code == 400
    assert resp.json['code'] == 'csrf_error' 