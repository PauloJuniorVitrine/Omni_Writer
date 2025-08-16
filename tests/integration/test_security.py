import os
import pytest
from flask import Flask
from app.routes import routes_bp, csrf

@pytest.fixture
def client():
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../templates'))
    app = Flask(__name__, template_folder=template_dir)
    app.secret_key = 'test'
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['TESTING'] = True
    csrf.init_app(app)
    app.register_blueprint(routes_bp)
    with app.test_client() as client:
        yield client

def test_generate_csrf_protection(client):
    resp = client.post('/generate', data={
        'api_key': 'testkey123', 'model_type': 'gpt', 'instancias_json': '[]'
    })
    # Espera 400 ou 403 se CSRF ativo
    assert resp.status_code in (400, 403)
    # Aceita JSON padronizado ou mensagens antigas
    if resp.is_json:
        data = resp.get_json()
        assert data.get('code') == 'csrf_error'
        assert 'csrf' in data.get('error', '').lower()
    else:
        assert b'csrf' in resp.data.lower() or b'invalid' in resp.data.lower() or b'forbidden' in resp.data.lower()

def test_generate_invalid_input(client):
    # POST com campos obrigatórios ausentes
    resp = client.post('/generate', data={})
    assert resp.status_code == 400
    assert b'Dados inv' in resp.data or b'invalid' in resp.data.lower()

def test_security_headers(client):
    resp = client.get('/test_headers')
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert 'Strict-Transport-Security' in resp.headers
    assert resp.headers['Content-Security-Policy'].startswith("default-src") 