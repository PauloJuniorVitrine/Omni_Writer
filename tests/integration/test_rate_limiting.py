import os
import pytest
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

@pytest.fixture
def client():
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../templates'))
    app = Flask(__name__, template_folder=template_dir)
    app.secret_key = 'test'
    app.config['TESTING'] = True
    limiter = Limiter(get_remote_address, app=app)

    @app.route('/test_generate', methods=['POST'])
    @limiter.limit('10/minute')
    def test_generate():
        return '', 200

    @app.route('/test_feedback', methods=['POST'])
    @limiter.limit('20/minute')
    def test_feedback():
        return '', 200

    @app.route('/test_index', methods=['GET'])
    @limiter.limit('100/minute')
    def test_index():
        return '', 200

    with app.test_client() as client:
        yield client

def test_generate_rate_limit(client):
    for i in range(10):
        resp = client.post('/test_generate')
        assert resp.status_code == 200
    resp = client.post('/test_generate')
    assert resp.status_code == 429
    assert b"Too Many Requests" in resp.data or b"429" in resp.data

def test_feedback_rate_limit(client):
    for i in range(20):
        resp = client.post('/test_feedback')
        assert resp.status_code == 200
    resp = client.post('/test_feedback')
    assert resp.status_code == 429
    assert b"Too Many Requests" in resp.data or b"429" in resp.data

def test_global_rate_limit(client):
    for i in range(100):
        resp = client.get('/test_index')
        assert resp.status_code == 200
    resp = client.get('/test_index')
    assert resp.status_code == 429
    assert b"Too Many Requests" in resp.data or b"429" in resp.data 