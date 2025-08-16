import pytest
from flask import Flask
from feedback.routes import feedback_bp

def create_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.register_blueprint(feedback_bp)
    return app

def client():
    app = create_app()
    return app.test_client()

def test_submit_feedback_ok():
    c = client()
    data = {'id_artigo': 'a1', 'prompt': 'p1', 'avaliacao': 1, 'comentario': 'bom'}
    resp = c.post('/feedback', json=data)
    assert resp.status_code in (200, 201)
    assert resp.get_json()['status'] in ('ok', 'duplicado')

def test_submit_feedback_duplicate():
    c = client()
    data = {'id_artigo': 'a2', 'prompt': 'p2', 'avaliacao': 1}
    c.post('/feedback', json=data)
    resp = c.post('/feedback', json=data)
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'duplicado'

def test_submit_feedback_invalid():
    c = client()
    # Campos obrigatórios ausentes
    resp = c.post('/feedback', json={})
    assert resp.status_code == 400
    # Avaliação inválida
    data = {'id_artigo': 'a3', 'prompt': 'p3', 'avaliacao': 5}
    resp2 = c.post('/feedback', json=data)
    assert resp2.status_code == 400
    # Comentário inválido
    data = {'id_artigo': 'a3', 'prompt': 'p3', 'avaliacao': 1, 'comentario': 123}
    resp3 = c.post('/feedback', json=data)
    assert resp3.status_code == 400

def test_get_feedback():
    c = client()
    data = {'id_artigo': 'a4', 'prompt': 'p4', 'avaliacao': 0}
    c.post('/feedback', json=data)
    resp = c.get('/feedback/a4')
    assert resp.status_code == 200
    feedbacks = resp.get_json()
    assert isinstance(feedbacks, list)
    assert any(f['id_artigo'] == 'a4' for f in feedbacks)

def test_submit_feedback_duplicate_cobertura():
    c = client()
    data = {'id_artigo': 'dup1', 'prompt': 'pdup', 'avaliacao': 1}
    resp1 = c.post('/feedback', json=data)
    resp2 = c.post('/feedback', json=data)
    assert resp2.status_code == 200
    assert resp2.get_json()['status'] == 'duplicado' 