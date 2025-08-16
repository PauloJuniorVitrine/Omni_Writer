import pytest
from app import app as flask_app

def test_feedback_valid(client):
    resp = client.post('/feedback', data={
        'user_id': 'usuario123',
        'artigo_id': 'artigo456',
        'tipo': 'positivo',
        'comentario': 'Ótimo artigo!'
    }, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 201
    assert resp.json['status'] == 'ok'

def test_feedback_invalid_fields(client):
    # user_id muito curto
    resp = client.post('/feedback', data={
        'user_id': 'a',
        'artigo_id': 'artigo456',
        'tipo': 'positivo',
        'comentario': 'Ótimo artigo!'
    }, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 400
    assert 'user_id inválido' in resp.json['detalhes']

def test_feedback_tipo_invalido(client):
    resp = client.post('/feedback', data={
        'user_id': 'usuario123',
        'artigo_id': 'artigo456',
        'tipo': 'spam',
        'comentario': 'Ótimo artigo!'
    }, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 400
    assert 'tipo inválido' in resp.json['detalhes']

def test_feedback_comentario_xss(client):
    resp = client.post('/feedback', data={
        'user_id': 'usuario123',
        'artigo_id': 'artigo456',
        'tipo': 'positivo',
        'comentario': '<script>alert(1)</script>'
    }, headers={'Authorization': 'Bearer token_valido'})
    assert resp.status_code == 201
    # O comentário deve ser sanitizado (não executável)
    assert '<script>' not in resp.json.get('comentario', '') 