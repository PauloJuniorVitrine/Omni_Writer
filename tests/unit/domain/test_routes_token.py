import pytest
from app import app as flask_app

def test_token_rotate_success(client):
    resp = client.post('/token/rotate', data={'user_id': 'usuario123'})
    assert resp.status_code == 200
    assert 'token' in resp.json

def test_token_rotate_missing_user_id(client):
    resp = client.post('/token/rotate', data={})
    assert resp.status_code == 400
    assert 'user_id obrigatório' in resp.json['error'] 