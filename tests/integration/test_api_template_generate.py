import pytest
from app.app_factory import create_app

def test_index_template():
    with create_app().test_client() as c:
        resp = c.get('/')
        assert resp.status_code == 200
        assert b'OmniWriter' in resp.data

def test_generate_sem_dados():
    with create_app().test_client() as c:
        resp = c.post('/generate', data={})
        assert resp.status_code == 200
        assert b'erro' in resp.data or b'Prompts' in resp.data 