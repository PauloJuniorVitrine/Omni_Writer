import pytest
from app.app_factory import create_app
import os
import tempfile
import shutil

@pytest.fixture(autouse=True)
def limpar_blogs(monkeypatch):
    # Redireciona o caminho do arquivo de blogs para um temporário
    temp_dir = tempfile.mkdtemp()
    temp_blogs = os.path.join(temp_dir, 'blogs.json')
    monkeypatch.setattr(create_app, 'BLOGS_FILE', temp_blogs)
    yield
    shutil.rmtree(temp_dir)

def test_blog_nome_obrigatorio():
    data = {'desc': 'desc'}
    with create_app.app.test_client() as c:
        resp = c.post('/api/blogs', json=data)
        assert resp.status_code == 400
        assert 'obrigatório' in resp.get_json()['error']

def test_blog_nome_unico():
    # Cria um blog
    with create_app.app.test_client() as c:
        c.post('/api/blogs', json={'nome': 'Unico', 'desc': ''})
        resp = c.post('/api/blogs', json={'nome': 'Unico', 'desc': ''})
        assert resp.status_code == 409
        assert 'existe' in resp.get_json()['error']

def test_blog_nome_tamanho():
    nome = 'A' * 41
    with create_app.app.test_client() as c:
        resp = c.post('/api/blogs', json={'nome': nome, 'desc': ''})
        assert resp.status_code == 400
        assert '40 caracteres' in resp.get_json()['error']

def test_prompt_texto_obrigatorio():
    # Cria blog
    with create_app.app.test_client() as c:
        resp = c.post('/api/blogs', json={'nome': 'BlogPrompt', 'desc': ''})
        blog_id = resp.get_json()['id']
        resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={})
        assert resp2.status_code == 400
        assert 'obrigatório' in resp2.get_json()['error']

def test_prompt_texto_tamanho():
    # Cria blog
    with create_app.app.test_client() as c:
        resp = c.post('/api/blogs', json={'nome': 'BlogPrompt2', 'desc': ''})
        blog_id = resp.get_json()['id']
        texto = 'A' * 501
        resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': texto})
        assert resp2.status_code == 400
        assert '500 caracteres' in resp2.get_json()['error'] 