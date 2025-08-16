import pytest
from flask import Flask
from app.app_factory import create_app

@pytest.fixture(scope='module')
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_list_blogs_empty(client):
    resp = client.get('/api/blogs')
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)

def test_create_blog_missing_nome(client):
    resp = client.post('/api/blogs', json={"desc": "desc"})
    assert resp.status_code == 400
    assert 'error' in resp.get_json()

def test_create_blog_success(client):
    resp = client.post('/api/blogs', json={"nome": "Blog Teste", "desc": "desc"})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['nome'] == "Blog Teste"
    assert 'id' in data
    blog_id = data['id']
    # Test update
    resp2 = client.put(f'/api/blogs/{blog_id}', json={"nome": "Blog Editado", "desc": "nova desc"})
    assert resp2.status_code == 200
    assert resp2.get_json()['nome'] == "Blog Editado"
    # Test add prompt
    resp3 = client.post(f'/api/blogs/{blog_id}/prompts', json={"text": "Prompt 1"})
    assert resp3.status_code == 201
    prompt_id = resp3.get_json()['id']
    # Test list prompts
    resp4 = client.get(f'/api/blogs/{blog_id}/prompts')
    assert resp4.status_code == 200
    assert isinstance(resp4.get_json(), list)
    # Test delete prompt
    resp5 = client.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
    assert resp5.status_code == 204
    # Test delete blog with no prompts
    resp6 = client.delete(f'/api/blogs/{blog_id}')
    assert resp6.status_code == 204

def test_delete_blog_not_found(client):
    resp = client.delete('/api/blogs/99999')
    assert resp.status_code == 404
    assert 'error' in resp.get_json()

def test_add_prompt_blog_not_found(client):
    resp = client.post('/api/blogs/99999/prompts', json={"text": "Prompt"})
    assert resp.status_code == 404
    assert 'error' in resp.get_json()

def test_add_prompt_missing_text(client):
    # Cria blog
    resp = client.post('/api/blogs', json={"nome": "Blog Prompt", "desc": "desc"})
    blog_id = resp.get_json()['id']
    resp2 = client.post(f'/api/blogs/{blog_id}/prompts', json={})
    assert resp2.status_code == 400
    assert 'error' in resp2.get_json()
    # Limpeza
    client.delete(f'/api/blogs/{blog_id}')

def test_generate_invalid(client):
    resp = client.post('/generate', data={})
    # Pode retornar JSON ou HTML, mas se JSON deve ter 'error'
    if resp.content_type == 'application/json':
        assert resp.status_code == 400
        assert 'error' in resp.get_json()

def test_feedback_invalid(client):
    resp = client.post('/feedback', data={})
    assert resp.status_code == 400
    assert 'error' in resp.get_json()

def test_status_not_found(client):
    resp = client.get('/status/nao_existe')
    assert resp.status_code == 404
    assert 'error' in resp.get_json()

def test_api_protegido_unauth(client):
    resp = client.get('/api/protegido')
    assert resp.status_code == 401
    assert 'error' in resp.get_json() 