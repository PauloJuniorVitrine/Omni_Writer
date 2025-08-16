import pytest
from app.app_factory import create_app

def test_crud_blog():
    with create_app().test_client() as c:
        # Criação
        resp = c.post('/api/blogs', json={'nome': 'Blog1', 'desc': 'Desc1'})
        assert resp.status_code == 201
        blog = resp.get_json()
        blog_id = blog['id']
        # Listagem
        resp2 = c.get('/api/blogs')
        assert resp2.status_code == 200
        blogs = resp2.get_json()
        assert any(b['id'] == blog_id for b in blogs)
        # Exclusão
        resp3 = c.delete(f'/api/blogs/{blog_id}')
        assert resp3.status_code == 204
        # Exclusão de inexistente
        resp4 = c.delete(f'/api/blogs/{blog_id}')
        assert resp4.status_code == 404

def test_crud_prompts():
    with create_app().test_client() as c:
        # Cria blog
        resp = c.post('/api/blogs', json={'nome': 'Blog2', 'desc': ''})
        blog_id = resp.get_json()['id']
        # Adiciona prompt
        resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'PromptX'})
        assert resp2.status_code == 201
        prompt = resp2.get_json()
        prompt_id = prompt['id']
        # Lista prompts
        resp3 = c.get(f'/api/blogs/{blog_id}/prompts')
        assert resp3.status_code == 200
        prompts = resp3.get_json()
        assert any(p['id'] == prompt_id for p in prompts)
        # Exclui prompt
        resp4 = c.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
        assert resp4.status_code == 204
        # Exclui prompt inexistente
        resp5 = c.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
        assert resp5.status_code == 404 