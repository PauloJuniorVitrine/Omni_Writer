import pytest
from app.app_factory import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_crud_blog_completo(client):
    # Criação
    resp = client.post('/api/blogs', json={'nome': 'Blog1', 'desc': 'Desc1'})
    assert resp.status_code == 201
    blog = resp.get_json()
    blog_id = blog['id']
    # Atualização
    resp2 = client.put(f'/api/blogs/{blog_id}', json={'nome': 'Blog1 Editado', 'desc': 'Nova desc'})
    assert resp2.status_code == 200
    assert resp2.get_json()['nome'] == 'Blog1 Editado'
    # Listagem
    resp3 = client.get('/api/blogs')
    assert resp3.status_code == 200
    blogs = resp3.get_json()
    assert any(b['id'] == blog_id for b in blogs)
    # Paginação e filtro
    resp4 = client.get('/api/blogs?pagina=1&tamanho=10&nome=Blog1')
    assert resp4.status_code == 200
    # Exclusão
    resp5 = client.delete(f'/api/blogs/{blog_id}')
    assert resp5.status_code == 204
    # Exclusão de inexistente
    resp6 = client.delete(f'/api/blogs/{blog_id}')
    assert resp6.status_code == 404

def test_criar_blog_dados_invalidos(client):
    resp = client.post('/api/blogs', json={'nome': '', 'desc': ''})
    assert resp.status_code in (400, 422)
    assert b'erro' in resp.data.lower() or b'invalido' in resp.data.lower()

def test_excluir_blog_com_prompts(client):
    # Cria blog
    resp = client.post('/api/blogs', json={'nome': 'Blog2', 'desc': 'Desc2'})
    blog_id = resp.get_json()['id']
    # Adiciona prompt vinculado
    resp2 = client.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'Prompt vinculado'})
    assert resp2.status_code == 201
    # Tenta excluir
    resp3 = client.delete(f'/api/blogs/{blog_id}')
    # Deve bloquear exclusão por prompt vinculado
    assert resp3.status_code == 409
    assert b'prompt' in resp3.data.lower() or b'vinculado' in resp3.data.lower() or b'erro' in resp3.data.lower() 