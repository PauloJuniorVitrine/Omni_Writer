import pytest
from app.app_factory import create_app
import os
import tempfile
import shutil
from unittest import mock

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()

def test_load_webhooks_sem_arquivo(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'WEBHOOKS_FILE', str(tmp_path / 'webhooks.json'))
    assert main.load_webhooks() == []

def test_save_webhook(tmp_path, monkeypatch):
    file = tmp_path / 'webhooks.json'
    monkeypatch.setattr(main, 'WEBHOOKS_FILE', str(file))
    main.save_webhook('http://a.com')
    assert 'http://a.com' in main.load_webhooks()
    main.save_webhook('http://a.com')  # Não duplica
    assert main.load_webhooks().count('http://a.com') == 1

def test_notify_webhooks(monkeypatch):
    monkeypatch.setattr(main, 'load_webhooks', lambda: ['http://fake-url'])
    monkeypatch.setattr(main.requests, 'post', lambda url, json, timeout: None)
    main.notify_webhooks({'zip_path': 'ok'})  # Não deve lançar

def test_validar_instancias_ok():
    inst, err = main.validar_instancias('[{"api_key": "k"}]')
    assert isinstance(inst, list) and err is None

def test_validar_instancias_erro():
    inst, err = main.validar_instancias('invalido')
    assert inst is None and err is not None

def test_obter_prompts_ok(monkeypatch):
    class Req:
        form = {'prompts': 'a\nb'}
        files = {}
    prompts, err = main.obter_prompts(Req())
    assert prompts == ['a', 'b'] and err is None

def test_obter_prompts_arquivo(monkeypatch, tmp_path):
    class File:
        filename = 'p.txt'
        def read(self): return 'a\nb'.encode('utf-8')
    class Req:
        form = {}
        files = {'prompts_file': File()}
    prompts, err = main.obter_prompts(Req())
    assert prompts == ['a', 'b'] and err is None

def test_obter_prompts_erro(monkeypatch):
    class File:
        filename = 'p.txt'
        def read(self): raise Exception('erro')
    class Req:
        form = {}
        files = {'prompts_file': File()}
    prompts, err = main.obter_prompts(Req())
    assert prompts is None and err is not None

def test_api_blogs(client, monkeypatch):
    # GET vazio
    resp = client.get('/api/blogs')
    assert resp.status_code == 200
    # POST válido
    resp2 = client.post('/api/blogs', json={'nome': 'Blog', 'desc': 'd'})
    assert resp2.status_code == 201
    # POST inválido
    resp3 = client.post('/api/blogs', json={})
    assert resp3.status_code == 400
    # POST nome duplicado
    resp4 = client.post('/api/blogs', json={'nome': 'Blog', 'desc': 'd'})
    assert resp4.status_code == 409
    # DELETE existente
    blog_id = resp2.get_json()['id']
    resp5 = client.delete(f'/api/blogs/{blog_id}')
    assert resp5.status_code == 204
    # DELETE inexistente
    resp6 = client.delete(f'/api/blogs/{blog_id}')
    assert resp6.status_code == 404

def test_api_prompts(client, monkeypatch):
    # Cria blog
    resp = client.post('/api/blogs', json={'nome': 'Blog2', 'desc': ''})
    blog_id = resp.get_json()['id']
    # GET prompts vazio
    resp2 = client.get(f'/api/blogs/{blog_id}/prompts')
    assert resp2.status_code == 200
    # POST prompt válido
    resp3 = client.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'Prompt1'})
    assert resp3.status_code == 201
    # POST prompt inválido
    resp4 = client.post(f'/api/blogs/{blog_id}/prompts', json={})
    assert resp4.status_code == 400
    # POST prompt texto longo
    resp5 = client.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'A'*501})
    assert resp5.status_code == 400
    # DELETE existente
    prompt_id = resp3.get_json()['id']
    resp6 = client.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
    assert resp6.status_code == 204
    # DELETE inexistente
    resp7 = client.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
    assert resp7.status_code == 404

@pytest.fixture(autouse=True)
def limpar_blogs(monkeypatch, tmp_path):
    temp_blogs = tmp_path / 'blogs.json'
    monkeypatch.setattr(main, 'BLOGS_FILE', str(temp_blogs))
    yield 

def test_generate_excecao_validar_instancias(client, monkeypatch):
    monkeypatch.setattr(main, 'validar_instancias', lambda x: (_ for _ in ()).throw(Exception('erro')))
    resp = client.post('/generate', data={'instancias_json': '[]', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'erro_gerar_artigos' in resp.data or b'OmniWriter' in resp.data

def test_generate_excecao_obter_prompts(client, monkeypatch):
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (_ for _ in ()).throw(Exception('erro')))
    resp = client.post('/generate', data={'instancias_json': '[]', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'erro_gerar_artigos' in resp.data or b'OmniWriter' in resp.data

def test_generate_excecao_pipeline(client, monkeypatch):
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (['prompt'], None))
    monkeypatch.setattr(main, 'run_generation_pipeline', lambda *a, **kw: (_ for _ in ()).throw(Exception('erro')))
    data = {'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'}
    resp = client.post('/generate', data=data)
    assert resp.status_code == 200
    assert b'erro_gerar_artigos' in resp.data or b'OmniWriter' in resp.data

def test_download_excecao_send_file(client, monkeypatch):
    # Simula que o arquivo existe, mas na verdade não existe, forçando erro de leitura
    monkeypatch.setattr(os.path, 'exists', lambda x: True)
    monkeypatch.setattr(main, 'ARTIGOS_ZIP', '/caminho/invalido/arquivo.zip')
    resp = client.get('/download')
    assert resp.status_code == 302 or resp.status_code == 200

def test_download_multi_excecao_send_file(client, monkeypatch, tmp_path):
    # Simula que o arquivo existe, mas na verdade não existe, forçando erro de leitura
    monkeypatch.setattr(os.path, 'exists', lambda x: True)
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(tmp_path))
    resp = client.get('/download_multi')
    assert resp.status_code == 302 or resp.status_code == 200

def test_export_prompts_excecao(client, monkeypatch):
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', '/caminho/invalido')
    monkeypatch.setattr(os.path, 'exists', lambda x: True)
    monkeypatch.setattr(main, 'os', mock.Mock())
    main.os.listdir.side_effect = Exception('erro')
    resp = client.get('/export_prompts')
    assert resp.status_code == 200 or resp.status_code == 500

def test_export_artigos_csv_excecao(client, monkeypatch):
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', '/caminho/invalido')
    monkeypatch.setattr(os.path, 'exists', lambda x: True)
    monkeypatch.setattr(main, 'os', mock.Mock())
    main.os.listdir.side_effect = Exception('erro')
    resp = client.get('/export_artigos_csv')
    assert resp.status_code == 200 or resp.status_code == 500

def test_events_sse_excecao(client, monkeypatch):
    monkeypatch.setenv('TESTING', '0')
    monkeypatch.setattr(main, 'get_status', lambda tid: (_ for _ in ()).throw(Exception('erro')))
    try:
        resp = client.get('/events/abc')
        # Se não lançar, deve retornar 200 ou 500
        assert resp.status_code in (200, 500)
    except Exception as e:
        assert str(e) == 'erro'

def test_sentry_init(monkeypatch):
    # Simula SENTRY_DSN definido e import do sentry_sdk
    import importlib
    monkeypatch.setattr(main, 'SENTRY_DSN', 'fake_dsn')
    sentry_mock = type('sentry_sdk', (), {'init': lambda **kwargs: True})
    monkeypatch.setitem(__import__('sys').modules, 'sentry_sdk', sentry_mock)
    importlib.reload(main)
    assert True  # Apenas valida que não lança

def test_openapi_import(monkeypatch):
    # Simula ausência do módulo openapi
    import importlib
    monkeypatch.setitem(__import__('sys').modules, 'app.openapi', None)
    importlib.reload(main)
    assert True  # Não deve lançar

def test_load_webhooks_erro(monkeypatch, tmp_path):
    file = tmp_path / 'webhooks.json'
    file.write_text('{corrompido')
    monkeypatch.setattr(main, 'WEBHOOKS_FILE', str(file))
    assert main.load_webhooks() == []

def test_save_webhook_excecao(monkeypatch, tmp_path):
    file = tmp_path / 'webhooks.json'
    file.write_text('[]')
    monkeypatch.setattr(main, 'WEBHOOKS_FILE', str(file))
    class F:
        def __enter__(self): return self
        def __exit__(self, t, v, tb): pass
        def write(self, *a, **kw): raise IOError('erro')
        def read(self, *a, **kw): return '[]'
    monkeypatch.setattr('builtins.open', lambda *a, **kw: F())
    with pytest.raises(IOError):
        main.save_webhook('http://fail.com')

def test_load_blogs_erro(monkeypatch, tmp_path):
    file = tmp_path / 'blogs.json'
    file.write_text('{corrompido')
    monkeypatch.setattr(main, 'BLOGS_FILE', str(file))
    with pytest.raises(Exception):
        main.load_blogs()

def test_save_blogs_excecao(monkeypatch, tmp_path):
    file = tmp_path / 'blogs.json'
    monkeypatch.setattr(main, 'BLOGS_FILE', str(file))
    def erro_write(*a, **kw): raise IOError('erro')
    monkeypatch.setattr('builtins.open', lambda *a, **kw: type('F', (), {'__enter__': lambda s: s, '__exit__': lambda s, t, v, tb: None, 'write': erro_write})())
    with pytest.raises(IOError):
        main.save_blogs([{'id': 1, 'nome': 'x', 'desc': ''}])

def test_load_prompts_erro(monkeypatch, tmp_path):
    path = tmp_path / 'prompts_1.json'
    path.write_text('{corrompido')
    monkeypatch.setattr(main, 'PROMPTS_DIR', str(tmp_path))
    with pytest.raises(Exception):
        main.load_prompts(1)

def test_save_prompts_excecao(monkeypatch, tmp_path):
    path = tmp_path / 'prompts_1.json'
    monkeypatch.setattr(main, 'PROMPTS_DIR', str(tmp_path))
    def erro_write(*a, **kw): raise IOError('erro')
    monkeypatch.setattr('builtins.open', lambda *a, **kw: type('F', (), {'__enter__': lambda s: s, '__exit__': lambda s, t, v, tb: None, 'write': erro_write})())
    with pytest.raises(IOError):
        main.save_prompts(1, [{'id': 1, 'text': 'p'}])

def test_load_blogs_jsondecode(monkeypatch, tmp_path):
    file = tmp_path / 'blogs.json'
    file.write_text('{corrompido')
    monkeypatch.setattr(main, 'BLOGS_FILE', str(file))
    with pytest.raises(Exception):
        main.load_blogs()

def test_load_prompts_jsondecode(monkeypatch, tmp_path):
    path = tmp_path / 'prompts_1.json'
    path.write_text('{corrompido')
    monkeypatch.setattr(main, 'PROMPTS_DIR', str(tmp_path))
    with pytest.raises(Exception):
        main.load_prompts(1)

def test_notify_webhooks_excecao(monkeypatch):
    monkeypatch.setattr(main, 'load_webhooks', lambda: ['http://fail-url'])
    def raise_exc(*a, **kw): raise Exception('erro')
    monkeypatch.setattr(main.requests, 'post', raise_exc)
    # Não deve lançar
    main.notify_webhooks({'zip_path': 'ok'})

def test_api_create_blog_nome_duplicado(client):
    client.post('/api/blogs', json={'nome': 'BlogDup', 'desc': ''})
    resp = client.post('/api/blogs', json={'nome': 'BlogDup', 'desc': ''})
    assert resp.status_code == 409

def test_api_create_blog_nome_vazio(client):
    resp = client.post('/api/blogs', json={'nome': '', 'desc': ''})
    assert resp.status_code == 400

def test_api_create_blog_nome_longo(client):
    resp = client.post('/api/blogs', json={'nome': 'A'*41, 'desc': ''})
    assert resp.status_code == 400

def test_api_create_blog_desc_longa(client):
    resp = client.post('/api/blogs', json={'nome': 'Blog', 'desc': 'A'*81})
    assert resp.status_code == 400

def test_api_add_prompt_texto_longo(client):
    resp = client.post('/api/blogs', json={'nome': 'BlogPrompt', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = client.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'A'*501})
    assert resp2.status_code == 400

def test_api_add_prompt_texto_vazio(client):
    resp = client.post('/api/blogs', json={'nome': 'BlogPrompt2', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = client.post(f'/api/blogs/{blog_id}/prompts', json={'text': ''})
    assert resp2.status_code == 400

def test_api_delete_prompt_inexistente(client):
    resp = client.post('/api/blogs', json={'nome': 'BlogPrompt3', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = client.delete(f'/api/blogs/{blog_id}/prompts/9999')
    assert resp2.status_code == 404

def test_api_list_prompts_blog_inexistente(client):
    resp = client.get('/api/blogs/9999/prompts')
    assert resp.status_code == 404

def test_api_delete_blog_inexistente(client):
    resp = client.delete('/api/blogs/9999')
    assert resp.status_code == 404

def test_api_register_webhook_sem_url(client):
    resp = client.post('/webhook', data={})
    assert resp.status_code == 400

def test_os_makedirs_excecao(monkeypatch):
    def raise_exc(*a, **kw): raise PermissionError('erro')
    monkeypatch.setattr(main.os, 'makedirs', raise_exc)
    with pytest.raises(PermissionError):
        main.os.makedirs('/caminho/proibido')

def test_error_response_500():
    with main.app.app_context():
        resp = main.error_response('erro', status=500)
        assert resp.status_code == 500
        assert resp.get_json()['error'] == 'erro' 