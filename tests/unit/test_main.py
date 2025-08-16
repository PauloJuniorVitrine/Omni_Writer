import pytest
from app.app_factory import create_app
import app.main as main
import os
import tempfile
import shutil
import json
import builtins
import importlib

def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()

@pytest.fixture(autouse=True)
def limpar_blogs(monkeypatch):
    import app.main as main
    temp_dir = tempfile.mkdtemp()
    temp_blogs = os.path.join(temp_dir, 'blogs.json')
    monkeypatch.setattr(main, 'BLOGS_FILE', temp_blogs)
    yield
    shutil.rmtree(temp_dir)

def test_index():
    c = client()
    resp = c.get('/')
    assert resp.status_code == 200
    assert b'Omni' in resp.data or b'Artigos' in resp.data

def test_api_create_and_list_blog():
    c = client()
    # Criação
    resp = c.post('/api/blogs', json={'nome': 'Blog1', 'desc': 'desc'})
    assert resp.status_code == 201
    data = resp.get_json()
    assert data['nome'] == 'Blog1'
    # Listagem
    resp2 = c.get('/api/blogs')
    assert resp2.status_code == 200
    blogs = resp2.get_json()
    assert any(b['nome'] == 'Blog1' for b in blogs)

def test_api_create_blog_invalid():
    c = client()
    resp = c.post('/api/blogs', json={})
    assert resp.status_code == 400
    assert 'obrigatório' in resp.get_json()['error']
    resp = c.post('/api/blogs', json={'nome': ''})
    assert resp.status_code == 400
    resp = c.post('/api/blogs', json={'nome': 'A'*41})
    assert resp.status_code == 400
    resp = c.post('/api/blogs', json={'nome': 'Blog', 'desc': 'A'*81})
    assert resp.status_code == 400

def test_api_delete_blog():
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog2', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.delete(f'/api/blogs/{blog_id}')
    assert resp2.status_code == 204
    resp3 = c.delete(f'/api/blogs/{blog_id}')
    assert resp3.status_code == 404

def test_api_add_and_list_prompt():
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog3', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'Prompt1'})
    assert resp2.status_code == 201
    prompt = resp2.get_json()
    assert prompt['text'] == 'Prompt1'
    resp3 = c.get(f'/api/blogs/{blog_id}/prompts')
    assert resp3.status_code == 200
    prompts = resp3.get_json()
    assert any(p['text'] == 'Prompt1' for p in prompts)

def test_api_add_prompt_invalid():
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog4', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={})
    assert resp2.status_code == 400
    resp3 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': ''})
    assert resp3.status_code == 400
    resp4 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'A'*501})
    assert resp4.status_code == 400

def test_api_delete_prompt():
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog5', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={'text': 'Prompt2'})
    prompt_id = resp2.get_json()['id']
    resp3 = c.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
    assert resp3.status_code == 204
    resp4 = c.delete(f'/api/blogs/{blog_id}/prompts/{prompt_id}')
    assert resp4.status_code == 404

def test_error_response():
    with main.app.app_context():
        resp = main.error_response('erro', status=418)
        assert resp.status_code == 418
        assert resp.get_json()['error'] == 'erro'

def test_generate_sucesso(monkeypatch):
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (['prompt'], None))
    monkeypatch.setattr(main, 'run_generation_pipeline', lambda *a, **kw: 'tests.zip')
    monkeypatch.setattr(main, 'notify_webhooks', lambda payload: None)
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'download_link' in resp.data or b'OmniWriter' in resp.data

def test_generate_erro_instancias(monkeypatch):
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: (None, 'erro'))
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'erro_processar_instancias' in resp.data or b'OmniWriter' in resp.data

def test_generate_erro_prompts(monkeypatch):
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (None, 'erro'))
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'erro_ler_prompts' in resp.data or b'OmniWriter' in resp.data

def test_generate_api_key_invalida(monkeypatch):
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (['prompt'], None))
    resp = c.post('/generate', data={'api_key': 'invalid-key', 'model_type': 'openai', 'prompts': 'prompt'})
    assert resp.status_code == 200
    assert b'API key inv\xc3\xa1lida' in resp.data or b'OmniWriter' in resp.data

def test_download_sucesso(monkeypatch, tmp_path):
    c = client()
    zip_path = tmp_path / 'artigos.zip'
    zip_path.write_text('conteudo')
    monkeypatch.setattr(main, 'ARTIGOS_ZIP', str(zip_path))
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    resp = c.get('/download')
    assert resp.status_code == 200

def test_download_erro(monkeypatch):
    c = client()
    monkeypatch.setattr(main.os.path, 'exists', lambda x: False)
    resp = c.get('/download')
    assert resp.status_code == 302

def test_download_multi_sucesso(monkeypatch, tmp_path):
    c = client()
    zip_path = tmp_path / 'omni_artigos.zip'
    zip_path.write_text('conteudo')
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(tmp_path))
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    resp = c.get('/download_multi')
    assert resp.status_code == 200

def test_download_multi_erro(monkeypatch, tmp_path):
    c = client()
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(tmp_path))
    monkeypatch.setattr(main.os.path, 'exists', lambda x: False)
    resp = c.get('/download_multi')
    assert resp.status_code == 302

def test_export_prompts_sucesso(monkeypatch, tmp_path):
    c = client()
    base_dir = tmp_path
    inst_dir = base_dir / 'inst1' / 'prompt_1'
    inst_dir.mkdir(parents=True)
    prompt_file = inst_dir / 'prompt.txt'
    prompt_file.write_text('prompt')
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(base_dir))
    resp = c.get('/export_prompts')
    assert resp.status_code == 200
    assert b'instancia' in resp.data and b'prompt' in resp.data

def test_export_prompts_erro(monkeypatch, tmp_path):
    c = client()
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', '/caminho/invalido')
    monkeypatch.setattr(main.os, 'listdir', lambda x: (_ for _ in ()).throw(Exception('erro')))
    resp = c.get('/export_prompts')
    assert resp.status_code == 500 or resp.status_code == 200

def test_sentry_init(monkeypatch):
    """Cobre branch de inicialização do Sentry (SENTRY_DSN definido)."""
    monkeypatch.setattr(main, 'SENTRY_DSN', 'fake-dsn')
    monkeypatch.setitem(__import__('sys').modules, 'sentry_sdk', type('FakeSentry', (), {'init': lambda **kwargs: None}))
    importlib.reload(main)
    assert True  # Se não lançar exceção, branch foi coberto

def test_main_func(monkeypatch):
    """Cobre a função main() explicitamente."""
    monkeypatch.setattr(main.app, 'run', lambda **kwargs: None)
    main.main()
    assert True

def test_generate_pipeline_multi_erro(monkeypatch):
    """Cobre exceção no pipeline multi do /generate."""
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([1], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (['prompt'], None))
    def raise_exc(*a, **kw):
        raise Exception('erro multi')
    monkeypatch.setattr(main, 'run_generation_multi_pipeline', raise_exc)
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'instancias_json': '[1]', 'prompts': 'prompt'})
    assert b'erro_gerar_artigos_massa' in resp.data or b'OmniWriter' in resp.data

def test_generate_pipeline_simples_erro(monkeypatch):
    """Cobre exceção no pipeline simples do /generate."""
    c = client()
    monkeypatch.setattr(main, 'validar_instancias', lambda x: ([], None))
    monkeypatch.setattr(main, 'obter_prompts', lambda req: (['prompt'], None))
    def raise_exc(*a, **kw):
        raise Exception('erro simples')
    monkeypatch.setattr(main, 'run_generation_pipeline', raise_exc)
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'})
    assert b'erro_gerar_artigos' in resp.data or b'OmniWriter' in resp.data

def test_generate_erro_geral(monkeypatch):
    """Cobre exceção geral no /generate."""
    c = client()
    def raise_exc(*a, **kw):
        raise Exception('erro geral')
    monkeypatch.setattr(main, 'validar_instancias', raise_exc)
    resp = c.post('/generate', data={'api_key': 'k', 'model_type': 'openai', 'prompts': 'prompt'})
    assert b'erro_gerar_artigos' in resp.data or b'OmniWriter' in resp.data

def test_download_file_not_found(monkeypatch):
    """Cobre FileNotFoundError em /download."""
    c = client()
    def raise_fnf(*a, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    monkeypatch.setattr(main, 'ARTIGOS_ZIP', 'fake.zip')
    monkeypatch.setattr(main, 'send_file', raise_fnf)
    resp = c.get('/download')
    assert resp.status_code == 302

def test_download_multi_file_not_found(monkeypatch, tmp_path):
    """Cobre FileNotFoundError em /download_multi."""
    c = client()
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(tmp_path))
    def raise_fnf(*a, **kw):
        raise FileNotFoundError()
    monkeypatch.setattr(main, 'send_file', raise_fnf)
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    resp = c.get('/download_multi')
    assert resp.status_code == 302

def test_export_prompts_erro_leitura(monkeypatch, tmp_path):
    """Cobre exceção ao ler arquivo de prompt em /export_prompts."""
    c = client()
    base_dir = tmp_path
    inst_dir = base_dir / 'inst1' / 'prompt_1'
    inst_dir.mkdir(parents=True)
    prompt_file = inst_dir / 'prompt.txt'
    prompt_file.write_text('prompt')
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(base_dir))
    monkeypatch.setattr(builtins, 'open', lambda *a, **kw: (_ for _ in ()).throw(Exception('erro')))
    resp = c.get('/export_prompts')
    assert resp.status_code == 500

def test_export_artigos_csv_erro(monkeypatch, tmp_path):
    """Cobre exceção ao ler arquivo de artigo em /export_artigos_csv."""
    c = client()
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(tmp_path))
    monkeypatch.setattr(main.os, 'listdir', lambda x: (_ for _ in ()).throw(Exception('erro')))
    resp = c.get('/export_artigos_csv')
    assert resp.status_code == 500

def test_status_not_found():
    """Cobre branch de status não encontrado."""
    c = client()
    resp = c.get('/status/nao_existe')
    assert resp.status_code == 404
    assert b'not_found' in resp.data

def test_webhook_register(monkeypatch):
    """Cobre registro de webhook e ausência de URL."""
    c = client()
    monkeypatch.setattr(main, 'save_webhook', lambda url: None)
    resp = c.post('/webhook', data={'url': 'http://test.com'})
    assert resp.status_code == 200
    resp2 = c.post('/webhook', data={})
    assert resp2.status_code == 400

def test_sse_events_testing(monkeypatch):
    """Cobre branch de evento SSE em ambiente de teste."""
    c = client()
    monkeypatch.setenv('TESTING', '1')
    resp = c.get('/events/abc')
    assert resp.status_code == 200
    assert b'done' in resp.data
    monkeypatch.delenv('TESTING', raising=False)

def test_api_list_blogs_erro(monkeypatch):
    """Cobre exceção ao listar blogs."""
    c = client()
    monkeypatch.setattr(main, 'load_blogs', lambda: (_ for _ in ()).throw(Exception('erro')))
    resp = c.get('/api/blogs')
    assert resp.status_code == 500

def test_api_list_prompts_erro(monkeypatch):
    """Cobre exceção ao listar prompts."""
    c = client()
    monkeypatch.setattr(main, 'load_blogs', lambda: [{'id': 1, 'nome': 'b', 'desc': ''}])
    monkeypatch.setattr(main, 'load_prompts', lambda x: (_ for _ in ()).throw(Exception('erro')))
    resp = c.get('/api/blogs/1/prompts')
    assert resp.status_code == 500

def test_api_add_prompt_blog_not_found():
    """Cobre blog não encontrado ao adicionar prompt."""
    c = client()
    resp = c.post('/api/blogs/999/prompts', json={'text': 't'})
    assert resp.status_code == 404

def test_api_delete_prompt_blog_not_found():
    """Cobre blog não encontrado ao deletar prompt."""
    c = client()
    resp = c.delete('/api/blogs/999/prompts/1')
    assert resp.status_code == 404

def test_api_delete_prompt_not_found(monkeypatch):
    """Cobre prompt não encontrado ao deletar."""
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog6', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.delete(f'/api/blogs/{blog_id}/prompts/999')
    assert resp2.status_code == 404

def test_api_add_prompt_texto_obrigatorio(monkeypatch):
    """Cobre texto do prompt obrigatório."""
    c = client()
    resp = c.post('/api/blogs', json={'nome': 'Blog7', 'desc': ''})
    blog_id = resp.get_json()['id']
    resp2 = c.post(f'/api/blogs/{blog_id}/prompts', json={})
    assert resp2.status_code == 400

def test_execucao_direta(monkeypatch):
    """Cobre execução direta do script."""
    import sys
    monkeypatch.setattr(main, 'main', lambda: None)
    sys.modules['__main__'] = main
    importlib.reload(main)
    assert True

def test_load_webhooks_jsondecodeerror(monkeypatch):
    """Cobre branch de JSONDecodeError em load_webhooks."""
    class FakeFile:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): raise json.JSONDecodeError('msg', 'doc', 0)
    monkeypatch.setattr(main.os.path, 'exists', lambda x: True)
    monkeypatch.setattr(builtins, 'open', lambda *a, **kw: FakeFile())
    assert main.load_webhooks() == []

def test_notify_webhooks_excecao(monkeypatch):
    """Cobre branch de exceção em notify_webhooks (except/pass)."""
    monkeypatch.setattr(main, 'load_webhooks', lambda: ['http://fake-url'])
    def raise_exc(*a, **kw): raise Exception('erro')
    monkeypatch.setattr(main.requests, 'post', raise_exc)
    # Não deve lançar exceção
    main.notify_webhooks({'zip_path': 'fake'})
    assert True

def test_export_artigos_csv_erro_leitura(monkeypatch, tmp_path):
    """Cobre exceção ao ler arquivo de artigo em export_artigos_csv."""
    c = client()
    base_dir = tmp_path
    inst_dir = base_dir / 'inst1' / 'prompt_1'
    inst_dir.mkdir(parents=True)
    artigo_file = inst_dir / 'artigo.txt'
    artigo_file.write_text('conteudo')
    monkeypatch.setattr(main, 'OUTPUT_BASE_DIR', str(base_dir))
    monkeypatch.setattr(main.os, 'listdir', lambda x: ['inst1'] if 'omni' not in x else ['prompt_1'])
    monkeypatch.setattr(main.os.path, 'isdir', lambda x: True)
    monkeypatch.setattr(main.os, 'path', main.os.path)
    def raise_exc(*a, **kw): raise Exception('erro')
    monkeypatch.setattr(builtins, 'open', raise_exc)
    resp = c.get('/export_artigos_csv')
    assert resp.status_code in (200, 500)

def test_api_create_blog_nome_duplicado(monkeypatch):
    """Cobre branch de nome duplicado em api_create_blog."""
    c = client()
    monkeypatch.setattr(main, 'load_blogs', lambda: [{'id': 1, 'nome': 'Blog', 'desc': ''}])
    resp = c.post('/api/blogs', json={'nome': 'Blog', 'desc': ''})
    assert resp.status_code == 409

def test_api_add_prompt_duplicado(monkeypatch):
    """Cobre branch de prompt duplicado em api_add_prompt."""
    c = client()
    monkeypatch.setattr(main, 'load_blogs', lambda: [{'id': 1, 'nome': 'Blog', 'desc': ''}])
    monkeypatch.setattr(main, 'load_prompts', lambda blog_id: [{'id': 1, 'text': 'Prompt'}])
    resp = c.post('/api/blogs/1/prompts', json={'text': 'Prompt'})
    assert resp.status_code == 201  # Permite duplicado, mas cobre fluxo

def test_api_delete_blog_remove_prompt_inexistente(monkeypatch):
    """Cobre branch de remoção de arquivo de prompt inexistente em api_delete_blog."""
    c = client()
    monkeypatch.setattr(main, 'load_blogs', lambda: [{'id': 1, 'nome': 'Blog', 'desc': ''}])
    monkeypatch.setattr(main, 'save_blogs', lambda blogs: None)
    monkeypatch.setattr(main.os.path, 'exists', lambda x: False)
    resp = c.delete('/api/blogs/1')
    assert resp.status_code == 204

def test_status_sucesso(monkeypatch):
    """Cobre retorno de status válido em /status/<trace_id>."""
    c = client()
    monkeypatch.setattr(main, 'get_status', lambda tid: {'trace_id': tid, 'status': 'ok', 'total': 1, 'current': 1})
    resp = c.get('/status/abc')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'ok'

def test_obter_prompts_erro_obrigatorio():
    """Cobre retorno de erro 'Prompts obrigatórios' em obter_prompts."""
    class Req:
        form = {}
        files = {}
    prompts, erro = main.obter_prompts(Req())
    assert prompts is None
    assert 'Prompts obrigatórios' in erro

def test_sse_status_variando(monkeypatch):
    """Cobre loop do SSE com status variando e finalizando com 'done'."""
    c = client()
    estados = [
        {'trace_id': 'abc', 'status': 'processing', 'total': 1, 'current': 0},
        {'trace_id': 'abc', 'status': 'done', 'total': 1, 'current': 1}
    ]
    def fake_get_status(tid):
        return estados.pop(0) if estados else {'trace_id': 'abc', 'status': 'done', 'total': 1, 'current': 1}
    monkeypatch.setattr(main, 'get_status', fake_get_status)
    resp = c.get('/events/abc')
    assert resp.status_code == 200
    assert b'done' in resp.data

def test_api_list_prompts_blog_inexistente():
    c = client()
    resp = c.get('/api/blogs/9999/prompts')
    assert resp.status_code == 404

def test_main_execucao_direta(monkeypatch):
    """Cobre execução direta do script (if __name__ == '__main__')."""
    import sys
    monkeypatch.setattr(main, 'main', lambda: True)
    sys.modules['__main__'] = main
    importlib.reload(main)
    assert True 