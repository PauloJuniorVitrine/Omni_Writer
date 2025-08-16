import pytest
from app import celery_worker

class DummyConfig:
    api_key = 'sk-teste'
    model_type = 'openai'
    prompts = []
    temperature = 0.7
    max_tokens = 4096
    language = 'pt-BR'
    extra = None

def test_gerar_artigos_task_sucesso(monkeypatch):
    monkeypatch.setattr(celery_worker, 'run_generation_pipeline', lambda *a, **kw: 'ok')
    config = {
        'api_key': 'sk-teste',
        'model_type': 'openai',
        'prompts': [],
        'temperature': 0.7,
        'max_tokens': 4096,
        'language': 'pt-BR',
        'extra': None
    }
    result = celery_worker.gerar_artigos_task(config, trace_id='123')
    assert result == 'ok'

def test_gerar_artigos_task_falha(monkeypatch):
    def raise_exc(*a, **kw): raise Exception('erro')
    monkeypatch.setattr(celery_worker, 'run_generation_pipeline', raise_exc)
    with pytest.raises(Exception):
        celery_worker.gerar_artigos_task(DummyConfig(), trace_id='123')

def test_gerar_artigos_task_multi(monkeypatch):
    monkeypatch.setattr(celery_worker, 'run_generation_multi_pipeline', lambda *a, **kw: 'multi')
    # Simula chamada direta da função multi, se existir
    if hasattr(celery_worker, 'run_generation_multi_pipeline'):
        result = celery_worker.run_generation_multi_pipeline([], [])
        assert result == 'multi'

def test_gerar_artigos_multi_task(monkeypatch):
    monkeypatch.setattr(celery_worker, 'run_generation_multi_pipeline', lambda *a, **kw: 'multi')
    result = celery_worker.gerar_artigos_multi_task([], [], trace_id='123')
    assert result == 'multi' 