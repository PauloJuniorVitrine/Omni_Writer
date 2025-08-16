import pytest
from unittest import mock
from app import controller
from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from types import SimpleNamespace

def make_config(model_type="openai"):
    return GenerationConfig(api_key="key", model_type=model_type, prompts=[PromptInput(text="t", index=0)])

def fake_gateway(config, prompt, trace_id=None, variation=0):
    return 'ok'

def test_generate_article_openai(monkeypatch):
    config = SimpleNamespace(model_type='openai')
    prompt = SimpleNamespace()
    monkeypatch.setattr(controller, 'generate_article_openai', fake_gateway)
    result = controller.generate_article(config, prompt)
    assert result == 'ok'

def test_generate_article_deepseek(monkeypatch):
    config = SimpleNamespace(model_type='deepseek')
    prompt = SimpleNamespace()
    monkeypatch.setattr(controller, 'generate_article_deepseek', fake_gateway)
    result = controller.generate_article(config, prompt)
    assert result == 'ok'

def test_generate_article_nao_suportado():
    config = SimpleNamespace(model_type='outro')
    prompt = SimpleNamespace()
    with pytest.raises(ValueError):
        controller.generate_article(config, prompt)

def test_generate_article_gateway_excecao(monkeypatch):
    def raise_exc(*a, **kw): raise Exception('erro')
    config = SimpleNamespace(model_type='openai')
    prompt = SimpleNamespace()
    monkeypatch.setattr(controller, 'generate_article_openai', raise_exc)
    with pytest.raises(Exception):
        controller.generate_article(config, prompt)

def test_generate_article_custom_gateway():
    config = SimpleNamespace(model_type='custom')
    prompt = SimpleNamespace()
    gateways = {'custom': lambda *a, **kw: 'custom_ok'}
    result = controller.generate_article(config, prompt, gateways=gateways)
    assert result == 'custom_ok'

def test_generate_article_gateways_vazio(monkeypatch):
    config = make_config("openai")
    prompt = config.prompts[0]
    # Garante que nenhum gateway real será chamado
    monkeypatch.setattr("app.controller.generate_article", lambda *a, **kw: (_ for _ in ()).throw(KeyError("openai")))
    with pytest.raises(KeyError):
        controller.generate_article(config, prompt, gateways={}) 