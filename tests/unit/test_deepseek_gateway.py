import pytest
from unittest import mock
from infraestructure.deepseek_gateway import generate_article_deepseek
from omni_writer.domain.models import GenerationConfig, PromptInput
import requests

def make_config():
    return GenerationConfig(api_key="k", model_type="deepseek", prompts=[PromptInput(text="t", index=0)])

def test_generate_article_deepseek_success(monkeypatch):
    config = make_config()
    prompt = config.prompts[0]
    fake_resp = mock.Mock()
    fake_resp.json.return_value = {"choices": [{"message": {"content": "conteudo"}}]}
    fake_resp.raise_for_status = mock.Mock()
    with mock.patch("infraestructure.deepseek_gateway.requests.post", return_value=fake_resp) as mpost:
        result = generate_article_deepseek(config, prompt, trace_id="abc", variation=2)
        assert result.content == "conteudo"
        assert result.filename.startswith("artigo_")
        assert mpost.called

def test_generate_article_deepseek_http_error(monkeypatch):
    config = make_config()
    prompt = config.prompts[0]
    fake_resp = mock.Mock()
    fake_resp.raise_for_status.side_effect = Exception("fail")
    with mock.patch("infraestructure.deepseek_gateway.requests.post", return_value=fake_resp):
        with pytest.raises(Exception):
            generate_article_deepseek(config, prompt)

def test_generate_article_deepseek_httperror(monkeypatch):
    config = make_config()
    prompt = config.prompts[0]
    fake_resp = mock.Mock()
    fake_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("http fail")
    with mock.patch("infraestructure.deepseek_gateway.requests.post", return_value=fake_resp):
        with pytest.raises(requests.exceptions.HTTPError):
            generate_article_deepseek(config, prompt) 