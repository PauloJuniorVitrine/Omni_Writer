import pytest
from unittest import mock
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput
from app.controller import generate_article

def make_config(model_type):
    return GenerationConfig(
        api_key="key",
        model_type=model_type,
        prompts=[PromptInput(text="p1", index=0)],
        temperature=0.7,
        max_tokens=4096,
        language="pt-BR"
    )

@pytest.fixture
def prompt():
    return PromptInput(text="p1", index=0)

# Sucesso com gateway openai
def test_generate_article_openai(prompt):
    config = make_config("openai")
    mock_gateway = mock.Mock(return_value=ArticleOutput(content="ok", filename="a.txt"))
    gateways = {"openai": mock_gateway}
    result = generate_article(config, prompt, gateways=gateways)
    assert result.content == "ok"
    mock_gateway.assert_called_once()

# Sucesso com gateway deepseek
def test_generate_article_deepseek(prompt):
    config = make_config("deepseek")
    mock_gateway = mock.Mock(return_value=ArticleOutput(content="ok2", filename="b.txt"))
    gateways = {"deepseek": mock_gateway}
    result = generate_article(config, prompt, gateways=gateways)
    assert result.content == "ok2"
    mock_gateway.assert_called_once()

# Modelo não suportado
def test_generate_article_modelo_nao_suportado(prompt):
    config = make_config("invalido")
    with pytest.raises(ValueError):
        generate_article(config, prompt)

# Propagação de exceção do gateway
def test_generate_article_gateway_exception(prompt):
    config = make_config("openai")
    mock_gateway = mock.Mock(side_effect=Exception("erro"))
    gateways = {"openai": mock_gateway}
    with pytest.raises(Exception):
        generate_article(config, prompt, gateways=gateways) 