import pytest
from unittest import mock
from omni_writer.domain.data_models import GenerationConfig, PromptInput
from infraestructure.deepseek_gateway import generate_article_deepseek
from omni_writer.domain.data_models import ArticleOutput

@pytest.fixture
def config():
    return GenerationConfig(
        api_key="key",
        model_type="deepseek",
        prompts=[PromptInput(text="p1", index=0)],
        temperature=0.7,
        max_tokens=4096,
        language="pt-BR"
    )

@pytest.fixture
def prompt():
    return PromptInput(text="p1", index=0)

# Sucesso
@mock.patch("infraestructure.deepseek_gateway.requests.post")
def test_generate_article_deepseek_success(mock_post, config, prompt):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"choices": [{"message": {"content": "artigo gerado"}}]}
    mock_post.return_value.raise_for_status = lambda: None
    result = generate_article_deepseek(config, prompt)
    assert isinstance(result, ArticleOutput)
    assert result.content == "artigo gerado"
    assert result.filename.startswith("artigo_")

# Falha HTTP
@mock.patch("infraestructure.deepseek_gateway.requests.post")
def test_generate_article_deepseek_http_error(mock_post, config, prompt):
    mock_post.return_value.raise_for_status.side_effect = Exception("HTTP error")
    with pytest.raises(Exception):
        generate_article_deepseek(config, prompt)

# Falha de parsing
@mock.patch("infraestructure.deepseek_gateway.requests.post")
def test_generate_article_deepseek_parsing_error(mock_post, config, prompt):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {}
    mock_post.return_value.raise_for_status = lambda: None
    with pytest.raises(Exception):
        generate_article_deepseek(config, prompt)

# Timeout
@mock.patch("infraestructure.deepseek_gateway.requests.post")
def test_generate_article_deepseek_timeout(mock_post, config, prompt):
    mock_post.side_effect = Exception("timeout")
    with pytest.raises(Exception):
        generate_article_deepseek(config, prompt) 