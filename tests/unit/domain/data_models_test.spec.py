import pytest
from omni_writer.domain.data_models import PromptInput, ArticleOutput, GenerationConfig

# Testes para PromptInput
@pytest.mark.parametrize("text,index,expected_exception", [
    ("Prompt válido", 0, None),
    ("", 0, ValueError),
    (None, 0, ValueError),
    ("Prompt válido", -1, ValueError),
    ("Prompt válido", None, ValueError),
])
def test_prompt_input_validation(text, index, expected_exception):
    if expected_exception:
        with pytest.raises(expected_exception):
            PromptInput(text=text, index=index)
    else:
        obj = PromptInput(text=text, index=index)
        assert obj.text == text
        assert obj.index == index
        assert isinstance(obj.to_dict(), dict)

# Testes para ArticleOutput
@pytest.mark.parametrize("content,filename,metadata", [
    ("Conteúdo de artigo", "artigo.txt", None),
    ("Outro artigo", "outro.txt", {"meta": 1}),
])
def test_article_output_to_dict(content, filename, metadata):
    obj = ArticleOutput(content=content, filename=filename, metadata=metadata)
    d = obj.to_dict()
    assert d["content"] == content
    assert d["filename"] == filename
    assert d["metadata"] == metadata

# Testes para GenerationConfig
@pytest.mark.parametrize("api_key,model_type,prompts,temperature,max_tokens,language,expected_exception", [
    ("chave", "openai", [PromptInput(text="p1", index=0)], 0.7, 4096, "pt-BR", None),
    ("chave", "deepseek", [PromptInput(text="p1", index=0)], 1.0, 4096, "en", None),
    ("", "openai", [PromptInput(text="p1", index=0)], 0.7, 4096, "pt-BR", ValueError),
    ("chave", "modelo_invalido", [PromptInput(text="p1", index=0)], 0.7, 4096, "pt-BR", ValueError),
    ("chave", "openai", [], 0.7, 4096, "pt-BR", ValueError),
    ("chave", "openai", [PromptInput(text="p1", index=0)], -0.1, 4096, "pt-BR", ValueError),
    ("chave", "openai", [PromptInput(text="p1", index=0)], 0.7, 100, "pt-BR", ValueError),
    ("chave", "openai", [PromptInput(text="p1", index=0)], 0.7, 4096, "", ValueError),
])
def test_generation_config_validation(api_key, model_type, prompts, temperature, max_tokens, language, expected_exception):
    if expected_exception:
        with pytest.raises(expected_exception):
            GenerationConfig(api_key=api_key, model_type=model_type, prompts=prompts, temperature=temperature, max_tokens=max_tokens, language=language)
    else:
        obj = GenerationConfig(api_key=api_key, model_type=model_type, prompts=prompts, temperature=temperature, max_tokens=max_tokens, language=language)
        assert obj.api_key == api_key
        assert obj.model_type == model_type
        assert obj.prompts == prompts
        assert obj.temperature == temperature
        assert obj.max_tokens == max_tokens
        assert obj.language == language
        assert isinstance(obj.to_dict(), dict) 