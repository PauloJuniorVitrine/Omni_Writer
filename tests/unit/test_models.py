import pytest
from omni_writer.domain.models import PromptInput, ArticleOutput, GenerationConfig

# PromptInput

def test_promptinput_valid():
    p = PromptInput(text="Teste", index=0)
    assert p.text == "Teste"
    assert p.index == 0
    assert isinstance(p.to_dict(), dict)

def test_promptinput_invalid_text():
    with pytest.raises(ValueError):
        PromptInput(text="", index=0)
    with pytest.raises(ValueError):
        PromptInput(text=None, index=0)

def test_promptinput_invalid_index():
    with pytest.raises(ValueError):
        PromptInput(text="Teste", index=-1)
    with pytest.raises(ValueError):
        PromptInput(text="Teste", index=None)

# ArticleOutput

def test_articleoutput_to_dict():
    a = ArticleOutput(content="Conteúdo", filename="artigo.txt")
    d = a.to_dict()
    assert d["content"] == "Conteúdo"
    assert d["filename"] == "artigo.txt"

# GenerationConfig

def test_generationconfig_valid():
    prompts = [PromptInput(text="Teste", index=0)]
    c = GenerationConfig(api_key="key", model_type="openai", prompts=prompts)
    assert c.api_key == "key"
    assert c.model_type == "openai"
    assert c.prompts == prompts
    assert isinstance(c.to_dict(), dict)

def test_generationconfig_invalid_api_key():
    prompts = [PromptInput(text="Teste", index=0)]
    with pytest.raises(ValueError):
        GenerationConfig(api_key="", model_type="openai", prompts=prompts)

def test_generationconfig_invalid_model_type():
    prompts = [PromptInput(text="Teste", index=0)]
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="foo", prompts=prompts)

def test_generationconfig_invalid_prompts():
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=None)
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=["not_prompt"])

def test_generationconfig_invalid_temperature():
    prompts = [PromptInput(text="Teste", index=0)]
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, temperature=3.0)
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, temperature=-1.0)

def test_generationconfig_invalid_max_tokens():
    prompts = [PromptInput(text="Teste", index=0)]
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, max_tokens=100)
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, max_tokens=9000)

def test_generationconfig_invalid_language():
    prompts = [PromptInput(text="Teste", index=0)]
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, language="")
    with pytest.raises(ValueError):
        GenerationConfig(api_key="key", model_type="openai", prompts=prompts, language=None) 