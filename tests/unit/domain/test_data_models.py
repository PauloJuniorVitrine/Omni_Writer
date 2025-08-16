"""
Testes unitários para data models.

Prompt: Separação de Modelos - IMP-004
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:05:00Z
Tracing ID: ENTERPRISE_20250127_004
"""

import pytest
from omni_writer.domain.data_models import PromptInput, ArticleOutput, GenerationConfig


class TestDataModels:
    """Testes unitários para data models."""
    
    def test_prompt_input_valid(self):
        """Testa criação de PromptInput válido."""
        prompt = PromptInput(text="Como criar um blog profissional", index=0)
        
        assert prompt.text == "Como criar um blog profissional"
        assert prompt.index == 0
    
    def test_prompt_input_empty_text(self):
        """Testa falha na criação de PromptInput com texto vazio."""
        with pytest.raises(ValueError) as exc_info:
            PromptInput(text="", index=0)
        
        assert "erro_prompt_vazio" in str(exc_info.value)
    
    def test_prompt_input_whitespace_text(self):
        """Testa falha na criação de PromptInput com texto apenas espaços."""
        with pytest.raises(ValueError) as exc_info:
            PromptInput(text="   ", index=0)
        
        assert "erro_prompt_vazio" in str(exc_info.value)
    
    def test_prompt_input_negative_index(self):
        """Testa falha na criação de PromptInput com índice negativo."""
        with pytest.raises(ValueError) as exc_info:
            PromptInput(text="Teste", index=-1)
        
        assert "erro_indice_invalido" in str(exc_info.value)
    
    def test_prompt_input_to_dict(self):
        """Testa conversão de PromptInput para dicionário."""
        prompt = PromptInput(text="Teste", index=0)
        result = prompt.to_dict()
        
        assert result == {"text": "Teste", "index": 0}
    
    def test_article_output_valid(self):
        """Testa criação de ArticleOutput válido."""
        article = ArticleOutput(
            content="Conteúdo do artigo",
            filename="artigo.txt",
            metadata={"model": "openai"}
        )
        
        assert article.content == "Conteúdo do artigo"
        assert article.filename == "artigo.txt"
        assert article.metadata == {"model": "openai"}
    
    def test_article_output_without_metadata(self):
        """Testa criação de ArticleOutput sem metadata."""
        article = ArticleOutput(content="Conteúdo", filename="artigo.txt")
        
        assert article.content == "Conteúdo"
        assert article.filename == "artigo.txt"
        assert article.metadata is None
    
    def test_article_output_to_dict(self):
        """Testa conversão de ArticleOutput para dicionário."""
        article = ArticleOutput(
            content="Conteúdo",
            filename="artigo.txt",
            metadata={"model": "openai"}
        )
        result = article.to_dict()
        
        assert result == {
            "content": "Conteúdo",
            "filename": "artigo.txt",
            "metadata": {"model": "openai"}
        }
    
    def test_generation_config_valid(self):
        """Testa criação de GenerationConfig válido."""
        prompts = [PromptInput(text="Prompt 1", index=0)]
        config = GenerationConfig(
            api_key="test-api-key-123456789",
            model_type="openai",
            prompts=prompts,
            temperature=0.7,
            max_tokens=4096,
            language="pt-BR"
        )
        
        assert config.api_key == "test-api-key-123456789"
        assert config.model_type == "openai"
        assert config.prompts == prompts
        assert config.temperature == 0.7
        assert config.max_tokens == 4096
        assert config.language == "pt-BR"
    
    def test_generation_config_empty_api_key(self):
        """Testa falha na criação de GenerationConfig com API key vazia."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(api_key="", model_type="openai", prompts=prompts)
        
        assert "erro_api_key_vazia" in str(exc_info.value)
    
    def test_generation_config_invalid_model_type(self):
        """Testa falha na criação de GenerationConfig com tipo de modelo inválido."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(api_key="test", model_type="invalid", prompts=prompts)
        
        assert "modelo_nao_suportado" in str(exc_info.value)
    
    def test_generation_config_empty_prompts(self):
        """Testa falha na criação de GenerationConfig com lista de prompts vazia."""
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(api_key="test", model_type="openai", prompts=[])
        
        assert "erro_lista_prompts" in str(exc_info.value)
    
    def test_generation_config_invalid_prompts_type(self):
        """Testa falha na criação de GenerationConfig com tipo de prompts inválido."""
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(api_key="test", model_type="openai", prompts=["invalid"])
        
        assert "erro_lista_prompts" in str(exc_info.value)
    
    def test_generation_config_temperature_too_low(self):
        """Testa falha na criação de GenerationConfig com temperature muito baixa."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(
                api_key="test",
                model_type="openai",
                prompts=prompts,
                temperature=-0.1
            )
        
        assert "erro_temperature" in str(exc_info.value)
    
    def test_generation_config_temperature_too_high(self):
        """Testa falha na criação de GenerationConfig com temperature muito alta."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(
                api_key="test",
                model_type="openai",
                prompts=prompts,
                temperature=2.1
            )
        
        assert "erro_temperature" in str(exc_info.value)
    
    def test_generation_config_max_tokens_too_low(self):
        """Testa falha na criação de GenerationConfig com max_tokens muito baixo."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(
                api_key="test",
                model_type="openai",
                prompts=prompts,
                max_tokens=255
            )
        
        assert "erro_max_tokens" in str(exc_info.value)
    
    def test_generation_config_max_tokens_too_high(self):
        """Testa falha na criação de GenerationConfig com max_tokens muito alto."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(
                api_key="test",
                model_type="openai",
                prompts=prompts,
                max_tokens=8193
            )
        
        assert "erro_max_tokens" in str(exc_info.value)
    
    def test_generation_config_empty_language(self):
        """Testa falha na criação de GenerationConfig com idioma vazio."""
        prompts = [PromptInput(text="Teste", index=0)]
        
        with pytest.raises(ValueError) as exc_info:
            GenerationConfig(
                api_key="test",
                model_type="openai",
                prompts=prompts,
                language=""
            )
        
        assert "erro_idioma" in str(exc_info.value)
    
    def test_generation_config_to_dict(self):
        """Testa conversão de GenerationConfig para dicionário."""
        prompts = [PromptInput(text="Teste", index=0)]
        config = GenerationConfig(
            api_key="test",
            model_type="openai",
            prompts=prompts,
            extra={"key": "value"}
        )
        result = config.to_dict()
        
        assert result["api_key"] == "test"
        assert result["model_type"] == "openai"
        assert result["temperature"] == 0.7
        assert result["max_tokens"] == 4096
        assert result["language"] == "pt-BR"
        assert result["extra"] == {"key": "value"}
        assert len(result["prompts"]) == 1
        assert result["prompts"][0]["text"] == "Teste" 