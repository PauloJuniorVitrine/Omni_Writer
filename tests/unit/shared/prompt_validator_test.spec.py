#!/usr/bin/env python3
"""
Testes unitários para o sistema de validação de prompts.
Cobre validação, estimativa de tokens e sugestões de correção.
"""

import pytest
from shared.prompt_validator import PromptValidator, ValidationResult, TokenEstimate

class TestPromptValidator:
    """Testes para PromptValidator."""
    
    @pytest.fixture
    def validator(self):
        """Instância do validador para testes."""
        return PromptValidator()
    
    def test_init(self, validator):
        """Testa inicialização do validador."""
        assert validator.validation_rules['min_length'] == 10
        assert validator.validation_rules['max_length'] == 4000
        assert len(validator.validation_rules['forbidden_words']) > 0
        assert len(validator.token_estimates['openai']) > 0
    
    def test_validate_prompt_valid(self, validator):
        """Testa validação de prompt válido."""
        valid_prompt = """
        Contexto: Artigo sobre tecnologia
        Objetivo: Escrever um artigo sobre inteligência artificial
        Tema: IA e seu impacto na sociedade moderna
        Formato: Artigo de 500 palavras
        Tom: Informativo e acessível
        """
        
        result = validator.validate_prompt(valid_prompt)
        
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.estimated_tokens > 0
        assert result.estimated_cost > 0
        assert result.validation_time_ms > 0
        assert result.prompt_hash is not None
    
    def test_validate_prompt_too_short(self, validator):
        """Testa validação de prompt muito curto."""
        short_prompt = "test"
        
        result = validator.validate_prompt(short_prompt)
        
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any("muito curto" in error for error in result.errors)
    
    def test_validate_prompt_too_long(self, validator):
        """Testa validação de prompt muito longo."""
        long_prompt = "test " * 1000  # 5000 caracteres
        
        result = validator.validate_prompt(long_prompt)
        
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any("muito longo" in error for error in result.errors)
    
    def test_validate_prompt_missing_required_elements(self, validator):
        """Testa validação de prompt sem elementos obrigatórios."""
        incomplete_prompt = "Escreva um texto sobre qualquer coisa"
        
        result = validator.validate_prompt(incomplete_prompt)
        
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any("obrigatórios ausentes" in error for error in result.errors)
    
    def test_validate_prompt_with_forbidden_words(self, validator):
        """Testa validação de prompt com palavras proibidas."""
        sensitive_prompt = "Escreva um artigo sobre senhas e tokens de API"
        
        result = validator.validate_prompt(sensitive_prompt)
        
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any("sensível detectado" in error for error in result.errors)
    
    def test_validate_prompt_with_suggestions(self, validator):
        """Testa validação de prompt com sugestões."""
        basic_prompt = "Escreva um artigo sobre tecnologia"
        
        result = validator.validate_prompt(basic_prompt)
        
        assert len(result.suggestions) > 0
        assert any("Considere adicionar" in suggestion for suggestion in result.suggestions)
    
    def test_estimate_tokens_openai_gpt4(self, validator):
        """Testa estimativa de tokens para GPT-4."""
        prompt = "Escreva um artigo sobre inteligência artificial"
        
        estimate = validator._estimate_tokens(prompt, 'openai', 'gpt-4')
        
        assert estimate.total_tokens > 0
        assert estimate.input_tokens > 0
        assert estimate.output_tokens > 0
        assert estimate.estimated_cost_usd > 0
        assert estimate.model_type == 'openai'
    
    def test_estimate_tokens_deepseek(self, validator):
        """Testa estimativa de tokens para DeepSeek."""
        prompt = "Escreva um artigo sobre programação"
        
        estimate = validator._estimate_tokens(prompt, 'deepseek', 'deepseek-chat')
        
        assert estimate.total_tokens > 0
        assert estimate.input_tokens > 0
        assert estimate.output_tokens > 0
        assert estimate.estimated_cost_usd > 0
        assert estimate.model_type == 'deepseek'
    
    def test_estimate_tokens_unknown_model(self, validator):
        """Testa estimativa de tokens para modelo desconhecido."""
        prompt = "Escreva um artigo"
        
        estimate = validator._estimate_tokens(prompt, 'unknown', 'unknown-model')
        
        assert estimate.total_tokens > 0
        assert estimate.estimated_cost_usd > 0
    
    def test_cache_functionality(self, validator):
        """Testa funcionalidade de cache."""
        prompt = "Escreva um artigo sobre cache"
        
        # Primeira validação
        result1 = validator.validate_prompt(prompt)
        
        # Segunda validação (deve usar cache)
        result2 = validator.validate_prompt(prompt)
        
        assert result1.prompt_hash == result2.prompt_hash
        assert result1.estimated_tokens == result2.estimated_tokens
        assert result1.estimated_cost == result2.estimated_cost
    
    def test_get_suggestions_for_prompt(self, validator):
        """Testa geração de sugestões para prompt."""
        short_prompt = "Escreva algo"
        
        suggestions = validator.get_suggestions_for_prompt(short_prompt)
        
        assert len(suggestions) > 0
        assert all(isinstance(suggestion, str) for suggestion in suggestions)
    
    def test_validate_multiple_prompts(self, validator):
        """Testa validação de múltiplos prompts."""
        prompts = [
            "Escreva um artigo sobre tecnologia",
            "Escreva um artigo sobre saúde",
            "Escreva um artigo sobre educação"
        ]
        
        results = validator.validate_multiple_prompts(prompts)
        
        assert len(results) == 3
        assert all(isinstance(result, ValidationResult) for result in results)
    
    def test_get_validation_stats(self, validator):
        """Testa obtenção de estatísticas de validação."""
        # Executa algumas validações
        validator.validate_prompt("Prompt 1")
        validator.validate_prompt("Prompt 2")
        validator.validate_prompt("Prompt 3")
        
        stats = validator.get_validation_stats()
        
        assert stats['total_validations'] >= 3
        assert 'validation_rate' in stats
        assert 'avg_tokens' in stats
        assert 'avg_cost_usd' in stats
        assert 'cache_size' in stats
    
    def test_validate_prompt_with_sensitive_patterns(self, validator):
        """Testa validação de prompt com padrões sensíveis."""
        # CPF
        cpf_prompt = "Escreva sobre o CPF 123.456.789-00"
        result = validator.validate_prompt(cpf_prompt)
        assert len(result.warnings) > 0
        
        # Email
        email_prompt = "Escreva sobre o email teste@exemplo.com"
        result = validator.validate_prompt(email_prompt)
        assert len(result.warnings) > 0
    
    def test_validate_prompt_structure(self, validator):
        """Testa validação de estrutura do prompt."""
        # Prompt sem parágrafos
        no_paragraphs = "Escreva um artigo sobre tecnologia. Deve ser informativo."
        result = validator.validate_prompt(no_paragraphs)
        assert any("parágrafos" in suggestion for suggestion in result.suggestions)
        
        # Prompt sem instruções claras
        no_instructions = "Artigo sobre tecnologia"
        result = validator.validate_prompt(no_instructions)
        assert any("instrução clara" in suggestion for suggestion in result.suggestions)
    
    def test_validate_prompt_repeated_words(self, validator):
        """Testa validação de palavras repetidas."""
        repeated_prompt = "Escreva um artigo sobre tecnologia. A tecnologia é importante. A tecnologia muda tudo."
        result = validator.validate_prompt(repeated_prompt)
        assert any("repetidas" in warning for warning in result.warnings)
    
    def test_cache_size_limit(self, validator):
        """Testa limite de tamanho do cache."""
        # Adiciona mais prompts que o limite do cache
        for i in range(validator.max_cache_size + 10):
            validator.validate_prompt(f"Prompt {i}")
        
        # Verifica se o cache não excedeu o limite
        assert len(validator.validation_cache) <= validator.max_cache_size
    
    def test_validation_result_dataclass(self):
        """Testa dataclass ValidationResult."""
        result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            suggestions=[],
            estimated_tokens=100,
            estimated_cost=0.01,
            validation_time_ms=5.0,
            prompt_hash="abc123"
        )
        
        assert result.is_valid is True
        assert result.estimated_tokens == 100
        assert result.estimated_cost == 0.01
        assert result.prompt_hash == "abc123"
    
    def test_token_estimate_dataclass(self):
        """Testa dataclass TokenEstimate."""
        estimate = TokenEstimate(
            total_tokens=150,
            input_tokens=50,
            output_tokens=100,
            estimated_cost_usd=0.02,
            model_type="openai"
        )
        
        assert estimate.total_tokens == 150
        assert estimate.input_tokens == 50
        assert estimate.output_tokens == 100
        assert estimate.estimated_cost_usd == 0.02
        assert estimate.model_type == "openai" 