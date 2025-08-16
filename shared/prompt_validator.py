#!/usr/bin/env python3
"""
Sistema de Pré-validação de Prompts para Omni Writer.
Valida prompts em tempo real, estima tokens e sugere correções.
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import logging

# Configuração de logging
validator_logger = logging.getLogger('prompt_validator')
validator_logger.setLevel(logging.INFO)

@dataclass
class ValidationResult:
    """Resultado da validação de prompt."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]
    estimated_tokens: int
    estimated_cost: float
    validation_time_ms: float
    prompt_hash: str

@dataclass
class TokenEstimate:
    """Estimativa de tokens e custo."""
    total_tokens: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    model_type: str

class PromptValidator:
    """
    Sistema de validação de prompts em tempo real.
    
    Funcionalidades:
    - Validação de sintaxe e estrutura
    - Estimativa de tokens e custo
    - Sugestões de correção automática
    - Validação de conteúdo sensível
    - Cache de validações anteriores
    """
    
    def __init__(self):
        # Regras de validação
        self.validation_rules = {
            'min_length': 10,
            'max_length': 4000,
            'min_words': 3,
            'max_words': 1000,
            'forbidden_words': [
                'senha', 'password', 'token', 'api_key', 'secret',
                'credencial', 'credential', 'chave', 'key'
            ],
            'required_elements': [
                'contexto', 'context', 'objetivo', 'objective', 'tema', 'topic'
            ],
            'suggested_elements': [
                'tone', 'tom', 'style', 'estilo', 'format', 'formato',
                'target_audience', 'publico_alvo', 'length', 'comprimento'
            ]
        }
        
        # Estimativas de tokens por modelo
        self.token_estimates = {
            'openai': {
                'gpt-4': {'input_per_char': 0.25, 'output_per_char': 0.3, 'cost_per_1k_input': 0.03, 'cost_per_1k_output': 0.06},
                'gpt-3.5-turbo': {'input_per_char': 0.25, 'output_per_char': 0.3, 'cost_per_1k_input': 0.0015, 'cost_per_1k_output': 0.002},
            },
            'deepseek': {
                'deepseek-chat': {'input_per_char': 0.25, 'output_per_char': 0.3, 'cost_per_1k_input': 0.0014, 'cost_per_1k_output': 0.0028},
                'deepseek-coder': {'input_per_char': 0.25, 'output_per_char': 0.3, 'cost_per_1k_input': 0.0014, 'cost_per_1k_output': 0.0028},
            }
        }
        
        # Cache de validações
        self.validation_cache = {}
        self.max_cache_size = 1000
    
    def validate_prompt(self, prompt: str, model_type: str = 'openai', model_name: str = 'gpt-4') -> ValidationResult:
        """
        Valida prompt completo.
        
        Args:
            prompt: Texto do prompt
            model_type: Tipo do modelo (openai, deepseek)
            model_name: Nome específico do modelo
        
        Returns:
            ValidationResult com resultados da validação
        """
        import time
        start_time = time.time()
        
        # Gera hash do prompt para cache
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
        
        # Verifica cache
        cache_key = f"{prompt_hash}_{model_type}_{model_name}"
        if cache_key in self.validation_cache:
            cached_result = self.validation_cache[cache_key]
            cached_result.validation_time_ms = round((time.time() - start_time) * 1000, 2)
            return cached_result
        
        errors = []
        warnings = []
        suggestions = []
        
        # Validações básicas
        self._validate_length(prompt, errors, warnings)
        self._validate_content(prompt, errors, warnings, suggestions)
        self._validate_structure(prompt, errors, warnings, suggestions)
        self._validate_sensitive_content(prompt, errors, warnings)
        
        # Estimativa de tokens
        token_estimate = self._estimate_tokens(prompt, model_type, model_name)
        
        # Cria resultado
        result = ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            estimated_tokens=token_estimate.total_tokens,
            estimated_cost=token_estimate.estimated_cost_usd,
            validation_time_ms=round((time.time() - start_time) * 1000, 2),
            prompt_hash=prompt_hash
        )
        
        # Armazena no cache
        self._cache_result(cache_key, result)
        
        return result
    
    def _validate_length(self, prompt: str, errors: List[str], warnings: List[str]):
        """Valida comprimento do prompt."""
        length = len(prompt)
        word_count = len(prompt.split())
        
        if length < self.validation_rules['min_length']:
            errors.append(f"Prompt muito curto ({length} caracteres). Mínimo: {self.validation_rules['min_length']}")
        
        if length > self.validation_rules['max_length']:
            errors.append(f"Prompt muito longo ({length} caracteres). Máximo: {self.validation_rules['max_length']}")
        
        if word_count < self.validation_rules['min_words']:
            errors.append(f"Poucas palavras ({word_count}). Mínimo: {self.validation_rules['min_words']}")
        
        if word_count > self.validation_rules['max_words']:
            warnings.append(f"Muitas palavras ({word_count}). Máximo recomendado: {self.validation_rules['max_words']}")
    
    def _validate_content(self, prompt: str, errors: List[str], warnings: List[str], suggestions: List[str]):
        """Valida conteúdo do prompt."""
        prompt_lower = prompt.lower()
        
        # Verifica elementos obrigatórios
        missing_required = []
        for element in self.validation_rules['required_elements']:
            if element not in prompt_lower:
                missing_required.append(element)
        
        if missing_required:
            errors.append(f"Elementos obrigatórios ausentes: {', '.join(missing_required)}")
        
        # Verifica elementos sugeridos
        missing_suggested = []
        for element in self.validation_rules['suggested_elements']:
            if element not in prompt_lower:
                missing_suggested.append(element)
        
        if missing_suggested:
            suggestions.append(f"Considere adicionar: {', '.join(missing_suggested)}")
        
        # Verifica repetições excessivas
        words = prompt.lower().split()
        word_freq = {}
        for word in words:
            if len(word) > 3:  # Ignora palavras muito curtas
                word_freq[word] = word_freq.get(word, 0) + 1
        
        repeated_words = [word for word, freq in word_freq.items() if freq > 3]
        if repeated_words:
            warnings.append(f"Palavras repetidas excessivamente: {', '.join(repeated_words[:3])}")
    
    def _validate_structure(self, prompt: str, errors: List[str], warnings: List[str], suggestions: List[str]):
        """Valida estrutura do prompt."""
        # Verifica se tem parágrafos
        paragraphs = prompt.split('\n\n')
        if len(paragraphs) < 2:
            suggestions.append("Considere dividir o prompt em parágrafos para melhor organização")
        
        # Verifica se tem instruções claras
        instruction_indicators = ['escreva', 'write', 'crie', 'create', 'gere', 'generate', 'produza', 'produce']
        has_instruction = any(indicator in prompt.lower() for indicator in instruction_indicators)
        
        if not has_instruction:
            suggestions.append("Adicione uma instrução clara sobre o que deve ser gerado")
        
        # Verifica se tem contexto
        context_indicators = ['sobre', 'about', 'relacionado a', 'related to', 'contexto', 'context']
        has_context = any(indicator in prompt.lower() for indicator in context_indicators)
        
        if not has_context:
            suggestions.append("Adicione contexto sobre o tema ou assunto")
    
    def _validate_sensitive_content(self, prompt: str, errors: List[str], warnings: List[str]):
        """Valida conteúdo sensível."""
        prompt_lower = prompt.lower()
        
        # Verifica palavras proibidas
        found_forbidden = []
        for word in self.validation_rules['forbidden_words']:
            if word in prompt_lower:
                found_forbidden.append(word)
        
        if found_forbidden:
            errors.append(f"Conteúdo sensível detectado: {', '.join(found_forbidden)}")
        
        # Verifica padrões suspeitos
        suspicious_patterns = [
            r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b',  # CPF
            r'\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b',  # CNPJ
            r'\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b',  # Cartão de crédito
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, prompt):
                warnings.append("Possível informação pessoal detectada no prompt")
                break
    
    def _estimate_tokens(self, prompt: str, model_type: str, model_name: str) -> TokenEstimate:
        """
        Estima tokens e custo para o prompt.
        
        Args:
            prompt: Texto do prompt
            model_type: Tipo do modelo
            model_name: Nome do modelo
        
        Returns:
            TokenEstimate com estimativas
        """
        # Obtém configurações do modelo
        model_config = self.token_estimates.get(model_type, {}).get(model_name, {})
        
        if not model_config:
            # Configuração padrão se modelo não encontrado
            model_config = {
                'input_per_char': 0.25,
                'output_per_char': 0.3,
                'cost_per_1k_input': 0.03,
                'cost_per_1k_output': 0.06
            }
        
        # Calcula tokens
        input_tokens = int(len(prompt) * model_config['input_per_char'])
        output_tokens = int(input_tokens * 2)  # Estimativa de saída 2x maior
        total_tokens = input_tokens + output_tokens
        
        # Calcula custo
        input_cost = (input_tokens / 1000) * model_config['cost_per_1k_input']
        output_cost = (output_tokens / 1000) * model_config['cost_per_1k_output']
        total_cost = input_cost + output_cost
        
        return TokenEstimate(
            total_tokens=total_tokens,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost_usd=round(total_cost, 4),
            model_type=model_type
        )
    
    def _cache_result(self, cache_key: str, result: ValidationResult):
        """Armazena resultado no cache."""
        if len(self.validation_cache) >= self.max_cache_size:
            # Remove entrada mais antiga
            oldest_key = next(iter(self.validation_cache))
            del self.validation_cache[oldest_key]
        
        self.validation_cache[cache_key] = result
    
    def get_suggestions_for_prompt(self, prompt: str) -> List[str]:
        """
        Gera sugestões específicas para melhorar o prompt.
        
        Args:
            prompt: Texto do prompt
        
        Returns:
            Lista de sugestões
        """
        suggestions = []
        
        # Sugestões baseadas no comprimento
        if len(prompt) < 100:
            suggestions.append("Adicione mais contexto e detalhes ao prompt")
        elif len(prompt) > 2000:
            suggestions.append("Considere simplificar o prompt para melhor foco")
        
        # Sugestões baseadas no conteúdo
        if '?' not in prompt:
            suggestions.append("Adicione perguntas específicas para direcionar a geração")
        
        if not any(word in prompt.lower() for word in ['artigo', 'article', 'texto', 'text']):
            suggestions.append("Especifique o tipo de conteúdo desejado (artigo, texto, etc.)")
        
        # Sugestões baseadas na estrutura
        if prompt.count('\n') < 2:
            suggestions.append("Organize o prompt em seções para melhor clareza")
        
        return suggestions
    
    def validate_multiple_prompts(self, prompts: List[str], model_type: str = 'openai', model_name: str = 'gpt-4') -> List[ValidationResult]:
        """
        Valida múltiplos prompts de uma vez.
        
        Args:
            prompts: Lista de prompts
            model_type: Tipo do modelo
            model_name: Nome do modelo
        
        Returns:
            Lista de ValidationResult
        """
        results = []
        for prompt in prompts:
            result = self.validate_prompt(prompt, model_type, model_name)
            results.append(result)
        
        return results
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """
        Obtém estatísticas de validação.
        
        Returns:
            Estatísticas do validador
        """
        total_validations = len(self.validation_cache)
        valid_prompts = sum(1 for result in self.validation_cache.values() if result.is_valid)
        invalid_prompts = total_validations - valid_prompts
        
        total_errors = sum(len(result.errors) for result in self.validation_cache.values())
        total_warnings = sum(len(result.warnings) for result in self.validation_cache.values())
        total_suggestions = sum(len(result.suggestions) for result in self.validation_cache.values())
        
        avg_tokens = sum(result.estimated_tokens for result in self.validation_cache.values()) / total_validations if total_validations > 0 else 0
        avg_cost = sum(result.estimated_cost for result in self.validation_cache.values()) / total_validations if total_validations > 0 else 0
        
        return {
            'total_validations': total_validations,
            'valid_prompts': valid_prompts,
            'invalid_prompts': invalid_prompts,
            'validation_rate': round((valid_prompts / total_validations * 100) if total_validations > 0 else 0, 2),
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'total_suggestions': total_suggestions,
            'avg_tokens': round(avg_tokens, 2),
            'avg_cost_usd': round(avg_cost, 4),
            'cache_size': len(self.validation_cache),
            'cache_hit_rate': 0  # Implementar se necessário
        }

# Instância global
prompt_validator = PromptValidator() 