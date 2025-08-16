"""
Validação de Prompts Avançada - Omni Writer
===========================================

Implementa validação semântica de prompts com:
- Detecção de prompts vazios ou malformados
- Estimativa de tokens antes do envio
- Sugestões de otimização automática
- Validação de contexto e coerência
- Feedback em tempo real no frontend

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import json

logger = logging.getLogger("domain.prompt_validator")

class ValidationLevel(Enum):
    """Níveis de validação"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class PromptType(Enum):
    """Tipos de prompt"""
    ARTICLE = "article"
    NEWS = "news"
    BLOG_POST = "blog_post"
    PRODUCT_DESCRIPTION = "product_description"
    REVIEW = "review"
    TUTORIAL = "tutorial"
    UNKNOWN = "unknown"

@dataclass
class ValidationIssue:
    """Problema de validação identificado"""
    level: ValidationLevel
    field: str
    message: str
    suggestion: Optional[str] = None
    code: str = ""

@dataclass
class TokenEstimate:
    """Estimativa de tokens"""
    total_tokens: int
    input_tokens: int
    output_tokens: int
    model: str
    cost_estimate: float = 0.0

@dataclass
class ValidationResult:
    """Resultado da validação"""
    is_valid: bool
    issues: List[ValidationIssue]
    token_estimate: Optional[TokenEstimate] = None
    prompt_type: PromptType = PromptType.UNKNOWN
    confidence_score: float = 0.0
    optimization_suggestions: Optional[List[str]] = None

class PromptValidator:
    """
    Validador avançado de prompts
    """
    
    def __init__(self):
        self.min_prompt_length = 10
        self.max_prompt_length = 4000
        self.token_estimates = {
            'gpt-4o': {'input': 0.00003, 'output': 0.00006},  # USD por token
            'gpt-4': {'input': 0.00003, 'output': 0.00006},
            'gpt-3.5-turbo': {'input': 0.0000015, 'output': 0.000002},
            'deepseek': {'input': 0.000014, 'output': 0.000028},
            'gemini': {'input': 0.0000125, 'output': 0.0000375},
            'claude': {'input': 0.000015, 'output': 0.000075}
        }
        self.prompt_patterns = {
            PromptType.ARTICLE: [
                r'artigo|article|conteúdo|content',
                r'tema|topic|assunto|subject',
                r'palavras|words|caracteres|characters'
            ],
            PromptType.NEWS: [
                r'notícia|news|atual|current',
                r'hoje|today|recente|recent',
                r'acontecimento|event|ocorrência|occurrence'
            ],
            PromptType.BLOG_POST: [
                r'blog|post|publicação|publication',
                r'blogueiro|blogger|escrever|write',
                r'compartilhar|share|comentário|comment'
            ],
            PromptType.PRODUCT_DESCRIPTION: [
                r'produto|product|descrição|description',
                r'características|features|benefícios|benefits',
                r'preço|price|compra|buy|venda|sale'
            ],
            PromptType.REVIEW: [
                r'review|análise|analysis|avaliação|evaluation',
                r'opinião|opinion|experiência|experience',
                r'recomendação|recommendation|nota|rating'
            ],
            PromptType.TUTORIAL: [
                r'tutorial|guia|guide|passo|step',
                r'como|how|instrução|instruction',
                r'aprender|learn|ensinar|teach'
            ]
        }
        
        # Palavras proibidas ou problemáticas
        self.forbidden_words = [
            'prompt', 'injection', 'bypass', 'ignore', 'previous',
            'anterior', 'desobedecer', 'desobedecendo', 'ignore',
            'ignore previous', 'ignore all previous'
        ]
        
        # Palavras que indicam contexto inadequado
        self.context_issues = [
            'pessoal', 'personal', 'privado', 'private', 'confidencial',
            'confidential', 'secreto', 'secret', 'interno', 'internal'
        ]
    
    def validate_prompt(self, prompt: str, model: str = 'gpt-4o') -> ValidationResult:
        """
        Valida prompt completo
        """
        issues = []
        
        # Validações básicas
        issues.extend(self._validate_basic_structure(prompt))
        
        # Validações de conteúdo
        issues.extend(self._validate_content(prompt))
        
        # Validações de contexto
        issues.extend(self._validate_context(prompt))
        
        # Estimativa de tokens
        token_estimate = self._estimate_tokens(prompt, model)
        
        # Identificação do tipo de prompt
        prompt_type = self._identify_prompt_type(prompt)
        
        # Sugestões de otimização
        optimization_suggestions = self._generate_optimization_suggestions(prompt, token_estimate)
        
        # Calcula score de confiança
        confidence_score = self._calculate_confidence_score(prompt, issues)
        
        is_valid = all(issue.level != ValidationLevel.ERROR for issue in issues)
        
        return ValidationResult(
            is_valid=is_valid,
            issues=issues,
            token_estimate=token_estimate,
            prompt_type=prompt_type,
            confidence_score=confidence_score,
            optimization_suggestions=optimization_suggestions
        )
    
    def _validate_basic_structure(self, prompt: str) -> List[ValidationIssue]:
        """
        Valida estrutura básica do prompt
        """
        issues = []
        
        # Verifica se está vazio
        if not prompt or not prompt.strip():
            issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                field="content",
                message="Prompt não pode estar vazio",
                suggestion="Adicione conteúdo ao prompt",
                code="EMPTY_PROMPT"
            ))
            return issues
        
        # Verifica comprimento mínimo
        if len(prompt.strip()) < self.min_prompt_length:
            issues.append(ValidationIssue(
                level=ValidationLevel.ERROR,
                field="content",
                message=f"Prompt muito curto (mínimo {self.min_prompt_length} caracteres)",
                suggestion="Adicione mais detalhes ao prompt",
                code="TOO_SHORT"
            ))
        
        # Verifica comprimento máximo
        if len(prompt) > self.max_prompt_length:
            issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                field="content",
                message=f"Prompt muito longo (máximo {self.max_prompt_length} caracteres)",
                suggestion="Considere dividir o prompt em partes menores",
                code="TOO_LONG"
            ))
        
        # Verifica caracteres especiais problemáticos
        if re.search(r'[<>{}[\]]', prompt):
            issues.append(ValidationIssue(
                level=ValidationLevel.WARNING,
                field="content",
                message="Caracteres especiais podem causar problemas",
                suggestion="Remova ou escape caracteres especiais",
                code="SPECIAL_CHARS"
            ))
        
        return issues
    
    def _validate_content(self, prompt: str) -> List[ValidationIssue]:
        """
        Valida conteúdo do prompt
        """
        issues = []
        prompt_lower = prompt.lower()
        
        # Verifica palavras proibidas
        for word in self.forbidden_words:
            if word in prompt_lower:
                issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    field="content",
                    message=f"Palavra proibida detectada: '{word}'",
                    suggestion="Remova ou substitua a palavra problemática",
                    code="FORBIDDEN_WORD"
                ))
        
        # Verifica repetições excessivas
        words = prompt_lower.split()
        word_counts = {}
        for word in words:
            if len(word) > 3:  # Ignora palavras muito curtas
                word_counts[word] = word_counts.get(word, 0) + 1
        
        for word, count in word_counts.items():
            if count > 5:  # Mais de 5 repetições
                issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    field="content",
                    message=f"Palavra repetida excessivamente: '{word}' ({count} vezes)",
                    suggestion="Use sinônimos ou reescreva para evitar repetição",
                    code="EXCESSIVE_REPETITION"
                ))
        
        # Verifica estrutura de frases
        sentences = re.split(r'[.!?]+', prompt)
        for i, sentence in enumerate(sentences):
            if len(sentence.strip()) > 200:  # Frase muito longa
                issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    field="content",
                    message=f"Frase muito longa na posição {i+1}",
                    suggestion="Divida a frase em partes menores",
                    code="LONG_SENTENCE"
                ))
        
        return issues
    
    def _validate_context(self, prompt: str) -> List[ValidationIssue]:
        """
        Valida contexto do prompt
        """
        issues = []
        prompt_lower = prompt.lower()
        
        # Verifica palavras que indicam contexto inadequado
        for word in self.context_issues:
            if word in prompt_lower:
                issues.append(ValidationIssue(
                    level=ValidationLevel.WARNING,
                    field="context",
                    message=f"Possível contexto inadequado: '{word}'",
                    suggestion="Verifique se o contexto é apropriado para geração de conteúdo",
                    code="INAPPROPRIATE_CONTEXT"
                ))
        
        # Verifica se tem instruções claras
        instruction_indicators = [
            'escreva', 'write', 'crie', 'create', 'gere', 'generate',
            'faça', 'make', 'produza', 'produce', 'elabore', 'elaborate'
        ]
        
        has_instruction = any(indicator in prompt_lower for indicator in instruction_indicators)
        if not has_instruction:
            issues.append(ValidationIssue(
                level=ValidationLevel.INFO,
                field="context",
                message="Nenhuma instrução clara de geração encontrada",
                suggestion="Adicione instruções claras sobre o que gerar",
                code="NO_INSTRUCTION"
            ))
        
        return issues
    
    def _estimate_tokens(self, prompt: str, model: str) -> TokenEstimate:
        """
        Estima número de tokens e custo
        """
        # Estimativa simples: ~4 caracteres por token
        estimated_tokens = len(prompt) // 4
        
        # Estimativa de output (assumindo 2x o input)
        output_tokens = estimated_tokens * 2
        total_tokens = estimated_tokens + output_tokens
        
        # Calcula custo estimado
        cost_estimate = 0.0
        if model in self.token_estimates:
            input_cost = estimated_tokens * self.token_estimates[model]['input']
            output_cost = output_tokens * self.token_estimates[model]['output']
            cost_estimate = input_cost + output_cost
        
        return TokenEstimate(
            total_tokens=total_tokens,
            input_tokens=estimated_tokens,
            output_tokens=output_tokens,
            model=model,
            cost_estimate=cost_estimate
        )
    
    def _identify_prompt_type(self, prompt: str) -> PromptType:
        """
        Identifica o tipo de prompt
        """
        prompt_lower = prompt.lower()
        
        for prompt_type, patterns in self.prompt_patterns.items():
            matches = 0
            for pattern in patterns:
                if re.search(pattern, prompt_lower):
                    matches += 1
            
            if matches >= 2:  # Pelo menos 2 padrões correspondem
                return prompt_type
        
        return PromptType.UNKNOWN
    
    def _generate_optimization_suggestions(self, prompt: str, token_estimate: TokenEstimate) -> List[str]:
        """
        Gera sugestões de otimização
        """
        suggestions = []
        
        # Sugestões baseadas no tamanho
        if token_estimate.input_tokens > 1000:
            suggestions.append("Considere dividir o prompt em partes menores para melhor controle")
        
        if token_estimate.input_tokens < 50:
            suggestions.append("Adicione mais contexto para obter resultados mais específicos")
        
        # Sugestões baseadas no custo
        if token_estimate.cost_estimate > 0.10:  # Mais de 10 centavos
            suggestions.append("Prompt pode ser custoso. Considere otimizar para reduzir tokens")
        
        # Sugestões baseadas no conteúdo
        if len(prompt.split()) < 10:
            suggestions.append("Adicione mais detalhes e especificações ao prompt")
        
        if len(prompt.split()) > 200:
            suggestions.append("Prompt muito longo. Considere ser mais conciso")
        
        # Sugestões específicas por tipo
        prompt_type = self._identify_prompt_type(prompt)
        if prompt_type == PromptType.ARTICLE:
            suggestions.append("Para artigos, especifique o tom, público-alvo e estrutura desejada")
        elif prompt_type == PromptType.NEWS:
            suggestions.append("Para notícias, inclua contexto temporal e fontes relevantes")
        elif prompt_type == PromptType.TUTORIAL:
            suggestions.append("Para tutoriais, especifique o nível de conhecimento do público")
        
        return suggestions
    
    def _calculate_confidence_score(self, prompt: str, issues: List[ValidationIssue]) -> float:
        """
        Calcula score de confiança (0-1)
        """
        base_score = 1.0
        
        # Reduz score baseado nos problemas
        for issue in issues:
            if issue.level == ValidationLevel.ERROR:
                base_score -= 0.3
            elif issue.level == ValidationLevel.WARNING:
                base_score -= 0.1
            elif issue.level == ValidationLevel.INFO:
                base_score -= 0.05
        
        # Ajusta baseado no tamanho e estrutura
        if len(prompt) < 50:
            base_score -= 0.2
        elif len(prompt) > 2000:
            base_score -= 0.1
        
        # Ajusta baseado no tipo identificado
        prompt_type = self._identify_prompt_type(prompt)
        if prompt_type != PromptType.UNKNOWN:
            base_score += 0.1
        
        return max(0.0, min(1.0, base_score))
    
    def validate_prompt_structure(self, prompt_data: Dict[str, Any]) -> List[ValidationIssue]:
        """
        Valida estrutura de dados do prompt
        """
        issues = []
        
        required_fields = ['content', 'type', 'target_length']
        
        for field in required_fields:
            if field not in prompt_data:
                issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    field=field,
                    message=f"Campo obrigatório ausente: {field}",
                    suggestion=f"Adicione o campo {field}",
                    code="MISSING_FIELD"
                ))
        
        # Validações específicas por campo
        if 'content' in prompt_data:
            content_issues = self._validate_basic_structure(prompt_data['content'])
            issues.extend(content_issues)
        
        if 'target_length' in prompt_data:
            try:
                target_length = int(prompt_data['target_length'])
                if target_length < 100 or target_length > 5000:
                    issues.append(ValidationIssue(
                        level=ValidationLevel.WARNING,
                        field="target_length",
                        message="Comprimento alvo fora do intervalo recomendado (100-5000)",
                        suggestion="Ajuste o comprimento alvo para um valor entre 100 e 5000",
                        code="INVALID_LENGTH"
                    ))
            except (ValueError, TypeError):
                issues.append(ValidationIssue(
                    level=ValidationLevel.ERROR,
                    field="target_length",
                    message="Comprimento alvo deve ser um número",
                    suggestion="Especifique um número válido para o comprimento",
                    code="INVALID_LENGTH_TYPE"
                ))
        
        return issues
    
    def get_validation_summary(self, result: ValidationResult) -> Dict[str, Any]:
        """
        Retorna resumo da validação
        """
        return {
            'is_valid': result.is_valid,
            'confidence_score': result.confidence_score,
            'prompt_type': result.prompt_type.value,
            'total_issues': len(result.issues),
            'error_count': len([i for i in result.issues if i.level == ValidationLevel.ERROR]),
            'warning_count': len([i for i in result.issues if i.level == ValidationLevel.WARNING]),
            'info_count': len([i for i in result.issues if i.level == ValidationLevel.INFO]),
            'token_estimate': {
                'total_tokens': result.token_estimate.total_tokens if result.token_estimate else 0,
                'input_tokens': result.token_estimate.input_tokens if result.token_estimate else 0,
                'output_tokens': result.token_estimate.output_tokens if result.token_estimate else 0,
                'cost_estimate': result.token_estimate.cost_estimate if result.token_estimate else 0.0
            } if result.token_estimate else None,
            'optimization_suggestions': result.optimization_suggestions or []
        } 