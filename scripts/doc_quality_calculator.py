"""
Sistema de Cálculo de DocQualityScore para Documentação Enterprise
Implementa métricas de qualidade para avaliação de documentação.

Prompt: Documentação Enterprise - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:15:00Z
Tracing ID: DOC_ENTERPRISE_20250127_003
"""

import os
import json
import logging
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import re
from pathlib import Path

# Configuração de logging estruturado
logger = logging.getLogger("doc_quality_calculator")
logger.setLevel(logging.INFO)

@dataclass
class QualityMetrics:
    """Métricas de qualidade da documentação"""
    completeness_score: float
    coherence_score: float
    semantic_similarity: float
    overall_score: float
    assessment_timestamp: str
    recommendations: List[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class DocumentationAssessment:
    """Avaliação completa de documentação"""
    file_path: str
    doc_type: str
    quality_metrics: QualityMetrics
    compliance_status: Dict[str, bool]
    security_status: Dict[str, bool]
    assessment_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class DocQualityCalculator:
    """
    Calculador de qualidade de documentação.
    Implementa métricas de completude, coerência e similaridade semântica.
    """
    
    def __init__(self, min_completeness: float = 0.7, min_coherence: float = 0.6, 
                 min_similarity: float = 0.85):
        """
        Inicializa o calculador de qualidade.
        
        Args:
            min_completeness: Score mínimo de completude
            min_coherence: Score mínimo de coerência
            min_similarity: Score mínimo de similaridade semântica
        """
        self.min_completeness = min_completeness
        self.min_coherence = min_coherence
        self.min_similarity = min_similarity
        self.assessments: List[DocumentationAssessment] = []
        
        # Critérios de completude
        self.completeness_criteria = {
            'has_title': 0.1,
            'has_description': 0.2,
            'has_structure': 0.15,
            'has_examples': 0.15,
            'has_api_reference': 0.1,
            'has_error_handling': 0.1,
            'has_version_info': 0.05,
            'has_author_info': 0.05
        }
        
        # Critérios de coerência
        self.coherence_criteria = {
            'logical_flow': 0.25,
            'consistent_formatting': 0.2,
            'clear_language': 0.2,
            'proper_links': 0.15,
            'no_contradictions': 0.2
        }
        
        logger.info("DocQualityCalculator inicializado")
    
    def calculate_doc_quality_score(self, completeness: float, coherence: float, 
                                  semantic_similarity: float) -> float:
        """
        Calcula DocQualityScore usando a fórmula especificada.
        
        Args:
            completeness: Score de completude (0-1)
            coherence: Score de coerência (0-1)
            semantic_similarity: Score de similaridade semântica (0-1)
            
        Returns:
            DocQualityScore entre 0 e 1
        """
        # Fórmula: ((completude * 4) + (coerência * 3) + (similaridade_semântica * 3)) / 10
        overall_score = ((completeness * 4) + (coherence * 3) + (semantic_similarity * 3)) / 10
        
        # Garantir que está entre 0 e 1
        return max(0.0, min(1.0, overall_score))
    
    def assess_completeness(self, content: str, doc_type: str = "general") -> Tuple[float, Dict[str, Any]]:
        """
        Avalia completude da documentação.
        
        Args:
            content: Conteúdo da documentação
            doc_type: Tipo de documentação
            
        Returns:
            Tupla (score, detalhes)
        """
        if not content or not content.strip():
            return 0.0, {'reason': 'Conteúdo vazio'}
        
        details = {}
        total_score = 0.0
        
        # Verificar critérios de completude
        for criterion, weight in self.completeness_criteria.items():
            criterion_score = self._check_completeness_criterion(content, criterion, doc_type)
            details[criterion] = {
                'score': criterion_score,
                'weight': weight,
                'weighted_score': criterion_score * weight
            }
            total_score += criterion_score * weight
        
        return total_score, details
    
    def _check_completeness_criterion(self, content: str, criterion: str, doc_type: str) -> float:
        """
        Verifica um critério específico de completude.
        
        Args:
            content: Conteúdo da documentação
            criterion: Critério a ser verificado
            doc_type: Tipo de documentação
            
        Returns:
            Score do critério (0-1)
        """
        content_lower = content.lower()
        
        if criterion == 'has_title':
            # Verificar se tem título (h1, h2, etc.)
            title_patterns = [r'^#\s+', r'^##\s+', r'<h1>', r'<h2>', r'^[A-Z][^.!?]*$']
            return 1.0 if any(re.search(pattern, content, re.MULTILINE) for pattern in title_patterns) else 0.0
        
        elif criterion == 'has_description':
            # Verificar se tem descrição substancial
            words = content.split()
            return min(1.0, len(words) / 100) if len(words) > 10 else 0.0
        
        elif criterion == 'has_structure':
            # Verificar se tem estrutura organizada
            has_sections = bool(re.search(r'^#{1,3}\s+', content, re.MULTILINE))
            has_lists = bool(re.search(r'^\s*[-*+]\s+', content, re.MULTILINE))
            has_code_blocks = bool(re.search(r'```', content))
            return (has_sections + has_lists + has_code_blocks) / 3
        
        elif criterion == 'has_examples':
            # Verificar se tem exemplos
            example_patterns = [r'exemplo', r'example', r'```', r'code', r'sample']
            return 1.0 if any(pattern in content_lower for pattern in example_patterns) else 0.0
        
        elif criterion == 'has_api_reference':
            # Verificar se tem referência de API (para documentação técnica)
            if doc_type in ['api', 'technical']:
                api_patterns = [r'endpoint', r'api', r'http', r'request', r'response']
                return 1.0 if any(pattern in content_lower for pattern in api_patterns) else 0.0
            return 0.5  # Neutro para outros tipos
        
        elif criterion == 'has_error_handling':
            # Verificar se menciona tratamento de erros
            error_patterns = [r'error', r'erro', r'exception', r'fail', r'falha']
            return 1.0 if any(pattern in content_lower for pattern in error_patterns) else 0.0
        
        elif criterion == 'has_version_info':
            # Verificar se tem informação de versão
            version_patterns = [r'version', r'versão', r'v\d+', r'\d+\.\d+']
            return 1.0 if any(re.search(pattern, content_lower) for pattern in version_patterns) else 0.0
        
        elif criterion == 'has_author_info':
            # Verificar se tem informação de autor
            author_patterns = [r'author', r'autor', r'created by', r'@', r'contact']
            return 1.0 if any(pattern in content_lower for pattern in author_patterns) else 0.0
        
        return 0.0
    
    def assess_coherence(self, content: str) -> Tuple[float, Dict[str, Any]]:
        """
        Avalia coerência da documentação.
        
        Args:
            content: Conteúdo da documentação
            
        Returns:
            Tupla (score, detalhes)
        """
        if not content or not content.strip():
            return 0.0, {'reason': 'Conteúdo vazio'}
        
        details = {}
        total_score = 0.0
        
        # Verificar critérios de coerência
        for criterion, weight in self.coherence_criteria.items():
            criterion_score = self._check_coherence_criterion(content, criterion)
            details[criterion] = {
                'score': criterion_score,
                'weight': weight,
                'weighted_score': criterion_score * weight
            }
            total_score += criterion_score * weight
        
        return total_score, details
    
    def _check_coherence_criterion(self, content: str, criterion: str) -> float:
        """
        Verifica um critério específico de coerência.
        
        Args:
            content: Conteúdo da documentação
            criterion: Critério a ser verificado
            
        Returns:
            Score do critério (0-1)
        """
        if criterion == 'logical_flow':
            # Verificar fluxo lógico
            sentences = re.split(r'[.!?]+', content)
            if len(sentences) < 2:
                return 0.0
            
            # Verificar se frases têm tamanho adequado
            avg_sentence_length = np.mean([len(s.split()) for s in sentences if s.strip()])
            return min(1.0, avg_sentence_length / 10)
        
        elif criterion == 'consistent_formatting':
            # Verificar formatação consistente
            lines = content.split('\n')
            if len(lines) < 2:
                return 0.0
            
            # Verificar consistência de indentação
            indentations = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
            if not indentations:
                return 1.0
            
            # Calcular variância da indentação
            indent_variance = np.var(indentations)
            return max(0.0, 1.0 - (indent_variance / 10))
        
        elif criterion == 'clear_language':
            # Verificar clareza da linguagem
            words = content.split()
            if len(words) < 5:
                return 0.0
            
            # Verificar diversidade de vocabulário
            unique_words = len(set(words))
            vocabulary_diversity = unique_words / len(words)
            
            # Verificar frases completas
            sentences = re.split(r'[.!?]+', content)
            complete_sentences = sum(1 for s in sentences if len(s.split()) > 3)
            sentence_completeness = complete_sentences / max(1, len(sentences))
            
            return (vocabulary_diversity + sentence_completeness) / 2
        
        elif criterion == 'proper_links':
            # Verificar links apropriados
            link_patterns = [r'\[.*?\]\(.*?\)', r'http[s]?://', r'www\.']
            has_links = any(re.search(pattern, content) for pattern in link_patterns)
            return 1.0 if has_links else 0.5
        
        elif criterion == 'no_contradictions':
            # Verificar ausência de contradições
            contradiction_patterns = [
                (r'não\s+.*\s+mas\s+.*\s+sim', 0.0),
                (r'never.*but.*always', 0.0),
                (r'false.*but.*true', 0.0)
            ]
            
            for pattern, penalty in contradiction_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return penalty
            
            return 1.0
        
        return 0.0
    
    def assess_documentation(self, file_path: str, semantic_similarity: float = 0.0) -> DocumentationAssessment:
        """
        Avalia documentação completa.
        
        Args:
            file_path: Caminho do arquivo
            semantic_similarity: Score de similaridade semântica
            
        Returns:
            Avaliação completa da documentação
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Determinar tipo de documentação
            doc_type = self._determine_doc_type(file_path, content)
            
            # Avaliar completude
            completeness_score, completeness_details = self.assess_completeness(content, doc_type)
            
            # Avaliar coerência
            coherence_score, coherence_details = self.assess_coherence(content)
            
            # Calcular score geral
            overall_score = self.calculate_doc_quality_score(
                completeness_score, coherence_score, semantic_similarity
            )
            
            # Gerar recomendações
            recommendations = self._generate_recommendations(
                completeness_score, coherence_score, semantic_similarity, overall_score
            )
            
            # Criar métricas de qualidade
            quality_metrics = QualityMetrics(
                completeness_score=completeness_score,
                coherence_score=coherence_score,
                semantic_similarity=semantic_similarity,
                overall_score=overall_score,
                assessment_timestamp=datetime.utcnow().isoformat(),
                recommendations=recommendations,
                details={
                    'completeness_details': completeness_details,
                    'coherence_details': coherence_details
                }
            )
            
            # Verificar compliance
            compliance_status = self._check_compliance(content, file_path)
            
            # Verificar segurança
            security_status = self._check_security(content, file_path)
            
            # Criar avaliação
            assessment = DocumentationAssessment(
                file_path=file_path,
                doc_type=doc_type,
                quality_metrics=quality_metrics,
                compliance_status=compliance_status,
                security_status=security_status,
                assessment_timestamp=datetime.utcnow().isoformat()
            )
            
            self.assessments.append(assessment)
            
            logger.info(f"Avaliação concluída para {file_path}: score={overall_score:.3f}")
            
            return assessment
            
        except Exception as e:
            logger.error(f"Erro ao avaliar documentação {file_path}: {e}")
            raise
    
    def _determine_doc_type(self, file_path: str, content: str) -> str:
        """
        Determina o tipo de documentação.
        
        Args:
            file_path: Caminho do arquivo
            content: Conteúdo do arquivo
            
        Returns:
            Tipo de documentação
        """
        file_lower = file_path.lower()
        content_lower = content.lower()
        
        if 'api' in file_lower or 'endpoint' in content_lower:
            return 'api'
        elif 'readme' in file_lower:
            return 'readme'
        elif 'architecture' in file_lower or 'arch' in file_lower:
            return 'architecture'
        elif 'test' in file_lower:
            return 'test'
        elif 'config' in file_lower or 'setup' in file_lower:
            return 'configuration'
        elif 'deploy' in file_lower or 'production' in file_lower:
            return 'deployment'
        else:
            return 'general'
    
    def _generate_recommendations(self, completeness: float, coherence: float, 
                                similarity: float, overall: float) -> List[str]:
        """
        Gera recomendações baseadas nos scores.
        
        Args:
            completeness: Score de completude
            coherence: Score de coerência
            similarity: Score de similaridade
            overall: Score geral
            
        Returns:
            Lista de recomendações
        """
        recommendations = []
        
        if completeness < self.min_completeness:
            recommendations.append(f"Completude baixa ({completeness:.3f} < {self.min_completeness}). "
                                 "Adicionar seções faltantes: título, descrição, exemplos, estrutura.")
        
        if coherence < self.min_coherence:
            recommendations.append(f"Coerência baixa ({coherence:.3f} < {self.min_coherence}). "
                                 "Melhorar fluxo lógico, formatação e clareza.")
        
        if similarity < self.min_similarity:
            recommendations.append(f"Similaridade semântica baixa ({similarity:.3f} < {self.min_similarity}). "
                                 "Alinhar documentação com implementação.")
        
        if overall >= 0.8:
            recommendations.append("Documentação de alta qualidade. Manter padrão.")
        elif overall >= 0.6:
            recommendations.append("Documentação adequada. Considerar melhorias pontuais.")
        else:
            recommendations.append("Documentação precisa de revisão significativa.")
        
        return recommendations
    
    def _check_compliance(self, content: str, file_path: str) -> Dict[str, bool]:
        """
        Verifica compliance da documentação.
        
        Args:
            content: Conteúdo da documentação
            file_path: Caminho do arquivo
            
        Returns:
            Status de compliance
        """
        return {
            'pci_dss': self._check_pci_dss_compliance(content),
            'lgpd': self._check_lgpd_compliance(content),
            'accessibility': self._check_accessibility_compliance(content),
            'security': self._check_security_compliance(content)
        }
    
    def _check_pci_dss_compliance(self, content: str) -> bool:
        """Verifica compliance PCI-DSS"""
        # Verificar se não contém dados de cartão de crédito
        credit_card_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        return not bool(re.search(credit_card_pattern, content))
    
    def _check_lgpd_compliance(self, content: str) -> bool:
        """Verifica compliance LGPD"""
        # Verificar se não contém dados pessoais sensíveis
        personal_data_patterns = [
            r'\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b',  # CPF
            r'\b[0-9]{11}\b',  # CPF sem formatação
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email
        ]
        
        for pattern in personal_data_patterns:
            if re.search(pattern, content):
                return False
        
        return True
    
    def _check_accessibility_compliance(self, content: str) -> bool:
        """Verifica compliance de acessibilidade"""
        # Verificar se tem estrutura adequada
        has_headings = bool(re.search(r'^#{1,6}\s+', content, re.MULTILINE))
        has_alt_text = bool(re.search(r'alt\s*=', content, re.IGNORECASE))
        has_links = bool(re.search(r'\[.*?\]\(.*?\)', content))
        
        return has_headings and (has_alt_text or has_links)
    
    def _check_security_compliance(self, content: str) -> bool:
        """Verifica compliance de segurança"""
        # Verificar se não contém dados sensíveis
        sensitive_patterns = [
            r'password\s*[:=]',
            r'secret\s*[:=]',
            r'token\s*[:=]',
            r'api_key\s*[:=]'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False
        
        return True
    
    def _check_security(self, content: str, file_path: str) -> Dict[str, bool]:
        """
        Verifica aspectos de segurança.
        
        Args:
            content: Conteúdo da documentação
            file_path: Caminho do arquivo
            
        Returns:
            Status de segurança
        """
        return {
            'no_sensitive_data': self._check_security_compliance(content),
            'no_hardcoded_credentials': not bool(re.search(r'password\s*[:=]\s*["\']?[^"\'\s]+["\']?', content, re.IGNORECASE)),
            'no_internal_paths': not bool(re.search(r'/etc/|/var/|/usr/', content)),
            'no_debug_info': not bool(re.search(r'debug|DEBUG', content))
        }
    
    def save_assessments(self, output_path: str):
        """
        Salva avaliações em arquivo JSON.
        
        Args:
            output_path: Caminho do arquivo de saída
        """
        try:
            assessments_data = {
                'assessment_metadata': {
                    'total_assessments': len(self.assessments),
                    'assessment_timestamp': datetime.utcnow().isoformat(),
                    'min_completeness': self.min_completeness,
                    'min_coherence': self.min_coherence,
                    'min_similarity': self.min_similarity,
                    'tracing_id': 'DOC_ENTERPRISE_20250127_003'
                },
                'assessments': [assessment.to_dict() for assessment in self.assessments]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(assessments_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Avaliações salvas em: {output_path}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar avaliações: {e}")
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas resumidas das avaliações.
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.assessments:
            return {}
        
        scores = [assessment.quality_metrics.overall_score for assessment in self.assessments]
        
        return {
            'total_assessments': len(self.assessments),
            'average_score': np.mean(scores),
            'median_score': np.median(scores),
            'min_score': np.min(scores),
            'max_score': np.max(scores),
            'std_score': np.std(scores),
            'high_quality_docs': len([s for s in scores if s >= 0.8]),
            'adequate_docs': len([s for s in scores if 0.6 <= s < 0.8]),
            'needs_improvement': len([s for s in scores if s < 0.6])
        }


def main():
    """Função principal para demonstração"""
    calculator = DocQualityCalculator()
    
    # Exemplo de avaliação
    test_content = """
    # Documentação de Exemplo
    
    Esta é uma documentação de exemplo que demonstra como usar o sistema.
    
    ## Uso
    
    Para usar o sistema, execute:
    
    ```bash
    python main.py
    ```
    
    ## Exemplos
    
    Exemplo de uso básico:
    
    ```python
    from app import main
    main()
    ```
    
    ## Tratamento de Erros
    
    O sistema trata erros automaticamente.
    """
    
    # Simular arquivo temporário
    test_file = "test_doc.md"
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    # Avaliar documentação
    assessment = calculator.assess_documentation(test_file, semantic_similarity=0.85)
    
    print(f"Score geral: {assessment.quality_metrics.overall_score:.3f}")
    print(f"Recomendações: {assessment.quality_metrics.recommendations}")
    
    # Limpar arquivo temporário
    os.remove(test_file)


if __name__ == "__main__":
    main() 