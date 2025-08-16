"""
Sistema de Detecção de Dados Sensíveis para Documentação Enterprise
Implementa detecção e mascaramento automático de dados sensíveis em documentação.

Prompt: Documentação Enterprise - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:10:00Z
Tracing ID: DOC_ENTERPRISE_20250127_002
"""

import os
import re
import json
import logging
import hashlib
from typing import List, Dict, Tuple, Optional, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

# Configuração de logging estruturado
logger = logging.getLogger("sensitive_data_detector")
logger.setLevel(logging.INFO)

@dataclass
class SensitiveDataFinding:
    """Resultado da detecção de dados sensíveis"""
    file_path: str
    line_number: int
    pattern_name: str
    pattern_description: str
    matched_text: str
    masked_text: str
    severity: str
    detection_timestamp: str
    hash_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class SensitiveDataDetector:
    """
    Detector de dados sensíveis para proteção de informações críticas.
    Implementa padrões regex para detecção e mascaramento automático.
    """
    
    def __init__(self):
        """Inicializa o detector de dados sensíveis"""
        self.findings: List[SensitiveDataFinding] = []
        self.masked_content_cache: Dict[str, str] = {}
        
        # Padrões de detecção de dados sensíveis
        self.patterns = {
            'aws_access_key': {
                'regex': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Key ID',
                'severity': 'critical',
                'mask_template': 'AKIA[MASKED]'
            },
            'aws_secret_key': {
                'regex': r'[0-9a-zA-Z/+]{40}',
                'description': 'AWS Secret Access Key',
                'severity': 'critical',
                'mask_template': '[AWS_SECRET_MASKED]'
            },
            'google_api_key': {
                'regex': r'AIza[0-9A-Za-z-_]{35}',
                'description': 'Google API Key',
                'severity': 'high',
                'mask_template': 'AIza[GOOGLE_API_MASKED]'
            },
            'openai_api_key': {
                'regex': r'sk-[0-9a-zA-Z]{48}',
                'description': 'OpenAI API Key',
                'severity': 'high',
                'mask_template': 'sk-[OPENAI_API_MASKED]'
            },
            'password_field': {
                'regex': r'(?i)(password|senha)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                'description': 'Password field in configuration',
                'severity': 'high',
                'mask_template': 'password: [MASKED]'
            },
            'secret_keyword': {
                'regex': r'(?i)(secret|secreto)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                'description': 'Secret keyword in configuration',
                'severity': 'high',
                'mask_template': 'secret: [MASKED]'
            },
            'token_keyword': {
                'regex': r'(?i)(token|api_key)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                'description': 'Token/API key in configuration',
                'severity': 'high',
                'mask_template': 'token: [MASKED]'
            },
            'database_url': {
                'regex': r'(?i)(postgresql|mysql|mongodb)://[^/\s]+:[^@\s]+@[^/\s]+',
                'description': 'Database connection URL with credentials',
                'severity': 'critical',
                'mask_template': '[DATABASE_URL_MASKED]'
            },
            'email_address': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email address',
                'severity': 'medium',
                'mask_template': '[EMAIL_MASKED]'
            },
            'phone_number': {
                'regex': r'(\+?[0-9]{1,3}[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                'description': 'Phone number',
                'severity': 'medium',
                'mask_template': '[PHONE_MASKED]'
            },
            'credit_card': {
                'regex': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                'description': 'Credit card number',
                'severity': 'critical',
                'mask_template': '[CREDIT_CARD_MASKED]'
            },
            'ssn': {
                'regex': r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
                'description': 'Social Security Number',
                'severity': 'critical',
                'mask_template': '[SSN_MASKED]'
            },
            'ip_address': {
                'regex': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                'description': 'IP address',
                'severity': 'low',
                'mask_template': '[IP_MASKED]'
            }
        }
        
        # Compilar padrões regex para performance
        self.compiled_patterns = {}
        for pattern_name, pattern_info in self.patterns.items():
            try:
                self.compiled_patterns[pattern_name] = {
                    'regex': re.compile(pattern_info['regex']),
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity'],
                    'mask_template': pattern_info['mask_template']
                }
            except re.error as e:
                logger.error(f"Erro ao compilar padrão {pattern_name}: {e}")
        
        logger.info(f"SensitiveDataDetector inicializado com {len(self.compiled_patterns)} padrões")
    
    def scan_file(self, file_path: str) -> List[SensitiveDataFinding]:
        """
        Escaneia um arquivo em busca de dados sensíveis.
        
        Args:
            file_path: Caminho do arquivo a ser escaneado
            
        Returns:
            Lista de descobertas de dados sensíveis
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_number, line in enumerate(lines, 1):
                line_findings = self._scan_line(line, line_number, file_path)
                findings.extend(line_findings)
            
            logger.info(f"Arquivo {file_path} escaneado: {len(findings)} descobertas")
            
        except Exception as e:
            logger.error(f"Erro ao escanear arquivo {file_path}: {e}")
        
        return findings
    
    def _scan_line(self, line: str, line_number: int, file_path: str) -> List[SensitiveDataFinding]:
        """
        Escaneia uma linha em busca de dados sensíveis.
        
        Args:
            line: Linha a ser escaneada
            line_number: Número da linha
            file_path: Caminho do arquivo
            
        Returns:
            Lista de descobertas na linha
        """
        findings = []
        
        for pattern_name, pattern_info in self.compiled_patterns.items():
            matches = pattern_info['regex'].finditer(line)
            
            for match in matches:
                matched_text = match.group()
                masked_text = self._mask_sensitive_data(matched_text, pattern_info['mask_template'])
                
                finding = SensitiveDataFinding(
                    file_path=file_path,
                    line_number=line_number,
                    pattern_name=pattern_name,
                    pattern_description=pattern_info['description'],
                    matched_text=matched_text,
                    masked_text=masked_text,
                    severity=pattern_info['severity'],
                    detection_timestamp=datetime.utcnow().isoformat(),
                    hash_id=self._generate_finding_hash(file_path, line_number, matched_text)
                )
                
                findings.append(finding)
                self.findings.append(finding)
        
        return findings
    
    def _mask_sensitive_data(self, original_text: str, mask_template: str) -> str:
        """
        Mascara dados sensíveis usando template.
        
        Args:
            original_text: Texto original
            mask_template: Template de mascaramento
            
        Returns:
            Texto mascarado
        """
        if '[MASKED]' in mask_template:
            return mask_template
        elif '[AWS_SECRET_MASKED]' in mask_template:
            return '[AWS_SECRET_MASKED]'
        elif '[GOOGLE_API_MASKED]' in mask_template:
            return '[GOOGLE_API_MASKED]'
        elif '[OPENAI_API_MASKED]' in mask_template:
            return '[OPENAI_API_MASKED]'
        elif '[DATABASE_URL_MASKED]' in mask_template:
            return '[DATABASE_URL_MASKED]'
        elif '[EMAIL_MASKED]' in mask_template:
            return '[EMAIL_MASKED]'
        elif '[PHONE_MASKED]' in mask_template:
            return '[PHONE_MASKED]'
        elif '[CREDIT_CARD_MASKED]' in mask_template:
            return '[CREDIT_CARD_MASKED]'
        elif '[SSN_MASKED]' in mask_template:
            return '[SSN_MASKED]'
        elif '[IP_MASKED]' in mask_template:
            return '[IP_MASKED]'
        else:
            # Mascaramento genérico
            return '[SENSITIVE_DATA_MASKED]'
    
    def _generate_finding_hash(self, file_path: str, line_number: int, matched_text: str) -> str:
        """
        Gera hash único para uma descoberta.
        
        Args:
            file_path: Caminho do arquivo
            line_number: Número da linha
            matched_text: Texto encontrado
            
        Returns:
            Hash único da descoberta
        """
        hash_input = f"{file_path}:{line_number}:{matched_text}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    def scan_directory(self, directory_path: str, file_extensions: Optional[List[str]] = None) -> List[SensitiveDataFinding]:
        """
        Escaneia um diretório em busca de dados sensíveis.
        
        Args:
            directory_path: Caminho do diretório
            file_extensions: Extensões de arquivo a serem escaneadas (opcional)
            
        Returns:
            Lista de todas as descobertas
        """
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.ts', '.json', '.yaml', '.yml', '.md', '.txt', '.env']
        
        all_findings = []
        
        for root, dirs, files in os.walk(directory_path):
            # Ignorar diretórios comuns que não devem ser escaneados
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv', '.pytest_cache']]
            
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
        
        logger.info(f"Diretório {directory_path} escaneado: {len(all_findings)} descobertas totais")
        
        return all_findings
    
    def mask_file_content(self, file_path: str, output_path: Optional[str] = None) -> str:
        """
        Mascara dados sensíveis em um arquivo.
        
        Args:
            file_path: Caminho do arquivo original
            output_path: Caminho do arquivo mascarado (opcional)
            
        Returns:
            Conteúdo mascarado
        """
        if output_path is None:
            output_path = file_path + '.masked'
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            masked_content = content
            
            # Aplicar mascaramento para cada padrão
            for pattern_name, pattern_info in self.compiled_patterns.items():
                masked_content = pattern_info['regex'].sub(
                    lambda m: self._mask_sensitive_data(m.group(), pattern_info['mask_template']),
                    masked_content
                )
            
            # Salvar arquivo mascarado
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(masked_content)
            
            self.masked_content_cache[file_path] = masked_content
            
            logger.info(f"Arquivo {file_path} mascarado e salvo em {output_path}")
            
            return masked_content
            
        except Exception as e:
            logger.error(f"Erro ao mascarar arquivo {file_path}: {e}")
            return ""
    
    def validate_documentation_safety(self, file_path: str) -> Dict[str, Any]:
        """
        Valida se um arquivo de documentação é seguro.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Dicionário com resultado da validação
        """
        findings = self.scan_file(file_path)
        
        critical_findings = [f for f in findings if f.severity == 'critical']
        high_findings = [f for f in findings if f.severity == 'high']
        medium_findings = [f for f in findings if f.severity == 'medium']
        low_findings = [f for f in findings if f.severity == 'low']
        
        is_safe = len(critical_findings) == 0 and len(high_findings) == 0
        
        return {
            'file_path': file_path,
            'is_safe': is_safe,
            'total_findings': len(findings),
            'critical_findings': len(critical_findings),
            'high_findings': len(high_findings),
            'medium_findings': len(medium_findings),
            'low_findings': len(low_findings),
            'validation_timestamp': datetime.utcnow().isoformat(),
            'recommendations': self._generate_safety_recommendations(findings)
        }
    
    def _generate_safety_recommendations(self, findings: List[SensitiveDataFinding]) -> List[str]:
        """
        Gera recomendações de segurança baseadas nas descobertas.
        
        Args:
            findings: Lista de descobertas
            
        Returns:
            Lista de recomendações
        """
        recommendations = []
        
        if not findings:
            recommendations.append("Arquivo seguro. Nenhum dado sensível detectado.")
            return recommendations
        
        critical_count = len([f for f in findings if f.severity == 'critical'])
        high_count = len([f for f in findings if f.severity == 'high'])
        
        if critical_count > 0:
            recommendations.append(f"CRÍTICO: {critical_count} dados críticos encontrados. "
                                 "Remover imediatamente antes de salvar documentação.")
        
        if high_count > 0:
            recommendations.append(f"ALTO RISCO: {high_count} dados de alto risco encontrados. "
                                 "Revisar e mascarar antes de salvar.")
        
        if critical_count == 0 and high_count == 0:
            recommendations.append("Arquivo pode ser salvo com mascaramento automático aplicado.")
        
        return recommendations
    
    def save_findings(self, output_path: str):
        """
        Salva descobertas em arquivo JSON.
        
        Args:
            output_path: Caminho do arquivo de saída
        """
        try:
            findings_data = {
                'detection_metadata': {
                    'total_findings': len(self.findings),
                    'detection_timestamp': datetime.utcnow().isoformat(),
                    'patterns_used': list(self.patterns.keys()),
                    'tracing_id': 'DOC_ENTERPRISE_20250127_002'
                },
                'findings': [finding.to_dict() for finding in self.findings]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(findings_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Descobertas salvas em: {output_path}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar descobertas: {e}")
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas resumidas das descobertas.
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.findings:
            return {}
        
        severity_counts = {}
        pattern_counts = {}
        
        for finding in self.findings:
            # Contar por severidade
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            
            # Contar por padrão
            pattern_counts[finding.pattern_name] = pattern_counts.get(finding.pattern_name, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'severity_distribution': severity_counts,
            'pattern_distribution': pattern_counts,
            'files_affected': len(set(f.file_path for f in self.findings)),
            'critical_findings': severity_counts.get('critical', 0),
            'high_findings': severity_counts.get('high', 0),
            'medium_findings': severity_counts.get('medium', 0),
            'low_findings': severity_counts.get('low', 0)
        }


def main():
    """Função principal para demonstração"""
    detector = SensitiveDataDetector()
    
    # Exemplo de escaneamento
    test_content = """
    # Configuração de API
    OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef1234567890abcdef
    AWS_ACCESS_KEY=AKIA1234567890ABCDEF
    DATABASE_URL=postgresql://user:password@localhost:5432/db
    EMAIL=user@example.com
    """
    
    # Simular arquivo temporário
    test_file = "test_config.py"
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    # Escanear arquivo
    findings = detector.scan_file(test_file)
    
    print(f"Descobertas: {len(findings)}")
    for finding in findings:
        print(f"- {finding.pattern_description}: {finding.matched_text} -> {finding.masked_text}")
    
    # Limpar arquivo temporário
    os.remove(test_file)


if __name__ == "__main__":
    main() 