"""
Secrets Scanner - Detecção Automática de Secrets em Código

Prompt: Integração Externa - Item 1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:00:00Z
Tracing ID: INT_CHECKLIST_20250127_001

Análise CoCoT:
- Comprovação: Baseado em OWASP ASVS 1.2 e PCI-DSS 6.3
- Causalidade: Necessário para compliance de segurança e prevenção de vazamentos
- Contexto: Integração com sistema existente de logging e monitoramento
- Tendência: Uso de regex patterns modernos e validação semântica

Decisões ToT:
- Abordagem 1: Regex patterns simples (rápido, mas muitos falsos positivos)
- Abordagem 2: ML-based detection (preciso, mas complexo)
- Abordagem 3: Regex + validação semântica (equilibrado)
- Escolha: Abordagem 3 - melhor relação custo-benefício

Simulação ReAct:
- Antes: Sistema sem detecção de secrets
- Durante: Falsos positivos em comentários e exemplos
- Depois: Detecção precisa com logs estruturados

Validação de Falsos Positivos:
- Regra: Regex pode detectar strings que não são secrets
- Validação: Verificar contexto e uso real da string
- Log: Registrar motivo do falso positivo para aprendizado
"""

import os
import re
import json
import hashlib
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging

from shared.logger import get_structured_logger

logger = get_structured_logger(__name__)

@dataclass
class SecretMatch:
    """Representa um secret detectado no código."""
    file_path: str
    line_number: int
    secret_type: str
    matched_text: str
    confidence: float
    context: str
    is_false_positive: bool = False
    false_positive_reason: Optional[str] = None

@dataclass
class ScanResult:
    """Resultado do scan de secrets."""
    scan_id: str
    timestamp: datetime
    files_scanned: int
    secrets_found: int
    false_positives: int
    scan_duration: float
    matches: List[SecretMatch]
    risk_score: float

class SecretsScanner:
    """
    Scanner de secrets baseado em regex patterns e validação semântica.
    
    Detecta:
    - API Keys (OpenAI, DeepSeek, etc.)
    - Database URLs
    - OAuth tokens
    - Private keys
    - Passwords
    - Access tokens
    """
    
    def __init__(self, tracing_id: str = None):
        self.tracing_id = tracing_id or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger = logger
        
        # Patterns baseados em OWASP ASVS 1.2
        self.secret_patterns = {
            'api_key': {
                'pattern': r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?',
                'confidence': 0.8,
                'description': 'API Key ou Access Token'
            },
            'database_url': {
                'pattern': r'(?i)(postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+',
                'confidence': 0.9,
                'description': 'Database URL com credenciais'
            },
            'oauth_token': {
                'pattern': r'(?i)(bearer|oauth|jwt)\s+([a-zA-Z0-9\-_]{20,})',
                'confidence': 0.7,
                'description': 'OAuth Token ou JWT'
            },
            'private_key': {
                'pattern': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----',
                'confidence': 0.95,
                'description': 'Private Key (PEM format)'
            },
            'password': {
                'pattern': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
                'confidence': 0.6,
                'description': 'Password em configuração'
            }
        }
        
        # Arquivos e diretórios a ignorar
        self.ignore_patterns = [
            r'\.git/',
            r'node_modules/',
            r'venv/',
            r'__pycache__/',
            r'\.pyc$',
            r'\.log$',
            r'coverage/',
            r'htmlcov/',
            r'test-results/',
            r'\.env\.example$',
            r'README\.md$',
            r'CHANGELOG\.md$'
        ]
        
        # Contextos que indicam falso positivo
        self.false_positive_indicators = [
            r'#\s*example',
            r'#\s*todo',
            r'#\s*fixme',
            r'//\s*example',
            r'//\s*todo',
            r'//\s*fixme',
            r'"""\s*example',
            r"'''\s*example",
            r'placeholder',
            r'dummy',
            r'test',
            r'mock',
            r'fake'
        ]
    
    def scan_directory(self, directory: str = None) -> ScanResult:
        """
        Escaneia um diretório em busca de secrets.
        
        Args:
            directory: Diretório para escanear (padrão: diretório atual)
            
        Returns:
            ScanResult: Resultado do scan
        """
        start_time = datetime.now()
        directory = directory or os.getcwd()
        
        self.logger.info("Iniciando scan de secrets", extra={
            'tracing_id': self.tracing_id,
            'directory': directory,
            'event': 'secrets_scan_started'
        })
        
        matches = []
        files_scanned = 0
        
        try:
            for file_path in self._get_files_to_scan(directory):
                file_matches = self._scan_file(file_path)
                matches.extend(file_matches)
                files_scanned += 1
                
                if files_scanned % 100 == 0:
                    self.logger.info(f"Escaneados {files_scanned} arquivos", extra={
                        'tracing_id': self.tracing_id,
                        'files_scanned': files_scanned,
                        'matches_found': len(matches)
                    })
        
        except Exception as e:
            self.logger.error(f"Erro durante scan: {e}", extra={
                'tracing_id': self.tracing_id,
                'error': str(e),
                'event': 'secrets_scan_error'
            })
            raise
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # Validar falsos positivos
        validated_matches = self._validate_false_positives(matches)
        
        # Calcular métricas
        false_positives = sum(1 for m in validated_matches if m.is_false_positive)
        risk_score = self._calculate_risk_score(validated_matches)
        
        result = ScanResult(
            scan_id=self.tracing_id,
            timestamp=start_time,
            files_scanned=files_scanned,
            secrets_found=len(validated_matches),
            false_positives=false_positives,
            scan_duration=scan_duration,
            matches=validated_matches,
            risk_score=risk_score
        )
        
        self.logger.info("Scan de secrets concluído", extra={
            'tracing_id': self.tracing_id,
            'files_scanned': files_scanned,
            'secrets_found': len(validated_matches),
            'false_positives': false_positives,
            'risk_score': risk_score,
            'scan_duration': scan_duration,
            'event': 'secrets_scan_completed'
        })
        
        return result
    
    def _get_files_to_scan(self, directory: str) -> List[str]:
        """Retorna lista de arquivos para escanear, ignorando padrões específicos."""
        files_to_scan = []
        
        for root, dirs, files in os.walk(directory):
            # Filtrar diretórios
            dirs[:] = [d for d in dirs if not any(re.search(pattern, d) for pattern in self.ignore_patterns)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Verificar se arquivo deve ser ignorado
                if any(re.search(pattern, file_path) for pattern in self.ignore_patterns):
                    continue
                
                # Verificar extensões de arquivo relevantes
                if self._is_relevant_file(file_path):
                    files_to_scan.append(file_path)
        
        return files_to_scan
    
    def _is_relevant_file(self, file_path: str) -> bool:
        """Verifica se arquivo é relevante para scan de secrets."""
        relevant_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp',
            '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.yml', '.yaml', '.json', '.xml', '.properties', '.conf',
            '.env', '.ini', '.cfg', '.config', '.toml'
        }
        
        return Path(file_path).suffix.lower() in relevant_extensions
    
    def _scan_file(self, file_path: str) -> List[SecretMatch]:
        """Escaneia um arquivo específico em busca de secrets."""
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for line_number, line in enumerate(lines, 1):
                line_matches = self._scan_line(line, line_number, file_path)
                matches.extend(line_matches)
        
        except Exception as e:
            self.logger.warning(f"Erro ao ler arquivo {file_path}: {e}", extra={
                'tracing_id': self.tracing_id,
                'file_path': file_path,
                'error': str(e)
            })
        
        return matches
    
    def _scan_line(self, line: str, line_number: int, file_path: str) -> List[SecretMatch]:
        """Escaneia uma linha específica em busca de secrets."""
        matches = []
        
        for secret_type, config in self.secret_patterns.items():
            pattern = config['pattern']
            confidence = config['confidence']
            description = config['description']
            
            for match in re.finditer(pattern, line):
                matched_text = match.group(0)
                
                # Extrair contexto (linha anterior e posterior)
                context = self._extract_context(line, line_number, file_path)
                
                secret_match = SecretMatch(
                    file_path=file_path,
                    line_number=line_number,
                    secret_type=secret_type,
                    matched_text=matched_text,
                    confidence=confidence,
                    context=context
                )
                
                matches.append(secret_match)
        
        return matches
    
    def _extract_context(self, line: str, line_number: int, file_path: str) -> str:
        """Extrai contexto da linha (anterior e posterior)."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_number - 2)
            end = min(len(lines), line_number + 1)
            
            context_lines = []
            for i in range(start, end):
                prefix = ">>> " if i == line_number - 1 else "    "
                context_lines.append(f"{prefix}{i+1:4d}: {lines[i].rstrip()}")
            
            return '\n'.join(context_lines)
        
        except Exception:
            return f"    {line_number:4d}: {line}"
    
    def _validate_false_positives(self, matches: List[SecretMatch]) -> List[SecretMatch]:
        """Valida matches para identificar falsos positivos."""
        validated_matches = []
        
        for match in matches:
            is_false_positive = self._is_false_positive(match)
            
            if is_false_positive:
                match.is_false_positive = True
                match.false_positive_reason = self._get_false_positive_reason(match)
                
                self.logger.info("Falso positivo detectado", extra={
                    'tracing_id': self.tracing_id,
                    'file_path': match.file_path,
                    'line_number': match.line_number,
                    'secret_type': match.secret_type,
                    'reason': match.false_positive_reason,
                    'event': 'false_positive_detected'
                })
            
            validated_matches.append(match)
        
        return validated_matches
    
    def _is_false_positive(self, match: SecretMatch) -> bool:
        """Verifica se um match é falso positivo."""
        context_lower = match.context.lower()
        matched_text_lower = match.matched_text.lower()
        
        # Verificar indicadores de falso positivo
        for indicator in self.false_positive_indicators:
            if re.search(indicator, context_lower):
                return True
        
        # Verificar se é um comentário
        if self._is_in_comment(match):
            return True
        
        # Verificar se é um exemplo ou teste
        if self._is_example_or_test(match):
            return True
        
        return False
    
    def _is_in_comment(self, match: SecretMatch) -> bool:
        """Verifica se o match está em um comentário."""
        context_lines = match.context.split('\n')
        
        for line in context_lines:
            if match.matched_text in line:
                stripped_line = line.strip()
                return (stripped_line.startswith('#') or 
                       stripped_line.startswith('//') or
                       stripped_line.startswith('/*') or
                       stripped_line.startswith('*') or
                       stripped_line.startswith('"""') or
                       stripped_line.startswith("'''"))
        
        return False
    
    def _is_example_or_test(self, match: SecretMatch) -> bool:
        """Verifica se o match está em um exemplo ou teste."""
        file_path_lower = match.file_path.lower()
        
        test_indicators = ['test', 'example', 'sample', 'demo', 'mock', 'fake']
        
        return any(indicator in file_path_lower for indicator in test_indicators)
    
    def _get_false_positive_reason(self, match: SecretMatch) -> str:
        """Retorna o motivo do falso positivo."""
        context_lower = match.context.lower()
        
        if any(re.search(indicator, context_lower) for indicator in self.false_positive_indicators):
            return "Indicador de exemplo/teste detectado"
        
        if self._is_in_comment(match):
            return "Match em comentário"
        
        if self._is_example_or_test(match):
            return "Arquivo de exemplo ou teste"
        
        return "Contexto indica falso positivo"
    
    def _calculate_risk_score(self, matches: List[SecretMatch]) -> float:
        """Calcula score de risco baseado nos secrets encontrados."""
        if not matches:
            return 0.0
        
        # Filtrar apenas matches reais (não falsos positivos)
        real_matches = [m for m in matches if not m.is_false_positive]
        
        if not real_matches:
            return 0.0
        
        # Calcular score baseado em:
        # - Número de secrets
        # - Confiança média
        # - Tipos de secrets (alguns são mais críticos)
        
        total_confidence = sum(m.confidence for m in real_matches)
        avg_confidence = total_confidence / len(real_matches)
        
        # Pesos por tipo de secret
        type_weights = {
            'private_key': 1.0,
            'database_url': 0.9,
            'api_key': 0.8,
            'oauth_token': 0.7,
            'password': 0.6
        }
        
        weighted_score = sum(
            type_weights.get(m.secret_type, 0.5) * m.confidence 
            for m in real_matches
        )
        
        # Normalizar para 0-100
        risk_score = min(100.0, (weighted_score / len(real_matches)) * 100)
        
        return round(risk_score, 2)
    
    def export_results(self, result: ScanResult, output_file: str = None) -> str:
        """Exporta resultados do scan para JSON."""
        if output_file is None:
            output_file = f"secrets_scan_{self.tracing_id}.json"
        
        # Converter para dict para serialização JSON
        result_dict = asdict(result)
        result_dict['timestamp'] = result.timestamp.isoformat()
        
        # Converter matches para dict
        result_dict['matches'] = [asdict(match) for match in result.matches]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
        
        self.logger.info("Resultados exportados", extra={
            'tracing_id': self.tracing_id,
            'output_file': output_file,
            'event': 'results_exported'
        })
        
        return output_file
    
    def generate_report(self, result: ScanResult) -> str:
        """Gera relatório em formato legível."""
        report_lines = [
            f"# Relatório de Secrets Scanner",
            f"**Scan ID:** {result.scan_id}",
            f"**Data/Hora:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duração:** {result.scan_duration:.2f} segundos",
            f"",
            f"## Resumo",
            f"- Arquivos escaneados: {result.files_scanned}",
            f"- Secrets encontrados: {result.secrets_found}",
            f"- Falsos positivos: {result.false_positives}",
            f"- Score de risco: {result.risk_score}/100",
            f"",
            f"## Secrets Detectados"
        ]
        
        if result.matches:
            for match in result.matches:
                status = "❌ FALSO POSITIVO" if match.is_false_positive else "⚠️ SECRET REAL"
                report_lines.extend([
                    f"",
                    f"### {status}",
                    f"**Arquivo:** {match.file_path}",
                    f"**Linha:** {match.line_number}",
                    f"**Tipo:** {match.secret_type}",
                    f"**Confiança:** {match.confidence:.2f}",
                    f"**Match:** `{match.matched_text}`",
                    f"",
                    f"**Contexto:**",
                    f"```",
                    f"{match.context}",
                    f"```"
                ])
                
                if match.is_false_positive:
                    report_lines.append(f"**Motivo:** {match.false_positive_reason}")
        else:
            report_lines.append("Nenhum secret detectado.")
        
        report_content = '\n'.join(report_lines)
        
        # Salvar relatório
        report_file = f"secrets_scan_report_{self.tracing_id}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.logger.info("Relatório gerado", extra={
            'tracing_id': self.tracing_id,
            'report_file': report_file,
            'event': 'report_generated'
        })
        
        return report_file


def main():
    """Função principal para execução do scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scanner de Secrets')
    parser.add_argument('--directory', '-d', default='.', help='Diretório para escanear')
    parser.add_argument('--output', '-o', help='Arquivo de saída JSON')
    parser.add_argument('--report', '-r', help='Arquivo de relatório Markdown')
    parser.add_argument('--tracing-id', '-t', help='ID de rastreamento')
    
    args = parser.parse_args()
    
    # Criar scanner
    scanner = SecretsScanner(tracing_id=args.tracing_id)
    
    # Executar scan
    result = scanner.scan_directory(args.directory)
    
    # Exportar resultados
    if args.output:
        scanner.export_results(result, args.output)
    else:
        scanner.export_results(result)
    
    # Gerar relatório
    if args.report:
        scanner.generate_report(result)
    else:
        scanner.generate_report(result)
    
    # Retornar código de saída baseado no risco
    if result.risk_score > 50:
        print(f"⚠️ Score de risco alto: {result.risk_score}/100")
        return 1
    elif result.risk_score > 20:
        print(f"⚠️ Score de risco médio: {result.risk_score}/100")
        return 0
    else:
        print(f"✅ Score de risco baixo: {result.risk_score}/100")
        return 0


if __name__ == '__main__':
    exit(main()) 