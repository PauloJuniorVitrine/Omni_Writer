#!/usr/bin/env python3
"""
🔒 Sistema de Verificação de Compliance
=======================================

Objetivo: Verificar compliance PCI-DSS e LGPD na documentação
Autor: AI Assistant
Data: 2025-01-27
Tracing ID: COMPLIANCE_CHECK_20250127_001

Compliance: PCI-DSS 6.3, LGPD Art. 37
"""

import os
import json
import re
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/compliance_checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ComplianceLevel(Enum):
    """Níveis de compliance"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    PASS = "pass"

@dataclass
class ComplianceRule:
    """Regra de compliance"""
    rule_id: str
    name: str
    description: str
    level: ComplianceLevel
    pci_dss_requirement: str
    lgpd_requirement: str
    pattern: str
    enabled: bool = True
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class ComplianceViolation:
    """Violação de compliance"""
    rule_id: str
    file_path: str
    line_number: int
    content: str
    level: ComplianceLevel
    description: str
    timestamp: datetime = None
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

@dataclass
class ComplianceReport:
    """Relatório de compliance"""
    timestamp: datetime
    total_files: int
    total_violations: int
    critical_violations: int
    high_violations: int
    medium_violations: int
    low_violations: int
    compliance_score: float
    pci_dss_score: float
    lgpd_score: float
    violations: List[ComplianceViolation] = None
    recommendations: List[str] = None

    def __post_init__(self):
        if self.violations is None:
            self.violations = []
        if self.recommendations is None:
            self.recommendations = []
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

class ComplianceChecker:
    """
    Sistema de verificação de compliance
    """
    
    def __init__(self):
        self.rules: List[ComplianceRule] = []
        self.reports: List[ComplianceReport] = []
        
        # Configurar regras de compliance
        self._setup_compliance_rules()
        
        logger.info(f"[COMPLIANCE] Sistema inicializado com {len(self.rules)} regras")

    def _setup_compliance_rules(self) -> None:
        """Configura regras de compliance"""
        
        # Regras PCI-DSS
        self.rules.extend([
            ComplianceRule(
                rule_id="PCI_001",
                name="Dados de Cartão de Crédito",
                description="Detectar números de cartão de crédito",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 3.4",
                lgpd_requirement="LGPD Art. 9",
                pattern=r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
            ),
            ComplianceRule(
                rule_id="PCI_002",
                name="CVV/CVC",
                description="Detectar códigos de segurança",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 3.4",
                lgpd_requirement="LGPD Art. 9",
                pattern=r"\b\d{3,4}\b"
            ),
            ComplianceRule(
                rule_id="PCI_003",
                name="Data de Expiração",
                description="Detectar datas de expiração",
                level=ComplianceLevel.HIGH,
                pci_dss_requirement="PCI-DSS 3.4",
                lgpd_requirement="LGPD Art. 9",
                pattern=r"\b(0[1-9]|1[0-2])/([0-9]{2})\b"
            )
        ])
        
        # Regras LGPD
        self.rules.extend([
            ComplianceRule(
                rule_id="LGPD_001",
                name="CPF",
                description="Detectar CPFs",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 6.3",
                lgpd_requirement="LGPD Art. 5",
                pattern=r"\b\d{3}[.-]?\d{3}[.-]?\d{3}[.-]?\d{2}\b"
            ),
            ComplianceRule(
                rule_id="LGPD_002",
                name="CNPJ",
                description="Detectar CNPJs",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 6.3",
                lgpd_requirement="LGPD Art. 5",
                pattern=r"\b\d{2}[.-]?\d{3}[.-]?\d{3}[.-]?\d{4}[.-]?\d{2}\b"
            ),
            ComplianceRule(
                rule_id="LGPD_003",
                name="Email Pessoal",
                description="Detectar emails pessoais",
                level=ComplianceLevel.HIGH,
                pci_dss_requirement="PCI-DSS 6.3",
                lgpd_requirement="LGPD Art. 5",
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ),
            ComplianceRule(
                rule_id="LGPD_004",
                name="Telefone",
                description="Detectar números de telefone",
                level=ComplianceLevel.MEDIUM,
                pci_dss_requirement="PCI-DSS 6.3",
                lgpd_requirement="LGPD Art. 5",
                pattern=r"\b\(?\d{2}\)?\s?\d{4,5}[-\s]?\d{4}\b"
            )
        ])
        
        # Regras de Segurança
        self.rules.extend([
            ComplianceRule(
                rule_id="SEC_001",
                name="Senhas Hardcoded",
                description="Detectar senhas no código",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 7.1",
                lgpd_requirement="LGPD Art. 46",
                pattern=r"password\s*=\s*['\"][^'\"]+['\"]"
            ),
            ComplianceRule(
                rule_id="SEC_002",
                name="Tokens de API",
                description="Detectar tokens de API",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 7.1",
                lgpd_requirement="LGPD Art. 46",
                pattern=r"api_key\s*=\s*['\"][^'\"]+['\"]"
            ),
            ComplianceRule(
                rule_id="SEC_003",
                name="Chaves Privadas",
                description="Detectar chaves privadas",
                level=ComplianceLevel.CRITICAL,
                pci_dss_requirement="PCI-DSS 3.5",
                lgpd_requirement="LGPD Art. 46",
                pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"
            ),
            ComplianceRule(
                rule_id="SEC_004",
                name="URLs de Banco de Dados",
                description="Detectar URLs de banco de dados",
                level=ComplianceLevel.HIGH,
                pci_dss_requirement="PCI-DSS 7.1",
                lgpd_requirement="LGPD Art. 46",
                pattern=r"postgresql://|mysql://|mongodb://"
            )
        ])

    def check_file_compliance(self, file_path: str) -> List[ComplianceViolation]:
        """Verifica compliance de um arquivo específico"""
        violations = []
        
        try:
            if not os.path.exists(file_path):
                logger.warning(f"[COMPLIANCE] Arquivo não encontrado: {file_path}")
                return violations
            
            # Verificar se é arquivo de texto
            if not self._is_text_file(file_path):
                return violations
            
            # Ler conteúdo do arquivo
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Verificar cada linha
            for line_number, line in enumerate(lines, 1):
                line_violations = self._check_line_compliance(line, file_path, line_number)
                violations.extend(line_violations)
            
            logger.info(f"[COMPLIANCE] Verificado {file_path}: {len(violations)} violações")
            return violations
            
        except Exception as e:
            logger.error(f"[COMPLIANCE] Erro ao verificar {file_path}: {e}")
            return violations

    def _is_text_file(self, file_path: str) -> bool:
        """Verifica se arquivo é de texto"""
        text_extensions = ['.md', '.txt', '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.html', '.css']
        return any(file_path.endswith(ext) for ext in text_extensions)

    def _check_line_compliance(self, line: str, file_path: str, line_number: int) -> List[ComplianceViolation]:
        """Verifica compliance de uma linha específica"""
        violations = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Verificar se linha contém padrão
            matches = re.finditer(rule.pattern, line, re.IGNORECASE)
            
            for match in matches:
                # Verificar se é falso positivo
                if self._is_false_positive(match.group(), line, rule):
                    continue
                
                # Criar violação
                violation = ComplianceViolation(
                    rule_id=rule.rule_id,
                    file_path=file_path,
                    line_number=line_number,
                    content=line.strip(),
                    level=rule.level,
                    description=rule.description,
                    metadata={
                        "matched_text": match.group(),
                        "pci_dss_requirement": rule.pci_dss_requirement,
                        "lgpd_requirement": rule.lgpd_requirement
                    }
                )
                
                violations.append(violation)
        
        return violations

    def _is_false_positive(self, matched_text: str, line: str, rule: ComplianceRule) -> bool:
        """Verifica se match é falso positivo"""
        
        # Falsos positivos comuns
        false_positive_patterns = {
            "PCI_001": [
                r"example\.com",  # URLs de exemplo
                r"test\s+card",   # Cartões de teste
                r"placeholder",   # Placeholders
                r"dummy"          # Dados dummy
            ],
            "LGPD_001": [
                r"000\.000\.000-00",  # CPF de exemplo
                r"111\.111\.111-11",  # CPF de exemplo
                r"example",           # Exemplos
                r"test"               # Testes
            ],
            "LGPD_002": [
                r"00\.000\.000/0000-00",  # CNPJ de exemplo
                r"11\.111\.111/1111-11",  # CNPJ de exemplo
                r"example",               # Exemplos
                r"test"                   # Testes
            ],
            "SEC_001": [
                r"password\s*=\s*['\"]\*+['\"]",  # Senhas mascaradas
                r"password\s*=\s*['\"]<.*>['\"]",  # Placeholders
                r"example",                        # Exemplos
                r"test"                            # Testes
            ]
        }
        
        # Verificar padrões de falso positivo
        if rule.rule_id in false_positive_patterns:
            for pattern in false_positive_patterns[rule.rule_id]:
                if re.search(pattern, line, re.IGNORECASE):
                    return True
        
        return False

    def check_directory_compliance(self, directory: str) -> List[ComplianceViolation]:
        """Verifica compliance de um diretório"""
        all_violations = []
        
        try:
            if not os.path.exists(directory):
                logger.warning(f"[COMPLIANCE] Diretório não encontrado: {directory}")
                return all_violations
            
            # Encontrar arquivos de texto
            text_files = []
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._is_text_file(file_path):
                        text_files.append(file_path)
            
            logger.info(f"[COMPLIANCE] Verificando {len(text_files)} arquivos em {directory}")
            
            # Verificar arquivos em paralelo
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(self.check_file_compliance, f) for f in text_files]
                
                for future in futures:
                    try:
                        violations = future.result()
                        all_violations.extend(violations)
                    except Exception as e:
                        logger.error(f"[COMPLIANCE] Erro ao processar arquivo: {e}")
            
            logger.info(f"[COMPLIANCE] Verificação concluída: {len(all_violations)} violações encontradas")
            return all_violations
            
        except Exception as e:
            logger.error(f"[COMPLIANCE] Erro ao verificar diretório {directory}: {e}")
            return all_violations

    def generate_compliance_report(self, violations: List[ComplianceViolation]) -> ComplianceReport:
        """Gera relatório de compliance"""
        try:
            # Contar violações por nível
            critical_violations = len([v for v in violations if v.level == ComplianceLevel.CRITICAL])
            high_violations = len([v for v in violations if v.level == ComplianceLevel.HIGH])
            medium_violations = len([v for v in violations if v.level == ComplianceLevel.MEDIUM])
            low_violations = len([v for v in violations if v.level == ComplianceLevel.LOW])
            
            total_violations = len(violations)
            
            # Calcular scores
            if total_violations == 0:
                compliance_score = 100.0
                pci_dss_score = 100.0
                lgpd_score = 100.0
            else:
                # Score baseado na severidade das violações
                severity_weights = {
                    ComplianceLevel.CRITICAL: 10,
                    ComplianceLevel.HIGH: 5,
                    ComplianceLevel.MEDIUM: 2,
                    ComplianceLevel.LOW: 1
                }
                
                total_weight = sum(severity_weights[v.level] for v in violations)
                max_weight = total_violations * 10  # Pior caso: todas críticas
                
                compliance_score = max(0, 100 - (total_weight / max_weight) * 100)
                
                # Scores específicos
                pci_violations = [v for v in violations if "PCI-DSS" in v.metadata.get("pci_dss_requirement", "")]
                lgpd_violations = [v for v in violations if "LGPD" in v.metadata.get("lgpd_requirement", "")]
                
                pci_dss_score = max(0, 100 - (len(pci_violations) * 10))
                lgpd_score = max(0, 100 - (len(lgpd_violations) * 10))
            
            # Gerar recomendações
            recommendations = self._generate_recommendations(violations)
            
            # Criar relatório
            report = ComplianceReport(
                timestamp=datetime.now(timezone.utc),
                total_files=len(set(v.file_path for v in violations)),
                total_violations=total_violations,
                critical_violations=critical_violations,
                high_violations=high_violations,
                medium_violations=medium_violations,
                low_violations=low_violations,
                compliance_score=round(compliance_score, 2),
                pci_dss_score=round(pci_dss_score, 2),
                lgpd_score=round(lgpd_score, 2),
                violations=violations,
                recommendations=recommendations
            )
            
            return report
            
        except Exception as e:
            logger.error(f"[COMPLIANCE] Erro ao gerar relatório: {e}")
            return ComplianceReport(
                timestamp=datetime.now(timezone.utc),
                total_files=0,
                total_violations=0,
                critical_violations=0,
                high_violations=0,
                medium_violations=0,
                low_violations=0,
                compliance_score=0.0,
                pci_dss_score=0.0,
                lgpd_score=0.0
            )

    def _generate_recommendations(self, violations: List[ComplianceViolation]) -> List[str]:
        """Gera recomendações baseadas nas violações"""
        recommendations = []
        
        # Agrupar violações por tipo
        violation_types = {}
        for violation in violations:
            rule_id = violation.rule_id
            if rule_id not in violation_types:
                violation_types[rule_id] = []
            violation_types[rule_id].append(violation)
        
        # Recomendações específicas
        if "PCI_001" in violation_types:
            recommendations.append("Remover números de cartão de crédito da documentação")
        
        if "LGPD_001" in violation_types:
            recommendations.append("Remover CPFs da documentação ou mascarar dados")
        
        if "LGPD_002" in violation_types:
            recommendations.append("Remover CNPJs da documentação ou mascarar dados")
        
        if "SEC_001" in violation_types:
            recommendations.append("Remover senhas hardcoded e usar variáveis de ambiente")
        
        if "SEC_002" in violation_types:
            recommendations.append("Remover tokens de API e usar configurações seguras")
        
        # Recomendações gerais
        if len(violations) > 10:
            recommendations.append("Implementar processo de revisão de compliance antes do commit")
        
        critical_count = len([v for v in violations if v.level == ComplianceLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append("Priorizar correção de violações críticas imediatamente")
        
        return recommendations

    def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Exporta relatório de compliance"""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            
            if format.lower() == "json":
                filename = f"compliance_report_{timestamp}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(asdict(report), f, indent=2, ensure_ascii=False, default=str)
            
            elif format.lower() == "html":
                filename = f"compliance_report_{timestamp}.html"
                self._export_html_report(report, filename)
            
            else:
                logger.error(f"[COMPLIANCE] Formato não suportado: {format}")
                return ""
            
            logger.info(f"[COMPLIANCE] Relatório exportado: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"[COMPLIANCE] Erro ao exportar relatório: {e}")
            return ""

    def _export_html_report(self, report: ComplianceReport, filename: str) -> None:
        """Exporta relatório em formato HTML"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Relatório de Compliance - {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .score {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .violation {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
        .recommendation {{ background-color: #e3f2fd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Compliance</h1>
        <p>Data: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div class="score">
            Score Geral: {report.compliance_score}/100
        </div>
        <div>
            PCI-DSS: {report.pci_dss_score}/100 | LGPD: {report.lgpd_score}/100
        </div>
    </div>
    
    <h2>Resumo</h2>
    <ul>
        <li>Arquivos verificados: {report.total_files}</li>
        <li>Total de violações: {report.total_violations}</li>
        <li>Críticas: <span class="critical">{report.critical_violations}</span></li>
        <li>Altas: <span class="high">{report.high_violations}</span></li>
        <li>Médias: <span class="medium">{report.medium_violations}</span></li>
        <li>Baixas: <span class="low">{report.low_violations}</span></li>
    </ul>
    
    <h2>Violações</h2>
"""
        
        for violation in report.violations:
            level_class = violation.level.value
            html_content += f"""
    <div class="violation">
        <strong class="{level_class}">{violation.rule_id}: {violation.description}</strong><br>
        Arquivo: {violation.file_path}:{violation.line_number}<br>
        Conteúdo: {violation.content[:100]}...
    </div>
"""
        
        html_content += f"""
    <h2>Recomendações</h2>
"""
        
        for recommendation in report.recommendations:
            html_content += f"""
    <div class="recommendation">
        {recommendation}
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def run_compliance_check(self, directories: List[str] = None) -> ComplianceReport:
        """Executa verificação completa de compliance"""
        try:
            if directories is None:
                directories = ["docs", "scripts", "omni_writer", "app"]
            
            logger.info(f"[COMPLIANCE] Iniciando verificação de compliance")
            
            # Verificar cada diretório
            all_violations = []
            for directory in directories:
                violations = self.check_directory_compliance(directory)
                all_violations.extend(violations)
            
            # Gerar relatório
            report = self.generate_compliance_report(all_violations)
            
            # Exportar relatório
            export_file = self.export_report(report)
            
            # Adicionar ao histórico
            self.reports.append(report)
            
            logger.info(f"[COMPLIANCE] Verificação concluída - {len(all_violations)} violações encontradas")
            
            return report
            
        except Exception as e:
            logger.error(f"[COMPLIANCE] Erro na verificação: {e}")
            return None

    def get_statistics(self) -> Dict:
        """Retorna estatísticas do sistema"""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "total_reports": len(self.reports),
            "last_check": self.reports[-1].timestamp if self.reports else None
        }


def main():
    """Função principal"""
    print("🔒 Iniciando Verificação de Compliance...")
    
    # Inicializar verificador
    checker = ComplianceChecker()
    
    # Executar verificação
    report = checker.run_compliance_check()
    
    if report:
        print(f"✅ Verificação concluída")
        print(f"📊 Score Geral: {report.compliance_score}/100")
        print(f"🔒 PCI-DSS: {report.pci_dss_score}/100")
        print(f"📋 LGPD: {report.lgpd_score}/100")
        print(f"⚠️ Violações: {report.total_violations}")
        print(f"   - Críticas: {report.critical_violations}")
        print(f"   - Altas: {report.high_violations}")
        print(f"   - Médias: {report.medium_violations}")
        print(f"   - Baixas: {report.low_violations}")
        
        if report.recommendations:
            print(f"\n💡 Recomendações:")
            for rec in report.recommendations:
                print(f"   - {rec}")
    else:
        print("❌ Erro na verificação de compliance")


if __name__ == "__main__":
    main() 