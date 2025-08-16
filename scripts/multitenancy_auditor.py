#!/usr/bin/env python3
"""
Multitenancy Auditor - Omni Writer
==================================

Sistema de auditoria de multitenancy para detectar isolamento de dados
e configurações por tenant, garantindo segurança e compliance.

Tracing ID: MULTITENANCY_AUDIT_20250127_001
Ruleset: enterprise_control_layer.yaml
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import ast
import logging

@dataclass
class TenantConfig:
    """Representa configuração de tenant identificada."""
    tenant_id: str
    config_type: str  # 'database', 'cache', 'storage', 'api', 'ui'
    isolation_level: str  # 'strong', 'weak', 'none'
    implementation: str
    file_path: str
    line_number: int
    security_score: float
    compliance_status: str  # 'compliant', 'partial', 'non_compliant'

@dataclass
class MultitenancyAuditResult:
    """Resultado da auditoria de multitenancy."""
    timestamp: datetime
    total_tenants: int
    strong_isolation: int
    weak_isolation: int
    no_isolation: int
    security_issues: int
    compliance_issues: int
    recommendations: List[str]
    isolation_score: float

class MultitenancyAuditor:
    """Auditor de multitenancy com análise de isolamento e segurança."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.audit_log_path = self.project_root / "logs" / "multitenancy_audit.log"
        self.results_path = self.project_root / "monitoring" / "multitenancy_audit_results.json"
        self.tracing_id = f"MULTITENANCY_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configurar logging estruturado
        self._setup_logging()
        
        # Padrões de detecção de multitenancy
        self.multitenancy_patterns = {
            'tenant_identification': [
                r'tenant_id',
                r'tenantId',
                r'tenant[-_]?id',
                r'organization[-_]?id',
                r'org[-_]?id',
                r'client[-_]?id'
            ],
            'database_isolation': [
                r'tenant[-_]?schema',
                r'tenant[-_]?database',
                r'tenant[-_]?table',
                r'WHERE.*tenant',
                r'tenant[-_]?filter',
                r'tenant[-_]?context'
            ],
            'cache_isolation': [
                r'tenant[-_]?cache',
                r'tenant[-_]?key',
                r'cache.*tenant',
                r'redis.*tenant',
                r'memcached.*tenant'
            ],
            'storage_isolation': [
                r'tenant[-_]?bucket',
                r'tenant[-_]?folder',
                r'tenant[-_]?path',
                r'storage.*tenant',
                r's3.*tenant'
            ],
            'api_isolation': [
                r'tenant[-_]?header',
                r'tenant[-_]?auth',
                r'tenant[-_]?middleware',
                r'tenant[-_]?validation'
            ],
            'ui_isolation': [
                r'tenant[-_]?theme',
                r'tenant[-_]?config',
                r'tenant[-_]?settings',
                r'tenant[-_]?branding'
            ]
        }
        
        # Padrões de segurança
        self.security_patterns = {
            'data_encryption': [
                r'encrypt',
                r'decrypt',
                r'AES',
                r'RSA',
                r'bcrypt',
                r'hash'
            ],
            'access_control': [
                r'permission',
                r'authorization',
                r'role',
                r'access[-_]?control',
                r'rbac'
            ],
            'audit_logging': [
                r'audit[-_]?log',
                r'audit[-_]?trail',
                r'tenant[-_]?log',
                r'access[-_]?log'
            ]
        }
        
    def _setup_logging(self):
        """Configura logging estruturado para auditoria."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] [MULTITENANCY_AUDIT] %(message)s',
            handlers=[
                logging.FileHandler(self.audit_log_path),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _log_audit_event(self, event: str, details: Dict = None):
        """Registra evento de auditoria com metadados."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": self.tracing_id,
            "event": event,
            "details": details or {}
        }
        self.logger.info(f"Multitenancy Audit Event: {json.dumps(log_entry)}")
        
    def find_multitenancy_files(self) -> List[Path]:
        """Encontra arquivos relacionados a multitenancy."""
        self._log_audit_event("finding_multitenancy_files")
        
        relevant_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.sql', '.yaml', '.yml', '.json'}
        multitenancy_files = []
        
        # Diretórios relevantes
        relevant_dirs = [
            self.project_root / "app",
            self.project_root / "ui",
            self.project_root / "shared",
            self.project_root / "infraestructure",
            self.project_root / "scripts"
        ]
        
        for relevant_dir in relevant_dirs:
            if relevant_dir.exists():
                for file_path in relevant_dir.rglob('*'):
                    if file_path.suffix in relevant_extensions:
                        # Verificar se contém padrões de multitenancy
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                            # Verificar se contém algum padrão de multitenancy
                            for pattern_category, patterns in self.multitenancy_patterns.items():
                                for pattern in patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        multitenancy_files.append(file_path)
                                        break
                                else:
                                    continue
                                break
                                
                        except Exception as e:
                            self.logger.warning(f"Erro ao ler arquivo {file_path}: {e}")
        
        self._log_audit_event("multitenancy_files_found", {"count": len(multitenancy_files)})
        return multitenancy_files
    
    def analyze_tenant_configurations(self, file_path: Path) -> List[TenantConfig]:
        """Analisa configurações de tenant em um arquivo específico."""
        tenant_configs = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Analisar cada tipo de configuração
            for config_type, patterns in self.multitenancy_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        
                        # Verificar se é uma implementação real
                        if self._is_real_implementation(content, match.start(), match.end()):
                            # Extrair tenant_id se disponível
                            tenant_id = self._extract_tenant_id(content, match.start())
                            
                            # Determinar nível de isolamento
                            isolation_level = self._determine_isolation_level(content, line_number, config_type)
                            
                            # Calcular score de segurança
                            security_score = self._calculate_security_score(content, line_number, config_type)
                            
                            # Determinar status de compliance
                            compliance_status = self._determine_compliance_status(isolation_level, security_score)
                            
                            tenant_config = TenantConfig(
                                tenant_id=tenant_id or "dynamic",
                                config_type=config_type,
                                isolation_level=isolation_level,
                                implementation=match.group(),
                                file_path=str(file_path),
                                line_number=line_number,
                                security_score=security_score,
                                compliance_status=compliance_status
                            )
                            tenant_configs.append(tenant_config)
                            
        except Exception as e:
            self.logger.warning(f"Erro ao analisar configurações de tenant em {file_path}: {e}")
            
        return tenant_configs
    
    def _is_real_implementation(self, content: str, start: int, end: int) -> bool:
        """Verifica se é uma implementação real, não apenas comentário ou string."""
        # Verificar se não está em comentário
        before_content = content[:start]
        after_content = content[end:]
        
        # Verificar comentários de linha
        line_start = before_content.rfind('\n') + 1
        line_content = content[line_start:end]
        
        if '//' in line_content and line_content.find('//') < line_content.find(content[start:end]):
            return False
            
        # Verificar comentários de bloco
        comment_start = before_content.rfind('/*')
        comment_end = after_content.find('*/')
        
        if comment_start != -1 and comment_end != -1:
            if start > comment_start and end < (start + comment_end):
                return False
                
        return True
    
    def _extract_tenant_id(self, content: str, match_start: int) -> Optional[str]:
        """Extrai tenant_id da implementação."""
        # Procurar por padrões de tenant_id próximos
        context_start = max(0, match_start - 200)
        context_end = min(len(content), match_start + 200)
        context = content[context_start:context_end]
        
        # Padrões para extrair tenant_id
        tenant_patterns = [
            r'tenant[-_]?id\s*[:=]\s*["\']([^"\']+)["\']',
            r'tenant[-_]?id\s*[:=]\s*(\w+)',
            r'tenantId\s*[:=]\s*["\']([^"\']+)["\']',
            r'tenantId\s*[:=]\s*(\w+)'
        ]
        
        for pattern in tenant_patterns:
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
    
    def _determine_isolation_level(self, content: str, line_number: int, config_type: str) -> str:
        """Determina o nível de isolamento baseado no contexto."""
        lines = content.split('\n')
        if line_number > len(lines):
            return "none"
            
        line_content = lines[line_number - 1]
        context_lines = lines[max(0, line_number - 5):line_number + 5]
        context = '\n'.join(context_lines)
        
        # Padrões de isolamento forte
        strong_patterns = [
            r'tenant[-_]?schema',
            r'tenant[-_]?database',
            r'tenant[-_]?bucket',
            r'tenant[-_]?folder',
            r'WHERE.*tenant',
            r'tenant[-_]?filter',
            r'tenant[-_]?context'
        ]
        
        # Padrões de isolamento fraco
        weak_patterns = [
            r'tenant[-_]?key',
            r'tenant[-_]?prefix',
            r'tenant[-_]?namespace',
            r'tenant[-_]?header'
        ]
        
        # Verificar isolamento forte
        for pattern in strong_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return "strong"
        
        # Verificar isolamento fraco
        for pattern in weak_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return "weak"
        
        return "none"
    
    def _calculate_security_score(self, content: str, line_number: int, config_type: str) -> float:
        """Calcula score de segurança (0-100)."""
        lines = content.split('\n')
        if line_number > len(lines):
            return 0.0
            
        context_lines = lines[max(0, line_number - 10):line_number + 10]
        context = '\n'.join(context_lines)
        
        score = 50.0  # Score base
        
        # Bônus por padrões de segurança
        for security_category, patterns in self.security_patterns.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    if security_category == 'data_encryption':
                        score += 20
                    elif security_category == 'access_control':
                        score += 15
                    elif security_category == 'audit_logging':
                        score += 10
        
        # Penalidades por padrões inseguros
        insecure_patterns = [
            r'tenant.*password',
            r'tenant.*secret',
            r'tenant.*key.*hardcoded',
            r'tenant.*id.*exposed'
        ]
        
        for pattern in insecure_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                score -= 30
        
        return max(0.0, min(100.0, score))
    
    def _determine_compliance_status(self, isolation_level: str, security_score: float) -> str:
        """Determina status de compliance baseado no isolamento e segurança."""
        if isolation_level == "strong" and security_score >= 80:
            return "compliant"
        elif isolation_level in ["strong", "weak"] and security_score >= 60:
            return "partial"
        else:
            return "non_compliant"
    
    def identify_tenant_isolation_gaps(self, tenant_configs: List[TenantConfig]) -> List[Dict]:
        """Identifica gaps de isolamento de tenant."""
        isolation_gaps = []
        
        # Agrupar por tenant_id
        tenant_groups = {}
        for config in tenant_configs:
            tenant_id = config.tenant_id
            if tenant_id not in tenant_groups:
                tenant_groups[tenant_id] = []
            tenant_groups[tenant_id].append(config)
        
        # Analisar cada tenant
        for tenant_id, configs in tenant_groups.items():
            config_types = [c.config_type for c in configs]
            isolation_levels = [c.isolation_level for c in configs]
            
            # Verificar se todos os tipos críticos estão cobertos
            critical_types = ['database_isolation', 'api_isolation']
            missing_critical = [t for t in critical_types if t not in config_types]
            
            if missing_critical:
                isolation_gaps.append({
                    'tenant_id': tenant_id,
                    'missing_types': missing_critical,
                    'severity': 'high',
                    'recommendation': f"Implementar isolamento para: {', '.join(missing_critical)}"
                })
            
            # Verificar se há isolamento fraco ou nenhum isolamento
            weak_or_none = [level for level in isolation_levels if level in ['weak', 'none']]
            if weak_or_none:
                isolation_gaps.append({
                    'tenant_id': tenant_id,
                    'weak_isolation_types': [c.config_type for c in configs if c.isolation_level in ['weak', 'none']],
                    'severity': 'medium',
                    'recommendation': "Melhorar nível de isolamento para strong"
                })
        
        return isolation_gaps
    
    def analyze_security_compliance(self, tenant_configs: List[TenantConfig]) -> Dict:
        """Analisa compliance de segurança dos tenants."""
        security_analysis = {
            'compliant_tenants': 0,
            'partial_compliant_tenants': 0,
            'non_compliant_tenants': 0,
            'average_security_score': 0.0,
            'security_issues': []
        }
        
        # Agrupar por tenant_id
        tenant_groups = {}
        for config in tenant_configs:
            tenant_id = config.tenant_id
            if tenant_id not in tenant_groups:
                tenant_groups[tenant_id] = []
            tenant_groups[tenant_id].append(config)
        
        total_security_score = 0.0
        total_configs = len(tenant_configs)
        
        for tenant_id, configs in tenant_groups.items():
            # Determinar status geral do tenant
            statuses = [c.compliance_status for c in configs]
            security_scores = [c.security_score for c in configs]
            
            avg_security_score = sum(security_scores) / len(security_scores)
            total_security_score += avg_security_score
            
            if 'non_compliant' in statuses:
                security_analysis['non_compliant_tenants'] += 1
                security_analysis['security_issues'].append({
                    'tenant_id': tenant_id,
                    'issue': 'Non-compliant security configuration',
                    'avg_security_score': avg_security_score
                })
            elif 'partial' in statuses:
                security_analysis['partial_compliant_tenants'] += 1
            else:
                security_analysis['compliant_tenants'] += 1
        
        if total_configs > 0:
            security_analysis['average_security_score'] = total_security_score / len(tenant_groups)
        
        return security_analysis
    
    def generate_multitenancy_recommendations(self, tenant_configs: List[TenantConfig], 
                                            isolation_gaps: List[Dict], 
                                            security_analysis: Dict) -> List[str]:
        """Gera recomendações para melhorar multitenancy."""
        recommendations = []
        
        # Recomendações baseadas em gaps de isolamento
        high_severity_gaps = [gap for gap in isolation_gaps if gap['severity'] == 'high']
        if high_severity_gaps:
            recommendations.append(f"🚨 {len(high_severity_gaps)} tenant(s) com gaps críticos de isolamento. Implementar urgente.")
        
        # Recomendações baseadas em compliance de segurança
        if security_analysis['non_compliant_tenants'] > 0:
            recommendations.append(f"🔒 {security_analysis['non_compliant_tenants']} tenant(s) não compliant com segurança. Revisar configurações.")
        
        if security_analysis['average_security_score'] < 70:
            recommendations.append(f"⚠️ Score médio de segurança baixo ({security_analysis['average_security_score']:.1f}). Implementar criptografia e controle de acesso.")
        
        # Recomendações específicas por tipo de configuração
        config_types = {}
        for config in tenant_configs:
            config_types[config.config_type] = config_types.get(config.config_type, 0) + 1
        
        if config_types.get('database_isolation', 0) < 3:
            recommendations.append("🗄️ Poucas configurações de isolamento de banco. Implementar schemas separados por tenant.")
            
        if config_types.get('api_isolation', 0) < 2:
            recommendations.append("🔐 Configurações de isolamento de API limitadas. Implementar middleware de tenant.")
            
        if config_types.get('audit_logging', 0) < 1:
            recommendations.append("📝 Logging de auditoria ausente. Implementar logs específicos por tenant.")
        
        return recommendations
    
    def run_audit(self) -> MultitenancyAuditResult:
        """Executa auditoria completa de multitenancy."""
        self._log_audit_event("starting_multitenancy_audit")
        
        # Encontrar arquivos de multitenancy
        multitenancy_files = self.find_multitenancy_files()
        
        # Analisar configurações de tenant
        all_tenant_configs = []
        for file_path in multitenancy_files:
            tenant_configs = self.analyze_tenant_configurations(file_path)
            all_tenant_configs.extend(tenant_configs)
        
        # Identificar gaps de isolamento
        isolation_gaps = self.identify_tenant_isolation_gaps(all_tenant_configs)
        
        # Analisar compliance de segurança
        security_analysis = self.analyze_security_compliance(all_tenant_configs)
        
        # Gerar recomendações
        recommendations = self.generate_multitenancy_recommendations(
            all_tenant_configs, isolation_gaps, security_analysis
        )
        
        # Calcular métricas
        total_tenants = len(set(config.tenant_id for config in all_tenant_configs))
        strong_isolation = len([c for c in all_tenant_configs if c.isolation_level == "strong"])
        weak_isolation = len([c for c in all_tenant_configs if c.isolation_level == "weak"])
        no_isolation = len([c for c in all_tenant_configs if c.isolation_level == "none"])
        security_issues = len(security_analysis['security_issues'])
        compliance_issues = security_analysis['non_compliant_tenants']
        
        # Calcular score de isolamento
        total_configs = len(all_tenant_configs)
        if total_configs > 0:
            isolation_score = (strong_isolation * 1.0 + weak_isolation * 0.5) / total_configs * 100
        else:
            isolation_score = 0.0
        
        # Criar resultado
        result = MultitenancyAuditResult(
            timestamp=datetime.now(),
            total_tenants=total_tenants,
            strong_isolation=strong_isolation,
            weak_isolation=weak_isolation,
            no_isolation=no_isolation,
            security_issues=security_issues,
            compliance_issues=compliance_issues,
            recommendations=recommendations,
            isolation_score=isolation_score
        )
        
        # Salvar resultados
        self._save_results(all_tenant_configs, isolation_gaps, security_analysis, result)
        
        self._log_audit_event("multitenancy_audit_completed", {
            "total_tenants": total_tenants,
            "strong_isolation": strong_isolation,
            "isolation_score": isolation_score,
            "security_issues": security_issues
        })
        
        return result
    
    def _save_results(self, tenant_configs: List[TenantConfig], isolation_gaps: List[Dict], 
                     security_analysis: Dict, audit_result: MultitenancyAuditResult):
        """Salva resultados da auditoria."""
        results_data = {
            "audit_result": asdict(audit_result),
            "tenant_configs": [asdict(config) for config in tenant_configs],
            "isolation_gaps": isolation_gaps,
            "security_analysis": security_analysis,
            "metadata": {
                "tracing_id": self.tracing_id,
                "generated_at": datetime.now().isoformat(),
                "ruleset": "enterprise_control_layer.yaml"
            }
        }
        
        # Converter datetime para string
        results_data["audit_result"]["timestamp"] = results_data["audit_result"]["timestamp"].isoformat()
        
        # Salvar em JSON
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self._log_audit_event("results_saved", {"path": str(self.results_path)})
    
    def generate_report(self) -> str:
        """Gera relatório em markdown da auditoria."""
        if not self.results_path.exists():
            return "❌ Nenhum resultado de auditoria encontrado."
        
        with open(self.results_path, 'r') as f:
            data = json.load(f)
        
        audit_result = data["audit_result"]
        tenant_configs = data["tenant_configs"]
        isolation_gaps = data["isolation_gaps"]
        security_analysis = data["security_analysis"]
        
        report = f"""# 🏢 Multitenancy Audit Report

**Tracing ID:** {data['metadata']['tracing_id']}  
**Generated:** {data['metadata']['generated_at']}  
**Ruleset:** {data['metadata']['ruleset']}

## 📊 Summary

- **Total Tenants:** {audit_result['total_tenants']}
- **Strong Isolation:** {audit_result['strong_isolation']}
- **Weak Isolation:** {audit_result['weak_isolation']}
- **No Isolation:** {audit_result['no_isolation']}
- **Security Issues:** {audit_result['security_issues']}
- **Compliance Issues:** {audit_result['compliance_issues']}
- **Isolation Score:** {audit_result['isolation_score']:.1f}%

## 🚨 Recommendations

"""
        
        for rec in audit_result['recommendations']:
            report += f"- {rec}\n"
        
        report += f"""

## 🔒 Security Analysis

- **Compliant Tenants:** {security_analysis['compliant_tenants']}
- **Partial Compliant:** {security_analysis['partial_compliant_tenants']}
- **Non-Compliant:** {security_analysis['non_compliant_tenants']}
- **Average Security Score:** {security_analysis['average_security_score']:.1f}/100

## ⚠️ Isolation Gaps

"""
        
        for gap in isolation_gaps:
            report += f"- **{gap['tenant_id']}** - {gap['severity'].upper()}: {gap['recommendation']}\n"
        
        report += "\n## 📋 Tenant Configurations\n\n"
        report += "| Tenant | Type | Isolation | Security | Compliance | File |\n"
        report += "|--------|------|-----------|----------|------------|------|\n"
        
        for config in tenant_configs:
            report += f"| {config['tenant_id']} | {config['config_type']} | {config['isolation_level']} | {config['security_score']:.1f} | {config['compliance_status']} | {Path(config['file_path']).name} |\n"
        
        return report

def main():
    """Função principal para execução da auditoria."""
    project_root = os.getcwd()
    auditor = MultitenancyAuditor(project_root)
    
    print("🏢 Iniciando auditoria de multitenancy...")
    result = auditor.run_audit()
    
    print(f"\n📊 Resultados da Auditoria:")
    print(f"   Total Tenants: {result.total_tenants}")
    print(f"   Strong Isolation: {result.strong_isolation}")
    print(f"   Weak Isolation: {result.weak_isolation}")
    print(f"   Isolation Score: {result.isolation_score:.1f}%")
    
    print(f"\n🚨 Recomendações:")
    for rec in result.recommendations:
        print(f"   {rec}")
    
    # Gerar relatório
    report = auditor.generate_report()
    report_path = Path(project_root) / "docs" / f"multitenancy_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\n📄 Relatório salvo em: {report_path}")
    print(f"📊 Resultados JSON: {auditor.results_path}")

if __name__ == "__main__":
    main() 