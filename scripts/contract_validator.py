#!/usr/bin/env python3
"""
Script de validação automática de contratos entre backend e frontend.

Tracing ID: COMM_IMPL_20250128_001
Data/Hora: 2025-01-28T11:20:00Z
Prompt: Fullstack Communication Audit
Ruleset: Enterprise+ Standards
"""

import os
import sys
import json
import yaml
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ContractValidationResult:
    """Resultado da validação de contrato."""
    endpoint: str
    method: str
    is_implemented: bool
    is_documented: bool
    has_tests: bool
    performance_ok: bool
    security_ok: bool
    errors: List[str]
    warnings: List[str]

class ContractValidator:
    """
    Validador de contratos entre backend e frontend.
    
    Responsável por:
    - Validar sincronização entre documentação e implementação
    - Verificar cobertura de testes
    - Validar performance e segurança
    - Gerar relatórios de conformidade
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.openapi_spec = self.project_root / "docs" / "openapi.yaml"
        self.routes_file = self.project_root / "app" / "routes.py"
        self.tests_dir = self.project_root / "tests"
        self.ui_dir = self.project_root / "ui"
        
    def validate_all_contracts(self) -> Dict[str, ContractValidationResult]:
        """
        Valida todos os contratos do sistema.
        
        Returns:
            Dict[str, ContractValidationResult]: Resultados da validação
        """
        logger.info("🔍 Iniciando validação completa de contratos")
        
        # Carrega especificação OpenAPI
        spec = self._load_openapi_spec()
        if not spec:
            return {}
        
        # Obtém endpoints implementados
        implemented_endpoints = self._get_implemented_endpoints()
        
        # Obtém endpoints testados
        tested_endpoints = self._get_tested_endpoints()
        
        # Valida cada endpoint
        results = {}
        
        for path, methods in spec['paths'].items():
            for method, operation in methods.items():
                endpoint_key = f"{method.upper()} {path}"
                
                result = self._validate_single_contract(
                    endpoint_key, path, method, operation,
                    implemented_endpoints, tested_endpoints
                )
                
                results[endpoint_key] = result
        
        logger.info(f"✅ Validação concluída: {len(results)} endpoints analisados")
        return results
    
    def _load_openapi_spec(self) -> Dict:
        """Carrega especificação OpenAPI."""
        try:
            with open(self.openapi_spec, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"❌ Erro ao carregar especificação OpenAPI: {e}")
            return {}
    
    def _get_implemented_endpoints(self) -> Set[str]:
        """Obtém conjunto de endpoints implementados."""
        implemented = set()
        
        try:
            if not self.routes_file.exists():
                logger.warning("⚠️ Arquivo routes.py não encontrado")
                return implemented
            
            with open(self.routes_file, 'r') as f:
                content = f.read()
            
            # Extrai rotas usando regex
            import re
            route_pattern = r'@routes_bp\.route\([\'"]([^\'"]+)[\'"],\s*methods=\[[^\]]*[\'"]([^\'"]+)[\'"]'
            matches = re.findall(route_pattern, content)
            
            for path, method in matches:
                implemented.add(f"{method.upper()} {path}")
            
            logger.info(f"📋 {len(implemented)} endpoints implementados encontrados")
            return implemented
            
        except Exception as e:
            logger.error(f"❌ Erro ao analisar endpoints implementados: {e}")
            return set()
    
    def _get_tested_endpoints(self) -> Set[str]:
        """Obtém conjunto de endpoints testados."""
        tested = set()
        
        try:
            # Procura por testes de integração
            integration_tests = self.tests_dir / "integration"
            if integration_tests.exists():
                for test_file in integration_tests.glob("*.py"):
                    with open(test_file, 'r') as f:
                        content = f.read()
                    
                    # Extrai endpoints testados
                    import re
                    test_patterns = [
                        r'client\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]',
                        r'requests\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]',
                        r'response\s*=\s*.*\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]'
                    ]
                    
                    for pattern in test_patterns:
                        matches = re.findall(pattern, content)
                        for method, path in matches:
                            tested.add(f"{method.upper()} {path}")
            
            logger.info(f"🧪 {len(tested)} endpoints testados encontrados")
            return tested
            
        except Exception as e:
            logger.error(f"❌ Erro ao analisar endpoints testados: {e}")
            return set()
    
    def _validate_single_contract(
        self, endpoint_key: str, path: str, method: str, 
        operation: Dict, implemented_endpoints: Set[str], 
        tested_endpoints: Set[str]
    ) -> ContractValidationResult:
        """Valida contrato de um endpoint específico."""
        errors = []
        warnings = []
        
        # Verifica implementação
        is_implemented = endpoint_key in implemented_endpoints
        if not is_implemented:
            errors.append("Endpoint documentado mas não implementado")
        
        # Verifica testes
        is_tested = endpoint_key in tested_endpoints
        if not is_tested:
            warnings.append("Endpoint não possui testes de integração")
        
        # Verifica documentação
        is_documented = bool(operation.get('summary') or operation.get('description'))
        if not is_documented:
            warnings.append("Endpoint não possui documentação adequada")
        
        # Verifica performance (simulação)
        performance_ok = self._check_performance_requirements(operation)
        if not performance_ok:
            warnings.append("Endpoint pode ter problemas de performance")
        
        # Verifica segurança
        security_ok = self._check_security_requirements(operation)
        if not security_ok:
            errors.append("Endpoint não atende requisitos de segurança")
        
        return ContractValidationResult(
            endpoint=path,
            method=method,
            is_implemented=is_implemented,
            is_documented=is_documented,
            has_tests=is_tested,
            performance_ok=performance_ok,
            security_ok=security_ok,
            errors=errors,
            warnings=warnings
        )
    
    def _check_performance_requirements(self, operation: Dict) -> bool:
        """Verifica requisitos de performance."""
        # Simulação de verificação de performance
        # Em um cenário real, isso seria baseado em métricas reais
        
        # Verifica se tem rate limiting
        has_rate_limiting = 'x-rate-limit' in str(operation)
        
        # Verifica se tem cache headers
        has_cache = 'cache-control' in str(operation)
        
        # Verifica se é endpoint crítico
        is_critical = any(keyword in str(operation).lower() 
                         for keyword in ['generate', 'process', 'upload'])
        
        if is_critical and not has_rate_limiting:
            return False
        
        return True
    
    def _check_security_requirements(self, operation: Dict) -> bool:
        """Verifica requisitos de segurança."""
        # Verifica se tem autenticação
        has_auth = 'security' in operation or 'BearerAuth' in str(operation)
        
        # Verifica se é endpoint sensível
        is_sensitive = any(keyword in str(operation).lower() 
                          for keyword in ['admin', 'user', 'token', 'password'])
        
        if is_sensitive and not has_auth:
            return False
        
        return True
    
    def generate_report(self, results: Dict[str, ContractValidationResult]) -> str:
        """Gera relatório de validação."""
        total_endpoints = len(results)
        implemented = sum(1 for r in results.values() if r.is_implemented)
        tested = sum(1 for r in results.values() if r.has_tests)
        documented = sum(1 for r in results.values() if r.is_documented)
        secure = sum(1 for r in results.values() if r.security_ok)
        performant = sum(1 for r in results.values() if r.performance_ok)
        
        errors = sum(len(r.errors) for r in results.values())
        warnings = sum(len(r.warnings) for r in results.values())
        
        report = f"""
# 📋 RELATÓRIO DE VALIDAÇÃO DE CONTRATOS

**Tracing ID**: COMM_IMPL_20250128_001  
**Data/Hora**: {datetime.now().isoformat()}  
**Status**: {'✅ CONFORME' if errors == 0 else '❌ NÃO CONFORME'}

## 📊 MÉTRICAS GERAIS

- **Total de Endpoints**: {total_endpoints}
- **Implementados**: {implemented} ({implemented/total_endpoints*100:.1f}%)
- **Testados**: {tested} ({tested/total_endpoints*100:.1f}%)
- **Documentados**: {documented} ({documented/total_endpoints*100:.1f}%)
- **Seguros**: {secure} ({secure/total_endpoints*100:.1f}%)
- **Performáticos**: {performant} ({performant/total_endpoints*100:.1f}%)

## ⚠️ PROBLEMAS ENCONTRADOS

- **Erros**: {errors}
- **Avisos**: {warnings}

## 📋 DETALHAMENTO POR ENDPOINT

"""
        
        for endpoint_key, result in results.items():
            status = "✅" if not result.errors else "❌"
            report += f"\n### {status} {endpoint_key}\n"
            
            if result.errors:
                report += "**Erros:**\n"
                for error in result.errors:
                    report += f"- ❌ {error}\n"
            
            if result.warnings:
                report += "**Avisos:**\n"
                for warning in result.warnings:
                    report += f"- ⚠️ {warning}\n"
            
            report += f"- Implementado: {'✅' if result.is_implemented else '❌'}\n"
            report += f"- Testado: {'✅' if result.has_tests else '❌'}\n"
            report += f"- Documentado: {'✅' if result.is_documented else '❌'}\n"
            report += f"- Seguro: {'✅' if result.security_ok else '❌'}\n"
            report += f"- Performático: {'✅' if result.performance_ok else '❌'}\n"
        
        return report
    
    def save_report(self, report: str, filename: Optional[str] = None):
        """Salva relatório em arquivo."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"contract_validation_report_{timestamp}.md"
        
        report_path = self.project_root / "docs" / "reports" / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"📄 Relatório salvo em: {report_path}")
        return report_path

def main():
    """Função principal do script."""
    validator = ContractValidator()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "validate":
            results = validator.validate_all_contracts()
            report = validator.generate_report(results)
            print(report)
            
            # Salva relatório
            validator.save_report(report)
            
            # Retorna código de saída baseado em erros
            total_errors = sum(len(r.errors) for r in results.values())
            sys.exit(0 if total_errors == 0 else 1)
        
        elif command == "report":
            results = validator.validate_all_contracts()
            report = validator.generate_report(results)
            validator.save_report(report)
            print("📄 Relatório gerado com sucesso")
            sys.exit(0)
        
        else:
            print("Comandos disponíveis: validate, report")
            sys.exit(1)
    else:
        # Executa validação por padrão
        results = validator.validate_all_contracts()
        report = validator.generate_report(results)
        print(report)
        
        # Salva relatório
        validator.save_report(report)
        
        # Retorna código de saída
        total_errors = sum(len(r.errors) for r in results.values())
        sys.exit(0 if total_errors == 0 else 1)

if __name__ == "__main__":
    main() 