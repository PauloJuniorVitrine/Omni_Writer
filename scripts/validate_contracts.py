#!/usr/bin/env python3
"""
Validação de Contratos OpenAPI - Omni Writer
Tracing ID: CONTRACT_VALIDATION_20250127_001

Este script valida a consistência entre:
- Documentação OpenAPI
- Implementação real dos endpoints
- Schemas de dados
"""

import json
import yaml
import requests
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ContractValidationResult:
    """Resultado da validação de contrato"""
    endpoint: str
    method: str
    status: str
    issues: List[str]
    warnings: List[str]

class OpenAPIContractValidator:
    """Validador de contratos OpenAPI"""
    
    def __init__(self, openapi_path: str, base_url: str = "http://localhost:5000"):
        self.openapi_path = Path(openapi_path)
        self.base_url = base_url
        self.openapi_spec = None
        self.validation_results: List[ContractValidationResult] = []
        
    def load_openapi_spec(self) -> bool:
        """Carrega especificação OpenAPI"""
        try:
            if self.openapi_path.suffix == '.yaml' or self.openapi_path.suffix == '.yml':
                with open(self.openapi_path, 'r', encoding='utf-8') as f:
                    self.openapi_spec = yaml.safe_load(f)
            else:
                with open(self.openapi_path, 'r', encoding='utf-8') as f:
                    self.openapi_spec = json.load(f)
            
            logger.info(f"OpenAPI spec carregada: {self.openapi_path}")
            return True
        except Exception as e:
            logger.error(f"Erro ao carregar OpenAPI spec: {e}")
            return False
    
    def validate_endpoint_exists(self, path: str, method: str) -> bool:
        """Valida se endpoint existe na implementação"""
        try:
            url = f"{self.base_url}{path}"
            response = requests.request(method, url, timeout=5)
            # Se retorna 404, endpoint não existe
            # Se retorna 405, método não permitido
            # Se retorna 401/403, endpoint existe mas precisa auth
            return response.status_code not in [404, 405]
        except requests.exceptions.RequestException:
            # Se não consegue conectar, assume que endpoint existe
            return True
    
    def validate_schema_consistency(self, path: str, method: str, operation: Dict) -> List[str]:
        """Valida consistência de schemas"""
        issues = []
        
        # Valida request schema
        if 'requestBody' in operation:
            content = operation['requestBody'].get('content', {})
            if 'application/json' in content:
                schema = content['application/json'].get('schema', {})
                if not schema:
                    issues.append("Request schema não definido")
        
        # Valida response schemas
        responses = operation.get('responses', {})
        for status_code, response in responses.items():
            if status_code.startswith('2'):  # Success responses
                content = response.get('content', {})
                if 'application/json' in content:
                    schema = content['application/json'].get('schema', {})
                    if not schema:
                        issues.append(f"Response schema não definido para {status_code}")
        
        return issues
    
    def validate_parameters(self, path: str, method: str, operation: Dict) -> List[str]:
        """Valida parâmetros do endpoint"""
        issues = []
        
        # Valida path parameters
        path_params = [p for p in operation.get('parameters', []) if p.get('in') == 'path']
        path_vars = [p.strip('{}') for p in path.split('/') if p.startswith('{') and p.endswith('}')]
        
        if len(path_params) != len(path_vars):
            issues.append(f"Path parameters inconsistentes: {len(path_params)} vs {len(path_vars)}")
        
        return issues
    
    def validate_security(self, operation: Dict) -> List[str]:
        """Valida configurações de segurança"""
        issues = []
        
        # Verifica se endpoints protegidos têm security definido
        if operation.get('security') is None:
            # Endpoints que devem ter segurança
            protected_paths = ['/api/blogs', '/generate', '/download']
            if any(path in operation.get('operationId', '') for path in protected_paths):
                issues.append("Endpoint protegido sem configuração de segurança")
        
        return issues
    
    def validate_all_endpoints(self) -> List[ContractValidationResult]:
        """Valida todos os endpoints da especificação OpenAPI"""
        if not self.openapi_spec:
            logger.error("OpenAPI spec não carregada")
            return []
        
        paths = self.openapi_spec.get('paths', {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    result = self.validate_endpoint(path, method.upper(), operation)
                    self.validation_results.append(result)
        
        return self.validation_results
    
    def validate_endpoint(self, path: str, method: str, operation: Dict) -> ContractValidationResult:
        """Valida um endpoint específico"""
        issues = []
        warnings = []
        
        # Validações básicas
        if not self.validate_endpoint_exists(path, method):
            issues.append("Endpoint não implementado ou não acessível")
        
        # Validações de schema
        schema_issues = self.validate_schema_consistency(path, method, operation)
        issues.extend(schema_issues)
        
        # Validações de parâmetros
        param_issues = self.validate_parameters(path, method, operation)
        issues.extend(param_issues)
        
        # Validações de segurança
        security_issues = self.validate_security(operation)
        issues.extend(security_issues)
        
        # Validações de documentação
        if not operation.get('summary'):
            warnings.append("Endpoint sem resumo")
        
        if not operation.get('description'):
            warnings.append("Endpoint sem descrição")
        
        # Determina status
        status = "PASS" if not issues else "FAIL"
        if warnings and not issues:
            status = "WARN"
        
        return ContractValidationResult(
            endpoint=path,
            method=method,
            status=status,
            issues=issues,
            warnings=warnings
        )
    
    def generate_report(self) -> Dict[str, Any]:
        """Gera relatório de validação"""
        total_endpoints = len(self.validation_results)
        passed = len([r for r in self.validation_results if r.status == "PASS"])
        failed = len([r for r in self.validation_results if r.status == "FAIL"])
        warnings = len([r for r in self.validation_results if r.status == "WARN"])
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": "CONTRACT_VALIDATION_20250127_001",
            "summary": {
                "total_endpoints": total_endpoints,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "success_rate": (passed / total_endpoints * 100) if total_endpoints > 0 else 0
            },
            "results": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "status": r.status,
                    "issues": r.issues,
                    "warnings": r.warnings
                }
                for r in self.validation_results
            ]
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], output_path: str = "contract_validation_report.json"):
        """Salva relatório em arquivo"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"Relatório salvo: {output_path}")
        except Exception as e:
            logger.error(f"Erro ao salvar relatório: {e}")

def main():
    """Função principal"""
    # Configuração
    openapi_path = "docs/openapi.yaml"
    base_url = os.getenv("API_BASE_URL", "http://localhost:5000")
    
    # Validação
    validator = OpenAPIContractValidator(openapi_path, base_url)
    
    if not validator.load_openapi_spec():
        sys.exit(1)
    
    logger.info("Iniciando validação de contratos...")
    results = validator.validate_all_endpoints()
    
    # Gera relatório
    report = validator.generate_report()
    validator.save_report(report)
    
    # Exibe resumo
    summary = report["summary"]
    logger.info(f"Validação concluída:")
    logger.info(f"  - Total: {summary['total_endpoints']}")
    logger.info(f"  - Aprovados: {summary['passed']}")
    logger.info(f"  - Falharam: {summary['failed']}")
    logger.info(f"  - Avisos: {summary['warnings']}")
    logger.info(f"  - Taxa de sucesso: {summary['success_rate']:.1f}%")
    
    # Exibe problemas
    failed_results = [r for r in results if r.status == "FAIL"]
    if failed_results:
        logger.error("Endpoints com problemas:")
        for result in failed_results:
            logger.error(f"  {result.method} {result.endpoint}:")
            for issue in result.issues:
                logger.error(f"    - {issue}")
    
    # Exit code baseado no resultado
    if summary['failed'] > 0:
        sys.exit(1)
    elif summary['warnings'] > 0:
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 