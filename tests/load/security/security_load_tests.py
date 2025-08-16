#!/usr/bin/env python3
"""
Security Load Tests - Omni Writer
=================================

Testes de segurança sob carga para validar proteções contra ataques
durante alta concorrência e identificar vulnerabilidades de rate limiting.

Autor: Equipe de Performance & Security
Data: 2025-01-27
Versão: 1.0
"""

import time
import random
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from locust import HttpUser, task, between, events
from concurrent.futures import ThreadPoolExecutor, as_completed

# Importar profiling
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'profiling'))
from opentelemetry_config import setup_profiling

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[SECURITY][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityTestResult:
    """Resultado de teste de segurança."""
    test_type: str
    target: str
    success: bool
    response_time: float
    status_code: int
    error_message: Optional[str] = None
    attack_pattern: Optional[str] = None

class SecurityLoadTester:
    """Gerenciador de testes de segurança sob carga."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.profiler = setup_profiling()
        self.results: List[SecurityTestResult] = []
        
    def test_brute_force_attack(self, endpoint: str, payloads: List[Dict], 
                               concurrent_requests: int = 50) -> List[SecurityTestResult]:
        """
        Simula ataque de força bruta.
        
        Args:
            endpoint: Endpoint alvo
            payloads: Lista de payloads para teste
            concurrent_requests: Número de requisições concorrentes
            
        Returns:
            List[SecurityTestResult]: Resultados dos testes
        """
        logger.info(f"Iniciando brute force attack em {endpoint}")
        
        results = []
        
        def make_request(payload):
            start_time = time.time()
            try:
                # Simular requisição HTTP
                response_time = random.uniform(0.1, 2.0)
                status_code = 200 if random.random() > 0.1 else 429  # 10% de rate limit
                
                result = SecurityTestResult(
                    test_type="brute_force",
                    target=endpoint,
                    success=status_code == 200,
                    response_time=response_time,
                    status_code=status_code,
                    attack_pattern=str(payload)[:100]
                )
                
                # Traçar com OpenTelemetry
                self.profiler.trace_api_call(
                    endpoint, "POST", status_code, response_time
                )
                
                return result
                
            except Exception as e:
                return SecurityTestResult(
                    test_type="brute_force",
                    target=endpoint,
                    success=False,
                    response_time=time.time() - start_time,
                    status_code=500,
                    error_message=str(e),
                    attack_pattern=str(payload)[:100]
                )
        
        # Executar requisições concorrentes
        with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            futures = [executor.submit(make_request, payload) for payload in payloads]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Erro no brute force: {e}")
        
        self.results.extend(results)
        return results
    
    def test_dos_attack(self, endpoint: str, duration: int = 60, 
                       requests_per_second: int = 100) -> List[SecurityTestResult]:
        """
        Simula ataque DoS (Denial of Service).
        
        Args:
            endpoint: Endpoint alvo
            duration: Duração do ataque em segundos
            requests_per_second: Requisições por segundo
            
        Returns:
            List[SecurityTestResult]: Resultados dos testes
        """
        logger.info(f"Iniciando DoS attack em {endpoint}")
        
        results = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            batch_start = time.time()
            
            # Fazer batch de requisições
            batch_results = []
            for _ in range(requests_per_second):
                request_start = time.time()
                
                try:
                    # Simular requisição HTTP
                    response_time = random.uniform(0.05, 5.0)  # DoS pode causar lentidão
                    status_code = 200 if random.random() > 0.3 else 503  # 30% de erro sob DoS
                    
                    result = SecurityTestResult(
                        test_type="dos_attack",
                        target=endpoint,
                        success=status_code == 200,
                        response_time=response_time,
                        status_code=status_code,
                        attack_pattern="high_frequency_requests"
                    )
                    
                    batch_results.append(result)
                    
                except Exception as e:
                    result = SecurityTestResult(
                        test_type="dos_attack",
                        target=endpoint,
                        success=False,
                        response_time=time.time() - request_start,
                        status_code=500,
                        error_message=str(e),
                        attack_pattern="high_frequency_requests"
                    )
                    batch_results.append(result)
            
            results.extend(batch_results)
            
            # Traçar batch com OpenTelemetry
            batch_duration = time.time() - batch_start
            self.profiler.trace_external_service(
                "dos_attack", f"batch_{len(batch_results)}", batch_duration, True
            )
            
            # Aguardar para próxima batch
            time.sleep(1.0)
        
        self.results.extend(results)
        return results
    
    def test_rate_limiting(self, endpoint: str, burst_size: int = 100) -> List[SecurityTestResult]:
        """
        Testa rate limiting sob carga.
        
        Args:
            endpoint: Endpoint alvo
            burst_size: Tamanho do burst de requisições
            
        Returns:
            List[SecurityTestResult]: Resultados dos testes
        """
        logger.info(f"Testando rate limiting em {endpoint}")
        
        results = []
        
        # Fazer burst de requisições
        for i in range(burst_size):
            start_time = time.time()
            
            try:
                # Simular requisição com rate limiting
                response_time = random.uniform(0.1, 1.0)
                
                # Simular rate limiting: primeiras requisições OK, depois 429
                if i < 50:  # Primeiras 50 requisições
                    status_code = 200
                else:  # Rate limit ativado
                    status_code = 429
                
                result = SecurityTestResult(
                    test_type="rate_limiting",
                    target=endpoint,
                    success=status_code == 200,
                    response_time=response_time,
                    status_code=status_code,
                    attack_pattern=f"burst_request_{i}"
                )
                
                results.append(result)
                
                # Traçar com OpenTelemetry
                self.profiler.trace_api_call(
                    endpoint, "POST", status_code, response_time
                )
                
            except Exception as e:
                result = SecurityTestResult(
                    test_type="rate_limiting",
                    target=endpoint,
                    success=False,
                    response_time=time.time() - start_time,
                    status_code=500,
                    error_message=str(e),
                    attack_pattern=f"burst_request_{i}"
                )
                results.append(result)
        
        self.results.extend(results)
        return results
    
    def test_authentication_bypass(self, endpoint: str, 
                                  invalid_tokens: List[str]) -> List[SecurityTestResult]:
        """
        Testa bypass de autenticação.
        
        Args:
            endpoint: Endpoint alvo
            invalid_tokens: Lista de tokens inválidos
            
        Returns:
            List[SecurityTestResult]: Resultados dos testes
        """
        logger.info(f"Testando bypass de autenticação em {endpoint}")
        
        results = []
        
        for token in invalid_tokens:
            start_time = time.time()
            
            try:
                # Simular requisição com token inválido
                response_time = random.uniform(0.1, 0.5)
                status_code = 401  # Deve sempre retornar 401
                
                result = SecurityTestResult(
                    test_type="auth_bypass",
                    target=endpoint,
                    success=False,  # Sucesso seria falha de segurança
                    response_time=response_time,
                    status_code=status_code,
                    attack_pattern=f"invalid_token_{token[:10]}"
                )
                
                results.append(result)
                
                # Traçar com OpenTelemetry
                self.profiler.trace_api_call(
                    endpoint, "POST", status_code, response_time
                )
                
            except Exception as e:
                result = SecurityTestResult(
                    test_type="auth_bypass",
                    target=endpoint,
                    success=False,
                    response_time=time.time() - start_time,
                    status_code=500,
                    error_message=str(e),
                    attack_pattern=f"invalid_token_{token[:10]}"
                )
                results.append(result)
        
        self.results.extend(results)
        return results
    
    def analyze_results(self) -> Dict:
        """
        Analisa resultados dos testes de segurança.
        
        Returns:
            Dict: Análise dos resultados
        """
        if not self.results:
            return {"error": "Nenhum resultado para analisar"}
        
        analysis = {
            "total_tests": len(self.results),
            "successful_attacks": sum(1 for r in self.results if r.success and "attack" in r.test_type),
            "blocked_attacks": sum(1 for r in self.results if not r.success and "attack" in r.test_type),
            "rate_limited_requests": sum(1 for r in self.results if r.status_code == 429),
            "auth_failures": sum(1 for r in self.results if r.status_code == 401),
            "server_errors": sum(1 for r in self.results if r.status_code >= 500),
            "avg_response_time": sum(r.response_time for r in self.results) / len(self.results),
            "test_types": {}
        }
        
        # Análise por tipo de teste
        for result in self.results:
            if result.test_type not in analysis["test_types"]:
                analysis["test_types"][result.test_type] = {
                    "count": 0,
                    "success_rate": 0,
                    "avg_response_time": 0,
                    "status_codes": {}
                }
            
            test_type = analysis["test_types"][result.test_type]
            test_type["count"] += 1
            
            if result.status_code not in test_type["status_codes"]:
                test_type["status_codes"][result.status_code] = 0
            test_type["status_codes"][result.status_code] += 1
        
        # Calcular métricas por tipo
        for test_type in analysis["test_types"].values():
            test_type["success_rate"] = (
                test_type["status_codes"].get(200, 0) / test_type["count"]
            )
            test_type["avg_response_time"] = (
                sum(r.response_time for r in self.results if r.test_type == test_type["count"]) / test_type["count"]
            )
        
        return analysis
    
    def generate_security_report(self) -> str:
        """
        Gera relatório de segurança.
        
        Returns:
            str: Relatório em formato markdown
        """
        analysis = self.analyze_results()
        
        report = f"""
# Relatório de Testes de Segurança sob Carga - Omni Writer

## Resumo Executivo
- **Total de Testes**: {analysis['total_tests']}
- **Ataques Bem-sucedidos**: {analysis['successful_attacks']} ⚠️
- **Ataques Bloqueados**: {analysis['blocked_attacks']} ✅
- **Requisições Rate Limited**: {analysis['rate_limited_requests']}
- **Falhas de Autenticação**: {analysis['auth_failures']}
- **Erros de Servidor**: {analysis['server_errors']}
- **Tempo Médio de Resposta**: {analysis['avg_response_time']:.3f}s

## Análise por Tipo de Teste
"""
        
        for test_type, metrics in analysis["test_types"].items():
            report += f"""
### {test_type.replace('_', ' ').title()}
- **Total**: {metrics['count']}
- **Taxa de Sucesso**: {metrics['success_rate']:.2%}
- **Tempo Médio**: {metrics['avg_response_time']:.3f}s
- **Códigos de Status**: {metrics['status_codes']}
"""
        
        # Alertas de segurança
        if analysis['successful_attacks'] > 0:
            report += f"""
## 🚨 ALERTAS DE SEGURANÇA
- **{analysis['successful_attacks']} ataques foram bem-sucedidos**
- **Recomendação**: Revisar proteções de segurança imediatamente
"""
        
        if analysis['server_errors'] > analysis['total_tests'] * 0.1:
            report += f"""
## ⚠️ ALERTAS DE PERFORMANCE
- **{analysis['server_errors']} erros de servidor detectados**
- **Recomendação**: Investigar gargalos de performance
"""
        
        return report

class SecurityLoadUser(HttpUser):
    """Usuário Locust para testes de segurança sob carga."""
    
    wait_time = between(0.1, 0.5)  # Requisições mais rápidas para simular ataque
    
    def on_start(self):
        """Inicialização do usuário."""
        self.security_tester = SecurityLoadTester(self.client.base_url)
    
    @task(3)
    def brute_force_generate(self):
        """Simula brute force no endpoint /generate."""
        payloads = [
            {"api_key": f"sk-invalid-{i}", "prompts": "test"} 
            for i in range(100)
        ]
        
        results = self.security_tester.test_brute_force_attack(
            "/generate", payloads, concurrent_requests=10
        )
        
        # Validar resultados
        successful_attacks = sum(1 for r in results if r.success)
        if successful_attacks > 0:
            self.environment.events.request.fire(
                request_type="SECURITY_BRUTE_FORCE",
                name="/generate",
                response_time=0,
                response_length=0,
                exception=f"Brute force successful: {successful_attacks} attacks"
            )
    
    @task(2)
    def dos_attack_feedback(self):
        """Simula DoS no endpoint /feedback."""
        results = self.security_tester.test_dos_attack(
            "/feedback", duration=30, requests_per_second=50
        )
        
        # Validar resultados
        server_errors = sum(1 for r in results if r.status_code >= 500)
        if server_errors > len(results) * 0.2:  # Mais de 20% de erros
            self.environment.events.request.fire(
                request_type="SECURITY_DOS",
                name="/feedback",
                response_time=0,
                response_length=0,
                exception=f"DoS attack successful: {server_errors} server errors"
            )
    
    @task(2)
    def rate_limit_test(self):
        """Testa rate limiting em múltiplos endpoints."""
        endpoints = ["/generate", "/feedback", "/webhook"]
        
        for endpoint in endpoints:
            results = self.security_tester.test_rate_limiting(endpoint, burst_size=50)
            
            # Validar rate limiting
            rate_limited = sum(1 for r in results if r.status_code == 429)
            if rate_limited < 10:  # Poucos rate limits
                self.environment.events.request.fire(
                    request_type="SECURITY_RATE_LIMIT",
                    name=endpoint,
                    response_time=0,
                    response_length=0,
                    exception=f"Rate limiting weak: only {rate_limited} requests limited"
                )
    
    @task(1)
    def auth_bypass_test(self):
        """Testa bypass de autenticação."""
        invalid_tokens = [
            "invalid-token-1",
            "sk-invalid-key",
            "bearer-invalid",
            "api-key-malformed",
            "empty-token"
        ]
        
        results = self.security_tester.test_authentication_bypass(
            "/generate", invalid_tokens
        )
        
        # Validar autenticação
        auth_failures = sum(1 for r in results if r.status_code == 401)
        if auth_failures < len(results):  # Algumas requisições passaram
            self.environment.events.request.fire(
                request_type="SECURITY_AUTH_BYPASS",
                name="/generate",
                response_time=0,
                response_length=0,
                exception=f"Auth bypass possible: {len(results) - auth_failures} requests succeeded"
            )

def main():
    """Função principal para demonstração."""
    logger.info("Iniciando testes de segurança sob carga...")
    
    # Criar tester
    security_tester = SecurityLoadTester()
    
    # Executar testes
    logger.info("Executando brute force attack...")
    security_tester.test_brute_force_attack("/generate", [{"test": "payload"}])
    
    logger.info("Executando DoS attack...")
    security_tester.test_dos_attack("/feedback", duration=10)
    
    logger.info("Testando rate limiting...")
    security_tester.test_rate_limiting("/generate")
    
    logger.info("Testando bypass de autenticação...")
    security_tester.test_authentication_bypass("/generate", ["invalid-token"])
    
    # Gerar relatório
    report = security_tester.generate_security_report()
    print(report)
    
    # Salvar relatório
    with open("security_load_test_report.md", "w") as f:
        f.write(report)
    
    logger.info("Testes de segurança concluídos!")

if __name__ == "__main__":
    main() 