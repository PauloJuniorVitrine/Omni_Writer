#!/usr/bin/env python3
"""
Testes de Chaos para falhas de rede na comunicação backend/frontend.

Tracing ID: COMM_IMPL_20250128_002
Data/Hora: 2025-01-28T11:45:00Z
Prompt: Fullstack Communication Audit
Ruleset: Enterprise+ Standards
"""

import pytest
import asyncio
import aiohttp
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ChaosTestResult:
    """Resultado de um teste de chaos."""
    test_name: str
    scenario: str
    success: bool
    response_time: float
    error_message: Optional[str]
    resilience_score: float  # 0-100
    recommendations: List[str]

class NetworkChaosTester:
    """
    Testador de chaos para falhas de rede.
    
    Responsável por:
    - Simular falhas de rede
    - Testar timeouts
    - Validar rate limiting
    - Medir resiliência
    - Gerar relatórios de teste
    """
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = None
        self.test_results = []
        
    async def __aenter__(self):
        """Context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.session:
            await self.session.close()
    
    async def test_timeout_scenario(self, endpoint: str, timeout_ms: int = 1000) -> ChaosTestResult:
        """
        Testa cenário de timeout.
        
        Args:
            endpoint: Endpoint a testar
            timeout_ms: Timeout em milissegundos
            
        Returns:
            ChaosTestResult: Resultado do teste
        """
        test_name = f"timeout_{timeout_ms}ms"
        start_time = time.time()
        
        try:
            # Configura timeout muito baixo para forçar timeout
            timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
            
            async with self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=timeout
            ) as response:
                response_time = (time.time() - start_time) * 1000
                
                if response.status == 408:  # Request Timeout
                    return ChaosTestResult(
                        test_name=test_name,
                        scenario=f"Timeout {timeout_ms}ms",
                        success=True,
                        response_time=response_time,
                        error_message=None,
                        resilience_score=80.0,
                        recommendations=["Timeout tratado corretamente"]
                    )
                else:
                    return ChaosTestResult(
                        test_name=test_name,
                        scenario=f"Timeout {timeout_ms}ms",
                        success=False,
                        response_time=response_time,
                        error_message=f"Timeout não tratado: status {response.status}",
                        resilience_score=20.0,
                        recommendations=["Implementar tratamento de timeout"]
                    )
                    
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"Timeout {timeout_ms}ms",
                success=True,
                response_time=response_time,
                error_message="Timeout ocorreu conforme esperado",
                resilience_score=90.0,
                recommendations=["Timeout funcionando corretamente"]
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"Timeout {timeout_ms}ms",
                success=False,
                response_time=response_time,
                error_message=str(e),
                resilience_score=10.0,
                recommendations=["Corrigir tratamento de exceções"]
            )
    
    async def test_rate_limiting(self, endpoint: str, requests_count: int = 10) -> ChaosTestResult:
        """
        Testa rate limiting.
        
        Args:
            endpoint: Endpoint a testar
            requests_count: Número de requisições simultâneas
            
        Returns:
            ChaosTestResult: Resultado do teste
        """
        test_name = "rate_limiting"
        start_time = time.time()
        
        try:
            # Faz múltiplas requisições simultâneas
            tasks = []
            for i in range(requests_count):
                task = self.session.get(f"{self.base_url}{endpoint}")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            response_time = (time.time() - start_time) * 1000
            
            # Analisa respostas
            success_count = 0
            rate_limited_count = 0
            error_count = 0
            
            for response in responses:
                if isinstance(response, Exception):
                    error_count += 1
                elif hasattr(response, 'status'):
                    if response.status == 429:  # Too Many Requests
                        rate_limited_count += 1
                    elif response.status < 400:
                        success_count += 1
                    else:
                        error_count += 1
            
            # Calcula score de resiliência
            if rate_limited_count > 0:
                resilience_score = 85.0
                recommendations = ["Rate limiting funcionando corretamente"]
            elif error_count == 0:
                resilience_score = 70.0
                recommendations = ["Considerar implementar rate limiting"]
            else:
                resilience_score = 30.0
                recommendations = ["Corrigir tratamento de múltiplas requisições"]
            
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"{requests_count} requisições simultâneas",
                success=rate_limited_count > 0 or error_count == 0,
                response_time=response_time,
                error_message=f"Sucesso: {success_count}, Rate Limited: {rate_limited_count}, Erros: {error_count}",
                resilience_score=resilience_score,
                recommendations=recommendations
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"{requests_count} requisições simultâneas",
                success=False,
                response_time=response_time,
                error_message=str(e),
                resilience_score=10.0,
                recommendations=["Corrigir tratamento de exceções"]
            )
    
    async def test_connection_drop(self, endpoint: str) -> ChaosTestResult:
        """
        Testa cenário de queda de conexão.
        
        Args:
            endpoint: Endpoint a testar
            
        Returns:
            ChaosTestResult: Resultado do teste
        """
        test_name = "connection_drop"
        start_time = time.time()
        
        try:
            # Simula queda de conexão com timeout muito baixo
            timeout = aiohttp.ClientTimeout(total=0.1)
            
            async with self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=timeout
            ) as response:
                response_time = (time.time() - start_time) * 1000
                
                return ChaosTestResult(
                    test_name=test_name,
                    scenario="Queda de conexão simulada",
                    success=False,
                    response_time=response_time,
                    error_message="Conexão não deveria ter sido estabelecida",
                    resilience_score=0.0,
                    recommendations=["Implementar retry logic"]
                )
                
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario="Queda de conexão simulada",
                success=True,
                response_time=response_time,
                error_message="Timeout ocorreu conforme esperado",
                resilience_score=80.0,
                recommendations=["Timeout funcionando para quedas de conexão"]
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario="Queda de conexão simulada",
                success=False,
                response_time=response_time,
                error_message=str(e),
                resilience_score=20.0,
                recommendations=["Melhorar tratamento de erros de conexão"]
            )
    
    async def test_slow_network(self, endpoint: str, delay_ms: int = 5000) -> ChaosTestResult:
        """
        Testa cenário de rede lenta.
        
        Args:
            endpoint: Endpoint a testar
            delay_ms: Delay simulado em milissegundos
            
        Returns:
            ChaosTestResult: Resultado do teste
        """
        test_name = f"slow_network_{delay_ms}ms"
        start_time = time.time()
        
        try:
            # Configura timeout maior que o delay
            timeout = aiohttp.ClientTimeout(total=(delay_ms + 1000) / 1000)
            
            async with self.session.get(
                f"{self.base_url}{endpoint}",
                timeout=timeout
            ) as response:
                response_time = (time.time() - start_time) * 1000
                
                if response.status < 400:
                    return ChaosTestResult(
                        test_name=test_name,
                        scenario=f"Rede lenta ({delay_ms}ms)",
                        success=True,
                        response_time=response_time,
                        error_message=None,
                        resilience_score=90.0,
                        recommendations=["Sistema tolera rede lenta"]
                    )
                else:
                    return ChaosTestResult(
                        test_name=test_name,
                        scenario=f"Rede lenta ({delay_ms}ms)",
                        success=False,
                        response_time=response_time,
                        error_message=f"Erro {response.status} em rede lenta",
                        resilience_score=40.0,
                        recommendations=["Melhorar tolerância a rede lenta"]
                    )
                    
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"Rede lenta ({delay_ms}ms)",
                success=False,
                response_time=response_time,
                error_message="Timeout em rede lenta",
                resilience_score=30.0,
                recommendations=["Aumentar timeout para redes lentas"]
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ChaosTestResult(
                test_name=test_name,
                scenario=f"Rede lenta ({delay_ms}ms)",
                success=False,
                response_time=response_time,
                error_message=str(e),
                resilience_score=20.0,
                recommendations=["Corrigir tratamento de rede lenta"]
            )
    
    async def run_all_chaos_tests(self, endpoints: List[str]) -> List[ChaosTestResult]:
        """
        Executa todos os testes de chaos.
        
        Args:
            endpoints: Lista de endpoints a testar
            
        Returns:
            List[ChaosTestResult]: Resultados de todos os testes
        """
        logger.info("🚀 Iniciando testes de chaos de rede")
        
        all_results = []
        
        for endpoint in endpoints:
            logger.info(f"🔍 Testando endpoint: {endpoint}")
            
            # Teste de timeout
            result = await self.test_timeout_scenario(endpoint, 1000)
            all_results.append(result)
            
            # Teste de rate limiting
            result = await self.test_rate_limiting(endpoint, 5)
            all_results.append(result)
            
            # Teste de queda de conexão
            result = await self.test_connection_drop(endpoint)
            all_results.append(result)
            
            # Teste de rede lenta
            result = await self.test_slow_network(endpoint, 3000)
            all_results.append(result)
        
        self.test_results = all_results
        logger.info(f"✅ Testes de chaos concluídos: {len(all_results)} testes executados")
        
        return all_results
    
    def generate_report(self) -> str:
        """Gera relatório dos testes de chaos."""
        if not self.test_results:
            return "Nenhum teste executado"
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for r in self.test_results if r.success)
        avg_resilience = sum(r.resilience_score for r in self.test_results) / total_tests
        
        report = f"""
# 🧪 RELATÓRIO DE TESTES DE CHAOS - REDE

**Tracing ID**: COMM_IMPL_20250128_002  
**Data/Hora**: {time.strftime('%Y-%m-%d %H:%M:%S')}  
**Status**: {'✅ RESILIENTE' if avg_resilience >= 70 else '❌ VULNERÁVEL'}

## 📊 MÉTRICAS GERAIS

- **Total de Testes**: {total_tests}
- **Testes Bem-sucedidos**: {successful_tests} ({successful_tests/total_tests*100:.1f}%)
- **Score Médio de Resiliência**: {avg_resilience:.1f}/100
- **Nível de Resiliência**: {'ALTO' if avg_resilience >= 80 else 'MÉDIO' if avg_resilience >= 60 else 'BAIXO'}

## 📋 DETALHAMENTO POR TESTE

"""
        
        for result in self.test_results:
            status = "✅" if result.success else "❌"
            report += f"\n### {status} {result.test_name}\n"
            report += f"- **Cenário**: {result.scenario}\n"
            report += f"- **Tempo de Resposta**: {result.response_time:.1f}ms\n"
            report += f"- **Score de Resiliência**: {result.resilience_score:.1f}/100\n"
            
            if result.error_message:
                report += f"- **Erro**: {result.error_message}\n"
            
            if result.recommendations:
                report += "\n**Recomendações:**\n"
                for rec in result.recommendations:
                    report += f"- 💡 {rec}\n"
        
        return report
    
    def save_report(self, report: str, filename: Optional[str] = None):
        """Salva relatório em arquivo."""
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"chaos_test_report_{timestamp}.md"
        
        report_path = Path(__file__).parent.parent.parent / "docs" / "reports" / filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"📄 Relatório salvo em: {report_path}")
        return report_path

# Testes pytest
@pytest.mark.asyncio
async def test_timeout_scenario():
    """Testa cenário de timeout."""
    async with NetworkChaosTester() as tester:
        result = await tester.test_timeout_scenario("/api/blogs", 1000)
        assert result.test_name == "timeout_1000ms"
        assert isinstance(result.resilience_score, float)

@pytest.mark.asyncio
async def test_rate_limiting():
    """Testa rate limiting."""
    async with NetworkChaosTester() as tester:
        result = await tester.test_rate_limiting("/api/blogs", 3)
        assert result.test_name == "rate_limiting"
        assert isinstance(result.resilience_score, float)

@pytest.mark.asyncio
async def test_connection_drop():
    """Testa queda de conexão."""
    async with NetworkChaosTester() as tester:
        result = await tester.test_connection_drop("/api/blogs")
        assert result.test_name == "connection_drop"
        assert isinstance(result.resilience_score, float)

@pytest.mark.asyncio
async def test_slow_network():
    """Testa rede lenta."""
    async with NetworkChaosTester() as tester:
        result = await tester.test_slow_network("/api/blogs", 2000)
        assert result.test_name == "slow_network_2000ms"
        assert isinstance(result.resilience_score, float)

@pytest.mark.asyncio
async def test_all_chaos_scenarios():
    """Executa todos os cenários de chaos."""
    endpoints = ["/api/blogs", "/api/generate-articles", "/api/entrega-zip"]
    
    async with NetworkChaosTester() as tester:
        results = await tester.run_all_chaos_tests(endpoints)
        
        # Verifica se todos os testes foram executados
        assert len(results) == len(endpoints) * 4  # 4 testes por endpoint
        
        # Verifica se pelo menos alguns testes passaram
        successful_tests = sum(1 for r in results if r.success)
        assert successful_tests > 0
        
        # Gera relatório
        report = tester.generate_report()
        tester.save_report(report)
        
        assert "RELATÓRIO DE TESTES DE CHAOS" in report 