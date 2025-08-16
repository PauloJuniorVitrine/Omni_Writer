"""
Multi-DC Simulation - Omni Writer
=================================

Sistema de simulação de múltiplos data centers para testes de carga.
Simula latências geográficas e valida consistência entre regiões.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 15
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:15:00Z
"""

import os
import json
import time
import random
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from geopy.distance import geodesic
import requests

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('multidc_simulation')

@dataclass
class DataCenter:
    """Representa um data center."""
    dc_id: str
    name: str
    region: str
    location: Tuple[float, float]  # (lat, lon)
    base_url: str
    latency_ms: int
    capacity: int  # requests/second
    health_status: str = "healthy"
    last_check: datetime = None

@dataclass
class GeoLatency:
    """Configuração de latência geográfica."""
    from_region: str
    to_region: str
    latency_ms: int
    jitter_ms: int = 0
    packet_loss: float = 0.0

@dataclass
class ConsistencyResult:
    """Resultado de teste de consistência."""
    test_id: str
    timestamp: datetime
    dc_pair: Tuple[str, str]
    data_consistent: bool
    latency_diff_ms: float
    response_diff_ms: float
    error_count: int = 0

class MultiDCSimulator:
    """
    Simulador de múltiplos data centers para testes de carga.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/multidc/config.json"):
        """
        Inicializa o simulador multi-DC.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/multidc/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Data centers configurados
        self.data_centers: Dict[str, DataCenter] = {}
        self.geo_latencies: List[GeoLatency] = []
        
        # Configurações
        self.simulation_config = {
            "enable_geo_latency": True,
            "enable_packet_loss": True,
            "enable_jitter": True,
            "consistency_check_interval": 30,  # segundos
            "max_concurrent_requests": 50,
            "timeout_seconds": 30,
            "retry_attempts": 3
        }
        
        # Resultados de simulação
        self.simulation_results: List[Dict[str, Any]] = []
        self.consistency_results: List[ConsistencyResult] = []
        
        # Estado da simulação
        self.is_running = False
        self.simulation_thread = None
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Data centers configurados: {len(self.data_centers)}")

    def load_config(self) -> None:
        """
        Carrega configuração de data centers e latências.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Carrega data centers
                for dc_data in config.get('data_centers', []):
                    dc = DataCenter(**dc_data)
                    self.data_centers[dc.dc_id] = dc
                
                # Carrega latências geográficas
                for latency_data in config.get('geo_latencies', []):
                    latency = GeoLatency(**latency_data)
                    self.geo_latencies.append(latency)
                
                # Carrega configurações
                self.simulation_config.update(config.get('simulation_config', {}))
                
                logger.info("Configuração carregada do arquivo")
            else:
                self._create_default_config()
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            self._create_default_config()

    def _create_default_config(self) -> None:
        """
        Cria configuração padrão com data centers globais.
        """
        # Data centers padrão baseados em regiões reais
        default_dcs = [
            DataCenter(
                dc_id="us-east-1",
                name="US East (N. Virginia)",
                region="us-east-1",
                location=(38.9072, -77.0369),
                base_url="http://localhost:5000",  # Simulado
                latency_ms=50,
                capacity=1000
            ),
            DataCenter(
                dc_id="us-west-2",
                name="US West (Oregon)",
                region="us-west-2",
                location=(45.5152, -122.6784),
                base_url="http://localhost:5001",  # Simulado
                latency_ms=80,
                capacity=800
            ),
            DataCenter(
                dc_id="eu-west-1",
                name="Europe (Ireland)",
                region="eu-west-1",
                location=(53.3498, -6.2603),
                base_url="http://localhost:5002",  # Simulado
                latency_ms=120,
                capacity=600
            ),
            DataCenter(
                dc_id="ap-southeast-1",
                name="Asia Pacific (Singapore)",
                region="ap-southeast-1",
                location=(1.3521, 103.8198),
                base_url="http://localhost:5003",  # Simulado
                latency_ms=200,
                capacity=400
            ),
            DataCenter(
                dc_id="sa-east-1",
                name="South America (São Paulo)",
                region="sa-east-1",
                location=(-23.5505, -46.6333),
                base_url="http://localhost:5004",  # Simulado
                latency_ms=150,
                capacity=300
            )
        ]
        
        for dc in default_dcs:
            self.data_centers[dc.dc_id] = dc
        
        # Latências geográficas calculadas
        self._calculate_geo_latencies()

    def _calculate_geo_latencies(self) -> None:
        """
        Calcula latências geográficas baseadas em distâncias reais.
        """
        dc_list = list(self.data_centers.values())
        
        for i, dc1 in enumerate(dc_list):
            for j, dc2 in enumerate(dc_list):
                if i != j:
                    # Calcula distância real
                    distance_km = geodesic(dc1.location, dc2.location).kilometers
                    
                    # Estima latência baseada na distância (aproximadamente 1ms por 200km)
                    base_latency = int(distance_km / 200)
                    
                    # Adiciona jitter e variação
                    jitter = random.randint(5, 20)
                    packet_loss = min(distance_km / 10000, 0.05)  # Máximo 5%
                    
                    latency = GeoLatency(
                        from_region=dc1.region,
                        to_region=dc2.region,
                        latency_ms=base_latency,
                        jitter_ms=jitter,
                        packet_loss=packet_loss
                    )
                    
                    self.geo_latencies.append(latency)

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'data_centers': [asdict(dc) for dc in self.data_centers.values()],
                'geo_latencies': [asdict(lat) for lat in self.geo_latencies],
                'simulation_config': self.simulation_config,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def get_latency_between_regions(self, from_region: str, to_region: str) -> int:
        """
        Obtém latência entre duas regiões.
        """
        for latency in self.geo_latencies:
            if latency.from_region == from_region and latency.to_region == to_region:
                base_latency = latency.latency_ms
                
                # Adiciona jitter se habilitado
                if self.simulation_config["enable_jitter"]:
                    jitter = random.randint(-latency.jitter_ms, latency.jitter_ms)
                    base_latency += jitter
                
                return max(base_latency, 1)  # Mínimo 1ms
        
        # Latência padrão se não encontrada
        return 100

    def simulate_packet_loss(self, from_region: str, to_region: str) -> bool:
        """
        Simula perda de pacotes entre regiões.
        """
        if not self.simulation_config["enable_packet_loss"]:
            return False
        
        for latency in self.geo_latencies:
            if latency.from_region == from_region and latency.to_region == to_region:
                return random.random() < latency.packet_loss
        
        return False

    async def send_request_to_dc(self, 
                                dc: DataCenter, 
                                endpoint: str, 
                                payload: Dict[str, Any],
                                source_region: str = None) -> Dict[str, Any]:
        """
        Envia requisição para um data center específico.
        """
        try:
            # Simula latência geográfica se especificada
            if source_region and self.simulation_config["enable_geo_latency"]:
                latency = self.get_latency_between_regions(source_region, dc.region)
                await asyncio.sleep(latency / 1000)  # Converte para segundos
            
            # Simula perda de pacotes
            if self.simulate_packet_loss(source_region or "unknown", dc.region):
                raise Exception("Packet loss simulated")
            
            # Envia requisição real
            url = f"{dc.base_url}{endpoint}"
            headers = {
                "Content-Type": "application/json",
                "X-Source-Region": source_region or "unknown",
                "X-Target-DC": dc.dc_id
            }
            
            start_time = time.time()
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.simulation_config["timeout_seconds"])) as session:
                async with session.post(url, json=payload, headers=headers) as response:
                    end_time = time.time()
                    
                    response_data = await response.json()
                    
                    result = {
                        "dc_id": dc.dc_id,
                        "region": dc.region,
                        "status_code": response.status,
                        "response_time": (end_time - start_time) * 1000,
                        "response_data": response_data,
                        "success": response.status == 200
                    }
                    
                    return result
                    
        except Exception as e:
            logger.error(f"Erro ao enviar requisição para {dc.dc_id}: {e}")
            return {
                "dc_id": dc.dc_id,
                "region": dc.region,
                "status_code": 0,
                "response_time": 0,
                "response_data": None,
                "success": False,
                "error": str(e)
            }

    async def run_multi_dc_test(self, 
                               endpoint: str, 
                               payload: Dict[str, Any],
                               source_region: str = None) -> List[Dict[str, Any]]:
        """
        Executa teste em múltiplos data centers simultaneamente.
        """
        logger.info(f"Executando teste multi-DC para {endpoint}")
        
        # Seleciona data centers ativos
        active_dcs = [dc for dc in self.data_centers.values() if dc.health_status == "healthy"]
        
        if not active_dcs:
            logger.error("Nenhum data center ativo encontrado")
            return []
        
        # Executa requisições em paralelo
        tasks = []
        for dc in active_dcs:
            task = self.send_request_to_dc(dc, endpoint, payload, source_region)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa resultados
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Erro no teste multi-DC: {result}")
            else:
                processed_results.append(result)
        
        # Registra resultados
        self.simulation_results.append({
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "source_region": source_region,
            "results": processed_results
        })
        
        logger.info(f"Teste multi-DC concluído - {len(processed_results)} resultados")
        return processed_results

    async def test_data_consistency(self, 
                                   endpoint: str, 
                                   payload: Dict[str, Any]) -> List[ConsistencyResult]:
        """
        Testa consistência de dados entre data centers.
        """
        logger.info("Testando consistência de dados entre DCs...")
        
        # Executa teste em todos os DCs
        results = await self.run_multi_dc_test(endpoint, payload)
        
        if len(results) < 2:
            logger.warning("Pelo menos 2 DCs necessários para teste de consistência")
            return []
        
        consistency_results = []
        
        # Compara resultados entre pares de DCs
        for i, result1 in enumerate(results):
            for j, result2 in enumerate(results[i+1:], i+1):
                if not result1["success"] or not result2["success"]:
                    continue
                
                # Compara dados de resposta
                data1 = result1["response_data"]
                data2 = result2["response_data"]
                
                # Verifica consistência
                data_consistent = self._compare_response_data(data1, data2)
                
                # Calcula diferenças
                latency_diff = abs(result1["response_time"] - result2["response_time"])
                
                consistency_result = ConsistencyResult(
                    test_id=f"consistency_{int(time.time())}",
                    timestamp=datetime.now(),
                    dc_pair=(result1["dc_id"], result2["dc_id"]),
                    data_consistent=data_consistent,
                    latency_diff_ms=latency_diff,
                    response_diff_ms=latency_diff
                )
                
                consistency_results.append(consistency_result)
                
                if not data_consistent:
                    logger.warning(f"Inconsistência detectada entre {result1['dc_id']} e {result2['dc_id']}")
        
        # Adiciona ao histórico
        self.consistency_results.extend(consistency_results)
        
        logger.info(f"Teste de consistência concluído - {len(consistency_results)} comparações")
        return consistency_results

    def _compare_response_data(self, data1: Any, data2: Any) -> bool:
        """
        Compara dados de resposta para verificar consistência.
        """
        try:
            # Comparação simples para estruturas básicas
            if isinstance(data1, dict) and isinstance(data2, dict):
                # Compara chaves críticas
                critical_keys = ["status", "success", "data", "result"]
                
                for key in critical_keys:
                    if key in data1 and key in data2:
                        if data1[key] != data2[key]:
                            return False
                
                return True
            else:
                return data1 == data2
                
        except Exception as e:
            logger.error(f"Erro ao comparar dados: {e}")
            return False

    def check_dc_health(self, dc: DataCenter) -> bool:
        """
        Verifica saúde de um data center.
        """
        try:
            health_url = f"{dc.base_url}/health"
            
            response = requests.get(health_url, timeout=5)
            
            if response.status_code == 200:
                dc.health_status = "healthy"
                dc.last_check = datetime.now()
                return True
            else:
                dc.health_status = "unhealthy"
                dc.last_check = datetime.now()
                return False
                
        except Exception as e:
            logger.error(f"Erro ao verificar saúde de {dc.dc_id}: {e}")
            dc.health_status = "unreachable"
            dc.last_check = datetime.now()
            return False

    def check_all_dc_health(self) -> Dict[str, bool]:
        """
        Verifica saúde de todos os data centers.
        """
        logger.info("Verificando saúde de todos os DCs...")
        
        health_results = {}
        
        with ThreadPoolExecutor(max_workers=len(self.data_centers)) as executor:
            future_to_dc = {
                executor.submit(self.check_dc_health, dc): dc.dc_id 
                for dc in self.data_centers.values()
            }
            
            for future in as_completed(future_to_dc):
                dc_id = future_to_dc[future]
                try:
                    health_results[dc_id] = future.result()
                except Exception as e:
                    logger.error(f"Erro ao verificar {dc_id}: {e}")
                    health_results[dc_id] = False
        
        healthy_count = sum(health_results.values())
        logger.info(f"DCs saudáveis: {healthy_count}/{len(self.data_centers)}")
        
        return health_results

    def generate_geo_report(self) -> str:
        """
        Gera relatório de simulação geográfica.
        """
        try:
            report_file = self.output_dir / f"geo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Simulação Multi-DC - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de DCs:** {len(self.data_centers)}\n")
                f.write(f"- **DCs ativos:** {len([dc for dc in self.data_centers.values() if dc.health_status == 'healthy'])}\n")
                f.write(f"- **Testes executados:** {len(self.simulation_results)}\n")
                f.write(f"- **Testes de consistência:** {len(self.consistency_results)}\n\n")
                
                f.write("## Data Centers\n\n")
                
                for dc in self.data_centers.values():
                    f.write(f"### {dc.name}\n")
                    f.write(f"- **ID:** {dc.dc_id}\n")
                    f.write(f"- **Região:** {dc.region}\n")
                    f.write(f"- **Localização:** {dc.location}\n")
                    f.write(f"- **Latência base:** {dc.latency_ms}ms\n")
                    f.write(f"- **Capacidade:** {dc.capacity} req/s\n")
                    f.write(f"- **Status:** {dc.health_status}\n")
                    f.write(f"- **Última verificação:** {dc.last_check}\n\n")
                
                f.write("## Latências Geográficas\n\n")
                
                f.write("| De | Para | Latência (ms) | Jitter (ms) | Packet Loss (%) |\n")
                f.write("|----|------|---------------|-------------|-----------------|\n")
                
                for latency in self.geo_latencies[:10]:  # Mostra apenas as primeiras 10
                    f.write(f"| {latency.from_region} | {latency.to_region} | {latency.latency_ms} | {latency.jitter_ms} | {latency.packet_loss*100:.2f} |\n")
                
                if len(self.geo_latencies) > 10:
                    f.write(f"| ... | ... | ... | ... | ... |\n")
                    f.write(f"| Total de combinações: {len(self.geo_latencies)} |\n\n")
                
                f.write("## Resultados de Consistência\n\n")
                
                if self.consistency_results:
                    consistent_count = sum(1 for r in self.consistency_results if r.data_consistent)
                    f.write(f"- **Total de comparações:** {len(self.consistency_results)}\n")
                    f.write(f"- **Consistentes:** {consistent_count}\n")
                    f.write(f"- **Inconsistentes:** {len(self.consistency_results) - consistent_count}\n")
                    f.write(f"- **Taxa de consistência:** {consistent_count/len(self.consistency_results)*100:.1f}%\n\n")
                    
                    if self.consistency_results:
                        f.write("### Últimas Inconsistências\n\n")
                        recent_inconsistencies = [
                            r for r in self.consistency_results[-5:] 
                            if not r.data_consistent
                        ]
                        
                        for result in recent_inconsistencies:
                            f.write(f"- **{result.dc_pair[0]} ↔ {result.dc_pair[1]}** - {result.timestamp}\n")
                            f.write(f"  - Diferença de latência: {result.latency_diff_ms:.2f}ms\n")
                            f.write(f"  - Erros: {result.error_count}\n\n")
                else:
                    f.write("Nenhum teste de consistência executado.\n\n")
                
                f.write("## Configurações\n\n")
                f.write(f"- **Latência geográfica:** {self.simulation_config['enable_geo_latency']}\n")
                f.write(f"- **Perda de pacotes:** {self.simulation_config['enable_packet_loss']}\n")
                f.write(f"- **Jitter:** {self.simulation_config['enable_jitter']}\n")
                f.write(f"- **Timeout:** {self.simulation_config['timeout_seconds']}s\n")
                f.write(f"- **Máximo de requisições concorrentes:** {self.simulation_config['max_concurrent_requests']}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""

    async def run_complete_simulation(self, 
                                    endpoints: List[str] = None,
                                    duration_minutes: int = 5) -> Dict[str, Any]:
        """
        Executa simulação completa multi-DC.
        """
        logger.info(f"Iniciando simulação completa - {duration_minutes} minutos")
        
        if not endpoints:
            endpoints = ["/generate", "/download", "/status"]
        
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        simulation_summary = {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "endpoints_tested": endpoints,
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "consistency_tests": 0,
            "inconsistencies_found": 0
        }
        
        try:
            while datetime.now() < end_time:
                # Verifica saúde dos DCs
                health_results = self.check_all_dc_health()
                
                # Executa testes para cada endpoint
                for endpoint in endpoints:
                    payload = self._generate_test_payload(endpoint)
                    
                    # Teste normal
                    results = await self.run_multi_dc_test(endpoint, payload)
                    
                    simulation_summary["total_requests"] += len(results)
                    simulation_summary["successful_requests"] += sum(1 for r in results if r["success"])
                    simulation_summary["failed_requests"] += sum(1 for r in results if not r["success"])
                    
                    # Teste de consistência
                    consistency_results = await self.test_data_consistency(endpoint, payload)
                    
                    simulation_summary["consistency_tests"] += len(consistency_results)
                    simulation_summary["inconsistencies_found"] += sum(1 for r in consistency_results if not r.data_consistent)
                
                # Aguarda antes da próxima iteração
                await asyncio.sleep(self.simulation_config["consistency_check_interval"])
                
        except Exception as e:
            logger.error(f"Erro durante simulação: {e}")
        
        simulation_summary["actual_end_time"] = datetime.now().isoformat()
        
        logger.info("Simulação completa finalizada")
        return simulation_summary

    def _generate_test_payload(self, endpoint: str) -> Dict[str, Any]:
        """
        Gera payload de teste baseado no endpoint.
        """
        if endpoint == "/generate":
            return {
                "api_key": "sk-multidc-test",
                "model_type": "openai",
                "prompts": [{"text": "Teste multi-DC", "index": 0}]
            }
        elif endpoint == "/download":
            return {"file": "test_file.zip"}
        elif endpoint == "/status":
            return {"trace_id": f"trace-multidc-{int(time.time())}"}
        else:
            return {"test": "multidc_simulation"}


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Multi-DC Simulator...")
    
    simulator = MultiDCSimulator()
    
    try:
        # Verifica saúde dos DCs
        health_results = simulator.check_all_dc_health()
        
        # Executa simulação completa
        simulation_summary = await simulator.run_complete_simulation(duration_minutes=2)
        
        # Gera relatório
        report_file = simulator.generate_geo_report()
        
        logger.info("Simulação multi-DC concluída com sucesso!")
        logger.info(f"Total de requisições: {simulation_summary['total_requests']}")
        logger.info(f"Sucessos: {simulation_summary['successful_requests']}")
        logger.info(f"Falhas: {simulation_summary['failed_requests']}")
        logger.info(f"Inconsistências: {simulation_summary['inconsistencies_found']}")
        logger.info(f"Relatório: {report_file}")
        
    except Exception as e:
        logger.error(f"Erro na simulação: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 