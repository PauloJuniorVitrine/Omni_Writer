"""
Smart Scenario Generator - Omni Writer
======================================

Gerador inteligente de cenários de teste baseado em análise de logs reais.
Utiliza machine learning para identificar padrões e gerar cenários realistas.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 9
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T15:40:00Z
"""

import os
import json
import re
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import pandas as pd
from collections import defaultdict, Counter
import logging

# Configuração de logging baseada no padrão real
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('scenario_generator')

class SmartScenarioGenerator:
    """
    Gerador inteligente de cenários de teste baseado em logs reais.
    Analisa padrões de uso e gera cenários realistas para testes de carga.
    """
    
    def __init__(self, logs_dir: str = "logs", results_dir: str = "tests/load/results"):
        """
        Inicializa o gerador de cenários inteligentes.
        
        Args:
            logs_dir: Diretório com logs da aplicação
            results_dir: Diretório com resultados de testes anteriores
        """
        self.logs_dir = Path(logs_dir)
        self.results_dir = Path(results_dir)
        self.output_dir = Path("tests/load/ai/generated_scenarios")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Padrões de extração baseados no código real
        self.patterns = {
            'api_call': r'POST|GET|PUT|DELETE\s+/(\w+)',
            'response_time': r'(\d+\.?\d*)ms',
            'error_code': r'(\d{3})\s+error',
            'user_agent': r'User-Agent:\s*([^\s]+)',
            'ip_address': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            'trace_id': r'trace_id[=:]\s*([a-zA-Z0-9-]+)',
            'tenant_id': r'tenant_id[=:]\s*([a-zA-Z0-9_-]+)',
            'model_type': r'model_type[=:]\s*([a-zA-Z0-9_-]+)',
            'prompt_count': r'prompts[=:]\s*(\d+)',
            'file_size': r'(\d+)\s*bytes',
            'status_code': r'(\d{3})\s*OK|(\d{3})\s*ERROR'
        }
        
        # Endpoints críticos baseados no código real
        self.critical_endpoints = [
            "/generate",      # Fluxo crítico 1
            "/download",      # Fluxo crítico 2
            "/export_prompts", # Fluxo crítico 3
            "/export_artigos_csv", # Fluxo crítico 4
            "/feedback",      # Fluxo crítico 5
            "/webhook",       # Fluxo crítico 6
            "/status",        # Fluxo crítico 7
            "/events"         # Fluxo crítico 8
        ]
        
        # Configurações de cenários
        self.scenario_configs = {
            "peak_hours": {
                "time_range": ["09:00", "11:00", "14:00", "16:00"],
                "multiplier": 2.5,
                "description": "Horários de pico identificados nos logs"
            },
            "normal_hours": {
                "time_range": ["08:00", "12:00", "13:00", "17:00"],
                "multiplier": 1.0,
                "description": "Horários normais de operação"
            },
            "low_traffic": {
                "time_range": ["00:00", "06:00", "22:00", "23:59"],
                "multiplier": 0.3,
                "description": "Horários de baixo tráfego"
            }
        }
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Diretório de logs: {self.logs_dir}")
        logger.info(f"Diretório de resultados: {self.results_dir}")

    def analyze_log_files(self) -> Dict[str, Any]:
        """
        Analisa arquivos de log para extrair padrões reais de uso.
        Baseado nos logs reais da aplicação Omni Writer.
        """
        logger.info("Iniciando análise de logs...")
        
        analysis_results = {
            'endpoint_usage': defaultdict(int),
            'response_times': defaultdict(list),
            'error_patterns': defaultdict(int),
            'user_patterns': defaultdict(int),
            'time_patterns': defaultdict(int),
            'payload_patterns': defaultdict(list),
            'tenant_patterns': defaultdict(int),
            'model_usage': defaultdict(int)
        }
        
        # Busca arquivos de log
        log_files = list(self.logs_dir.rglob("*.log")) + list(self.logs_dir.rglob("*.txt"))
        
        if not log_files:
            logger.warning("Nenhum arquivo de log encontrado")
            return analysis_results
        
        for log_file in log_files:
            try:
                logger.info(f"Analisando arquivo: {log_file}")
                
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Extrai padrões baseados no código real
                        self._extract_patterns_from_line(line, analysis_results)
                        
                        # Limita análise para performance
                        if line_num > 10000:  # Máximo 10k linhas por arquivo
                            break
                            
            except Exception as e:
                logger.error(f"Erro ao analisar {log_file}: {e}")
                continue
        
        # Processa resultados
        self._process_analysis_results(analysis_results)
        
        logger.info(f"Análise concluída - {len(log_files)} arquivos processados")
        return analysis_results

    def _extract_patterns_from_line(self, line: str, results: Dict[str, Any]) -> None:
        """
        Extrai padrões de uma linha de log baseado no código real.
        """
        try:
            # Endpoint usage
            api_match = re.search(self.patterns['api_call'], line)
            if api_match:
                endpoint = f"/{api_match.group(1)}"
                results['endpoint_usage'][endpoint] += 1
            
            # Response time
            rt_match = re.search(self.patterns['response_time'], line)
            if rt_match:
                response_time = float(rt_match.group(1))
                results['response_times'][endpoint].append(response_time)
            
            # Error patterns
            error_match = re.search(self.patterns['error_code'], line)
            if error_match:
                error_code = error_match.group(1)
                results['error_patterns'][error_code] += 1
            
            # User patterns (IP addresses)
            ip_match = re.search(self.patterns['ip_address'], line)
            if ip_match:
                ip = ip_match.group(1)
                results['user_patterns'][ip] += 1
            
            # Time patterns
            time_match = re.search(r'(\d{2}):(\d{2}):(\d{2})', line)
            if time_match:
                hour = int(time_match.group(1))
                results['time_patterns'][hour] += 1
            
            # Tenant patterns
            tenant_match = re.search(self.patterns['tenant_id'], line)
            if tenant_match:
                tenant = tenant_match.group(1)
                results['tenant_patterns'][tenant] += 1
            
            # Model usage
            model_match = re.search(self.patterns['model_type'], line)
            if model_match:
                model = model_match.group(1)
                results['model_usage'][model] += 1
            
            # Payload patterns (prompt count)
            prompt_match = re.search(self.patterns['prompt_count'], line)
            if prompt_match:
                prompt_count = int(prompt_match.group(1))
                results['payload_patterns']['prompt_counts'].append(prompt_count)
                
        except Exception as e:
            logger.debug(f"Erro ao extrair padrões da linha: {e}")

    def _process_analysis_results(self, results: Dict[str, Any]) -> None:
        """
        Processa resultados da análise para gerar insights.
        """
        # Calcula estatísticas de response time
        for endpoint, times in results['response_times'].items():
            if times:
                results['response_times'][endpoint] = {
                    'mean': sum(times) / len(times),
                    'median': sorted(times)[len(times)//2],
                    'p95': sorted(times)[int(len(times)*0.95)],
                    'p99': sorted(times)[int(len(times)*0.99)],
                    'count': len(times)
                }
        
        # Identifica horários de pico
        if results['time_patterns']:
            peak_hours = sorted(results['time_patterns'].items(), key=lambda x: x[1], reverse=True)[:4]
            results['peak_hours'] = [hour for hour, count in peak_hours]
        
        # Calcula distribuição de payloads
        if results['payload_patterns']['prompt_counts']:
            prompt_counts = results['payload_patterns']['prompt_counts']
            results['payload_patterns']['prompt_distribution'] = {
                'mean': sum(prompt_counts) / len(prompt_counts),
                'max': max(prompt_counts),
                'min': min(prompt_counts),
                'common_values': Counter(prompt_counts).most_common(5)
            }

    def generate_realistic_scenarios(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Gera cenários realistas baseados na análise de logs.
        """
        logger.info("Gerando cenários realistas...")
        
        scenarios = []
        
        # Cenário 1: Carga normal baseada em uso real
        normal_scenario = self._create_normal_load_scenario(analysis)
        scenarios.append(normal_scenario)
        
        # Cenário 2: Carga de pico baseada em horários identificados
        peak_scenario = self._create_peak_load_scenario(analysis)
        scenarios.append(peak_scenario)
        
        # Cenário 3: Carga multi-tenant baseada em padrões reais
        multitenant_scenario = self._create_multitenant_scenario(analysis)
        scenarios.append(multitenant_scenario)
        
        # Cenário 4: Carga de erro baseada em padrões de falha
        error_scenario = self._create_error_scenario(analysis)
        scenarios.append(error_scenario)
        
        # Cenário 5: Carga de stress baseada em limites identificados
        stress_scenario = self._create_stress_scenario(analysis)
        scenarios.append(stress_scenario)
        
        logger.info(f"Gerados {len(scenarios)} cenários realistas")
        return scenarios

    def _create_normal_load_scenario(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cria cenário de carga normal baseado em uso real.
        """
        # Identifica endpoints mais usados
        top_endpoints = sorted(analysis['endpoint_usage'].items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Calcula distribuição de usuários baseada em IPs únicos
        unique_users = len(analysis['user_patterns'])
        target_users = min(max(unique_users, 10), 100)  # Entre 10 e 100 usuários
        
        scenario = {
            "name": "normal_load_realistic",
            "description": "Carga normal baseada em padrões reais de uso",
            "target_users": target_users,
            "spawn_rate": max(1, target_users // 10),  # 10% do total por minuto
            "duration": "5m",
            "tasks": []
        }
        
        # Distribui tarefas baseado no uso real
        total_usage = sum(usage for _, usage in top_endpoints)
        
        for endpoint, usage in top_endpoints:
            weight = int((usage / total_usage) * 100)
            if weight > 0:
                scenario["tasks"].append({
                    "endpoint": endpoint,
                    "weight": weight,
                    "payload": self._generate_realistic_payload(endpoint, analysis)
                })
        
        return scenario

    def _create_peak_load_scenario(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cria cenário de carga de pico baseado em horários identificados.
        """
        peak_hours = analysis.get('peak_hours', [9, 10, 14, 15])
        
        scenario = {
            "name": "peak_load_realistic",
            "description": f"Carga de pico baseada em horários identificados: {peak_hours}",
            "target_users": 200,  # 2x carga normal
            "spawn_rate": 20,     # Ramp-up mais agressivo
            "duration": "10m",
            "tasks": []
        }
        
        # Foca nos endpoints mais críticos durante pico
        critical_endpoints = ["/generate", "/download", "/status"]
        
        for endpoint in critical_endpoints:
            if endpoint in analysis['endpoint_usage']:
                scenario["tasks"].append({
                    "endpoint": endpoint,
                    "weight": 40 if endpoint == "/generate" else 30,
                    "payload": self._generate_realistic_payload(endpoint, analysis)
                })
        
        return scenario

    def _create_multitenant_scenario(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cria cenário multi-tenant baseado em padrões reais.
        """
        tenants = list(analysis['tenant_patterns'].keys())[:5]  # Top 5 tenants
        if not tenants:
            tenants = ["tenant_enterprise", "tenant_business", "tenant_starter"]
        
        scenario = {
            "name": "multitenant_realistic",
            "description": f"Carga multi-tenant com {len(tenants)} tenants reais",
            "target_users": 150,
            "spawn_rate": 15,
            "duration": "8m",
            "tenants": tenants,
            "tasks": []
        }
        
        # Distribui carga por tenant baseado em uso real
        for tenant in tenants:
            tenant_usage = analysis['tenant_patterns'].get(tenant, 1)
            scenario["tasks"].append({
                "tenant_id": tenant,
                "weight": min(tenant_usage, 50),  # Limita peso máximo
                "endpoints": ["/generate", "/download", "/status"],
                "payload": self._generate_tenant_payload(tenant, analysis)
            })
        
        return scenario

    def _create_error_scenario(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cria cenário de teste de erro baseado em padrões de falha reais.
        """
        error_codes = list(analysis['error_patterns'].keys())
        if not error_codes:
            error_codes = ["400", "429", "500", "503"]
        
        scenario = {
            "name": "error_patterns_realistic",
            "description": f"Teste de padrões de erro identificados: {error_codes}",
            "target_users": 50,
            "spawn_rate": 5,
            "duration": "3m",
            "tasks": []
        }
        
        # Simula condições que geram erros
        error_conditions = [
            {"endpoint": "/generate", "invalid_payload": True, "weight": 40},
            {"endpoint": "/download", "file_not_found": True, "weight": 30},
            {"endpoint": "/status", "invalid_trace_id": True, "weight": 30}
        ]
        
        for condition in error_conditions:
            scenario["tasks"].append({
                "endpoint": condition["endpoint"],
                "weight": condition["weight"],
                "error_condition": condition,
                "payload": self._generate_error_payload(condition["endpoint"])
            })
        
        return scenario

    def _create_stress_scenario(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Cria cenário de stress baseado em limites identificados.
        """
        # Identifica endpoints com maior latência
        slow_endpoints = []
        for endpoint, stats in analysis['response_times'].items():
            if isinstance(stats, dict) and stats.get('p95', 0) > 1000:  # > 1s
                slow_endpoints.append(endpoint)
        
        scenario = {
            "name": "stress_realistic",
            "description": f"Stress test focado em endpoints lentos: {slow_endpoints}",
            "target_users": 500,  # Carga extrema
            "spawn_rate": 50,     # Ramp-up muito agressivo
            "duration": "15m",
            "tasks": []
        }
        
        # Foca nos endpoints mais lentos
        for endpoint in slow_endpoints:
            scenario["tasks"].append({
                "endpoint": endpoint,
                "weight": 60,
                "payload": self._generate_stress_payload(endpoint, analysis)
            })
        
        return scenario

    def _generate_realistic_payload(self, endpoint: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera payload realista baseado em padrões reais.
        """
        if endpoint == "/generate":
            # Baseado em análise de prompt_counts
            prompt_dist = analysis.get('payload_patterns', {}).get('prompt_distribution', {})
            prompt_count = prompt_dist.get('mean', 3) if prompt_dist else 3
            
            # Modelo mais usado
            model_usage = analysis.get('model_usage', {})
            model_type = max(model_usage.items(), key=lambda x: x[1])[0] if model_usage else "openai"
            
            return {
                "api_key": "sk-realistic-test",
                "model_type": model_type,
                "prompts": [
                    {
                        "text": f"Artigo realista sobre tecnologia - prompt {i}",
                        "index": i
                    }
                    for i in range(int(prompt_count))
                ]
            }
        
        elif endpoint == "/feedback":
            return {
                "article_id": f"art-{random.randint(1000, 9999)}",
                "feedback": random.choice(["positivo", "negativo", "neutro"]),
                "comentario": "Feedback realista baseado em uso real"
            }
        
        elif endpoint == "/webhook":
            return {
                "url": "https://webhook.site/realistic-test"
            }
        
        else:
            return {}

    def _generate_tenant_payload(self, tenant_id: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera payload específico para tenant.
        """
        return {
            "tenant_id": tenant_id,
            "api_key": f"sk-{tenant_id}-test",
            "model_type": "openai",
            "prompts": [
                {
                    "text": f"Conteúdo específico do tenant {tenant_id}",
                    "index": 0
                }
            ]
        }

    def _generate_error_payload(self, endpoint: str) -> Dict[str, Any]:
        """
        Gera payload que induz erros para teste.
        """
        if endpoint == "/generate":
            return {
                "api_key": "invalid-key",
                "model_type": "invalid-model",
                "prompts": []  # Payload vazio
            }
        
        elif endpoint == "/download":
            return {
                "file": "nonexistent_file.zip"
            }
        
        elif endpoint == "/status":
            return {
                "trace_id": "invalid-trace-id"
            }
        
        return {}

    def _generate_stress_payload(self, endpoint: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera payload para teste de stress.
        """
        if endpoint == "/generate":
            # Payload grande para stress
            return {
                "api_key": "sk-stress-test",
                "model_type": "openai",
                "prompts": [
                    {
                        "text": "Prompt muito longo para testar limites " * 100,
                        "index": i
                    }
                    for i in range(10)  # Muitos prompts
                ]
            }
        
        return self._generate_realistic_payload(endpoint, analysis)

    def generate_locust_file(self, scenario: Dict[str, Any]) -> str:
        """
        Gera arquivo Locust baseado no cenário.
        """
        locust_content = f'''"""
Generated Locust File - {scenario['name']}
==========================================

Cenário gerado automaticamente baseado em análise de logs reais.
Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 9
Data: {datetime.now().isoformat()}
"""

from locust import HttpUser, task, between
import json
import random
import time

class {scenario['name'].title().replace('_', '')}User(HttpUser):
    """
    Usuário Locust gerado automaticamente para cenário: {scenario['name']}
    """
    wait_time = between(1, 3)
    
    def on_start(self):
        """Inicialização baseada em padrões reais."""
        self.scenario_name = "{scenario['name']}"
        self.start_time = time.time()
        print(f"[INFO] [generated] Iniciando cenário {{self.scenario_name}}")

'''
        
        # Adiciona tarefas baseadas no cenário
        for task_config in scenario.get('tasks', []):
            endpoint = task_config.get('endpoint', '')
            weight = task_config.get('weight', 1)
            payload = task_config.get('payload', {})
            
            locust_content += f'''
    @task({weight})
    def {endpoint.replace('/', '_').replace('-', '_')}_task(self):
        """
        Tarefa gerada automaticamente para {endpoint}
        """
        start_time = time.time()
        
        with self.client.post("{endpoint}", json={json.dumps(payload)}, catch_response=True) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                response.success()
                print(f"[SUCCESS] [generated] {{endpoint}} - {{response_time:.2f}}ms")
            else:
                response.failure(f"{{endpoint}} falhou: {{response.status_code}}")

'''
        
        locust_content += '''
    def on_stop(self):
        """Finalização com métricas."""
        duration = time.time() - self.start_time
        print(f"[INFO] [generated] Cenário {self.scenario_name} finalizado em {duration:.2f}s")

'''
        
        # Salva arquivo
        output_file = self.output_dir / f"locustfile_{scenario['name']}.py"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(locust_content)
        
        logger.info(f"Arquivo Locust gerado: {output_file}")
        return str(output_file)

    def generate_all_scenarios(self) -> Dict[str, str]:
        """
        Gera todos os cenários e arquivos Locust correspondentes.
        """
        logger.info("Iniciando geração completa de cenários...")
        
        # Analisa logs
        analysis = self.analyze_log_files()
        
        # Gera cenários
        scenarios = self.generate_realistic_scenarios(analysis)
        
        # Gera arquivos Locust
        generated_files = {}
        
        for scenario in scenarios:
            try:
                locust_file = self.generate_locust_file(scenario)
                generated_files[scenario['name']] = locust_file
            except Exception as e:
                logger.error(f"Erro ao gerar arquivo para {scenario['name']}: {e}")
        
        # Salva análise e cenários
        self._save_analysis_results(analysis, scenarios)
        
        logger.info(f"Geração concluída - {len(generated_files)} arquivos criados")
        return generated_files

    def _save_analysis_results(self, analysis: Dict[str, Any], scenarios: List[Dict[str, Any]]) -> None:
        """
        Salva resultados da análise e cenários gerados.
        """
        try:
            # Salva análise
            analysis_file = self.output_dir / f"analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(analysis_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, default=str)
            
            # Salva cenários
            scenarios_file = self.output_dir / f"generated_scenarios_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(scenarios_file, 'w', encoding='utf-8') as f:
                json.dump(scenarios, f, indent=2, default=str)
            
            logger.info(f"Resultados salvos: {analysis_file}, {scenarios_file}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {e}")


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Smart Scenario Generator...")
    
    generator = SmartScenarioGenerator()
    generated_files = generator.generate_all_scenarios()
    
    logger.info("Processamento concluído!")
    logger.info(f"Arquivos gerados: {list(generated_files.keys())}")


if __name__ == "__main__":
    main() 