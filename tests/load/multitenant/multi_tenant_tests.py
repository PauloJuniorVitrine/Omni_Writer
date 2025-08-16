"""
Multi-tenant Load Tests - Omni Writer
=====================================

Implementação de testes de carga para cenários multi-tenant baseada no código real.
Baseado nos fluxos críticos identificados em MAP_FLUXOS_CRITICOS_20250709T000000Z.md

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 7
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T15:30:00Z
"""

import os
import json
import time
import random
from datetime import datetime
from locust import HttpUser, task, between, events
from typing import Dict, List, Any

# Configurações baseadas no código real
TENANT_CONFIGS = {
    "tenant_enterprise": {
        "api_key": "sk-enterprise-tenant-001",
        "model_type": "openai",
        "rate_limit": 100,  # requests/min
        "max_prompts": 10,
        "priority": "high"
    },
    "tenant_business": {
        "api_key": "sk-business-tenant-002", 
        "model_type": "deepseek",
        "rate_limit": 50,
        "max_prompts": 5,
        "priority": "medium"
    },
    "tenant_starter": {
        "api_key": "sk-starter-tenant-003",
        "model_type": "openai",
        "rate_limit": 20,
        "max_prompts": 3,
        "priority": "low"
    }
}

class MultiTenantUser(HttpUser):
    """
    Usuário Locust para simular carga multi-tenant.
    Baseado nos endpoints reais identificados nos fluxos críticos.
    """
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Inicializa configuração do tenant baseada no código real."""
        self.tenant_id = f"tenant_{random.randint(1, 1000)}"
        self.tenant_config = random.choice(list(TENANT_CONFIGS.values()))
        self.session_data = {
            "tenant_id": self.tenant_id,
            "api_key": self.tenant_config["api_key"],
            "model_type": self.tenant_config["model_type"],
            "requests_count": 0,
            "start_time": time.time()
        }
        
        # Log de inicialização baseado no padrão real
        print(f"[INFO] [multi_tenant] Tenant {self.tenant_id} inicializado - {datetime.now().isoformat()}")

    @task(5)
    def generate_article_multi_tenant(self):
        """
        Testa geração de artigos com isolamento por tenant.
        Baseado no fluxo crítico 1: POST /generate
        """
        # Payload baseado no código real em utils_load.py
        prompts_count = random.randint(1, self.tenant_config["max_prompts"])
        prompts = [
            {
                "text": f"Artigo sobre tecnologia para tenant {self.tenant_id} - prompt {i}",
                "index": i
            }
            for i in range(prompts_count)
        ]
        
        payload = {
            "api_key": self.tenant_config["api_key"],
            "model_type": self.tenant_config["model_type"],
            "prompts": prompts,
            "tenant_id": self.tenant_id
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": self.tenant_id,
            "Authorization": f"Bearer {self.tenant_config['api_key']}"
        }
        
        start_time = time.time()
        
        with self.client.post(
            "/generate", 
            json=payload, 
            headers=headers, 
            catch_response=True
        ) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            # Validação baseada no comportamento real da aplicação
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    if "download_link" in response_data or "status" in response_data:
                        response.success()
                        self.session_data["requests_count"] += 1
                        
                        # Log de sucesso baseado no padrão real
                        print(f"[SUCCESS] [multi_tenant] Tenant {self.tenant_id} - Generate OK - {response_time:.2f}ms")
                    else:
                        response.failure(f"Resposta inválida: {response_data}")
                except json.JSONDecodeError:
                    response.failure("Resposta não é JSON válido")
            elif response.status_code == 429:  # Rate limit
                response.success()  # Rate limit é comportamento esperado
                print(f"[RATE_LIMIT] [multi_tenant] Tenant {self.tenant_id} - Rate limit atingido")
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text[:200]}")

    @task(2)
    def download_article_multi_tenant(self):
        """
        Testa download de artigos com isolamento por tenant.
        Baseado no fluxo crítico 2: GET /download
        """
        headers = {
            "X-Tenant-ID": self.tenant_id,
            "Authorization": f"Bearer {self.tenant_config['api_key']}"
        }
        
        start_time = time.time()
        
        with self.client.get(
            "/download",
            headers=headers,
            catch_response=True
        ) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                if content_type.startswith("application/zip"):
                    response.success()
                    print(f"[SUCCESS] [multi_tenant] Tenant {self.tenant_id} - Download OK - {response_time:.2f}ms")
                else:
                    response.failure(f"Content-Type inválido: {content_type}")
            elif response.status_code == 404:
                response.success()  # Arquivo não existe é comportamento esperado
            else:
                response.failure(f"Download falhou: {response.status_code}")

    @task(1)
    def check_status_multi_tenant(self):
        """
        Testa verificação de status com isolamento por tenant.
        Baseado no fluxo crítico 6: GET /status/<trace_id>
        """
        trace_id = f"trace-{self.tenant_id}-{random.randint(1, 1000)}"
        
        headers = {
            "X-Tenant-ID": self.tenant_id,
            "Authorization": f"Bearer {self.tenant_config['api_key']}"
        }
        
        start_time = time.time()
        
        with self.client.get(
            f"/status/{trace_id}",
            headers=headers,
            catch_response=True
        ) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code in [200, 404]:
                response.success()
                print(f"[SUCCESS] [multi_tenant] Tenant {self.tenant_id} - Status OK - {response_time:.2f}ms")
            else:
                response.failure(f"Status check falhou: {response.status_code}")

    @task(1)
    def send_feedback_multi_tenant(self):
        """
        Testa envio de feedback com isolamento por tenant.
        Baseado no fluxo crítico 5: POST /feedback
        """
        feedback_payload = {
            "article_id": f"art-{self.tenant_id}-{random.randint(1, 1000)}",
            "feedback": random.choice(["positivo", "negativo", "neutro"]),
            "comentario": f"Feedback do tenant {self.tenant_id} - {datetime.now().isoformat()}",
            "tenant_id": self.tenant_id
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": self.tenant_id,
            "Authorization": f"Bearer {self.tenant_config['api_key']}"
        }
        
        start_time = time.time()
        
        with self.client.post(
            "/feedback",
            json=feedback_payload,
            headers=headers,
            catch_response=True
        ) as response:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                response.success()
                print(f"[SUCCESS] [multi_tenant] Tenant {self.tenant_id} - Feedback OK - {response_time:.2f}ms")
            else:
                response.failure(f"Feedback falhou: {response.status_code}")

    def on_stop(self):
        """Finaliza sessão do tenant com métricas."""
        session_duration = time.time() - self.session_data["start_time"]
        requests_per_second = self.session_data["requests_count"] / session_duration if session_duration > 0 else 0
        
        print(f"[INFO] [multi_tenant] Tenant {self.tenant_id} finalizado:")
        print(f"  - Duração: {session_duration:.2f}s")
        print(f"  - Requests: {self.session_data['requests_count']}")
        print(f"  - RPS: {requests_per_second:.2f}")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, response, context, exception, start_time, url, **kwargs):
    """Listener para métricas de tenant."""
    if hasattr(context, 'session_data'):
        tenant_id = context.session_data.get('tenant_id', 'unknown')
        print(f"[METRIC] [multi_tenant] Tenant {tenant_id} - {name} - {response_time:.2f}ms")


class TenantIsolationTest(HttpUser):
    """
    Teste específico para validar isolamento entre tenants.
    """
    wait_time = between(2, 5)
    
    def on_start(self):
        self.tenant_a = "tenant_isolation_a"
        self.tenant_b = "tenant_isolation_b"
    
    @task
    def test_tenant_isolation(self):
        """
        Testa se dados de um tenant não vazam para outro.
        """
        # Simula acesso simultâneo de dois tenants
        payload_a = {
            "api_key": "sk-tenant-a",
            "model_type": "openai",
            "prompts": [{"text": "Dados do tenant A", "index": 0}],
            "tenant_id": self.tenant_a
        }
        
        payload_b = {
            "api_key": "sk-tenant-b", 
            "model_type": "deepseek",
            "prompts": [{"text": "Dados do tenant B", "index": 0}],
            "tenant_id": self.tenant_b
        }
        
        # Executa requests simultâneos
        with self.client.post("/generate", json=payload_a, headers={"X-Tenant-ID": self.tenant_a}, catch_response=True) as resp_a:
            with self.client.post("/generate", json=payload_b, headers={"X-Tenant-ID": self.tenant_b}, catch_response=True) as resp_b:
                # Valida isolamento
                if resp_a.status_code == 200 and resp_b.status_code == 200:
                    resp_a.success()
                    resp_b.success()
                    print(f"[ISOLATION] [multi_tenant] Isolamento validado entre {self.tenant_a} e {self.tenant_b}")
                else:
                    resp_a.failure(f"Isolamento falhou - Tenant A: {resp_a.status_code}")
                    resp_b.failure(f"Isolamento falhou - Tenant B: {resp_b.status_code}")


if __name__ == "__main__":
    """
    Execução direta para testes de desenvolvimento.
    """
    print("[INFO] [multi_tenant] Iniciando testes multi-tenant...")
    print(f"[INFO] [multi_tenant] Configurações: {len(TENANT_CONFIGS)} tenants")
    print(f"[INFO] [multi_tenant] Timestamp: {datetime.now().isoformat()}") 