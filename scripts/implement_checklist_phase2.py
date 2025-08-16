#!/usr/bin/env python3
"""
Script de Implementação - Fase 2: Microserviços
==============================================

Implementa a ativação completa dos microserviços conforme checklist.
Prompt: Implementação do checklist - Fase 2 Microserviços
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T13:00:00Z
"""

import os
import sys
import logging
import json
import time
import subprocess
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/exec_trace/checklist_phase2_implementation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("checklist_phase2")

# Tracing ID único para rastreabilidade
TRACING_ID = "CHECKLIST_PHASE2_20250127_001"

class ChecklistPhase2Implementation:
    """
    Implementação da Fase 2 do Checklist - Microserviços
    
    Objetivos:
    - Ativar microserviços
    - Configurar service discovery
    - Implementar comunicação entre serviços
    - Validar observabilidade
    """
    
    def __init__(self):
        """Inicializa a implementação da Fase 2."""
        self.tracing_id = TRACING_ID
        self.start_time = datetime.now()
        self.results = {
            "phase": "phase2_microservices",
            "tracing_id": self.tracing_id,
            "start_time": self.start_time.isoformat(),
            "steps": [],
            "status": "in_progress"
        }
        
        # Configurações baseadas em código real
        self.docker_compose_file = "docker-compose.microservices.yml"
        self.services = [
            "nginx", "article-service", "user-service", 
            "notification-service", "redis", "postgres",
            "prometheus", "grafana", "jaeger"
        ]
        
        logger.info(f"[{self.tracing_id}] Iniciando implementação da Fase 2 - Microserviços")
    
    def step_1_validate_environment(self) -> bool:
        """
        Passo 1: Validar ambiente e dependências.
        
        Validações:
        - Docker disponível
        - Docker Compose disponível
        - Arquivos de configuração existem
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 1: Validação do Ambiente")
        
        try:
            # Verificar se Docker está disponível
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"[{self.tracing_id}] ✅ Docker disponível: {result.stdout.strip()}")
            
            # Verificar se Docker Compose está disponível
            result = subprocess.run(['docker-compose', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"[{self.tracing_id}] ✅ Docker Compose disponível: {result.stdout.strip()}")
            
            # Verificar se arquivo docker-compose existe
            if os.path.exists(self.docker_compose_file):
                logger.info(f"[{self.tracing_id}] ✅ Docker Compose file encontrado: {self.docker_compose_file}")
            else:
                logger.error(f"[{self.tracing_id}] ❌ Docker Compose file não encontrado: {self.docker_compose_file}")
                return False
            
            # Verificar se serviços existem
            service_dirs = [
                "services/article_service",
                "services/user_service", 
                "services/notification_service"
            ]
            
            for service_dir in service_dirs:
                if os.path.exists(service_dir):
                    logger.info(f"[{self.tracing_id}] ✅ Serviço encontrado: {service_dir}")
                else:
                    logger.warning(f"[{self.tracing_id}] ⚠️ Serviço não encontrado: {service_dir}")
            
            # Verificar se service mesh adapter existe
            if os.path.exists("infraestructure/service_mesh_adapter.py"):
                logger.info(f"[{self.tracing_id}] ✅ Service Mesh Adapter encontrado")
            else:
                logger.warning(f"[{self.tracing_id}] ⚠️ Service Mesh Adapter não encontrado")
            
            self.results["steps"].append({
                "step": "validate_environment",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "details": "Ambiente validado com sucesso"
            })
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na validação: {e}")
            self.results["steps"].append({
                "step": "validate_environment",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_2_backup_volumes(self) -> bool:
        """
        Passo 2: Backup dos volumes Docker.
        
        Cria backup de segurança antes do deploy.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 2: Backup dos Volumes")
        
        try:
            backup_dir = Path("backups") / f"microservices_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Volumes a fazer backup
            volumes = [
                "omniwriter_postgres_data",
                "omniwriter_redis_data", 
                "omniwriter_prometheus_data",
                "omniwriter_grafana_data"
            ]
            
            for volume in volumes:
                try:
                    # Verificar se volume existe
                    result = subprocess.run(['docker', 'volume', 'inspect', volume], 
                                          capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        # Criar backup do volume
                        backup_file = backup_dir / f"{volume}.tar"
                        subprocess.run([
                            'docker', 'run', '--rm', '-v', f'{volume}:/data', 
                            '-v', f'{backup_file.parent}:/backup', 'alpine', 
                            'tar', 'czf', f'/backup/{backup_file.name}', '-C', '/data', '.'
                        ], check=True)
                        
                        logger.info(f"[{self.tracing_id}] ✅ Backup criado: {volume} -> {backup_file}")
                    else:
                        logger.info(f"[{self.tracing_id}] ℹ️ Volume não existe: {volume}")
                        
                except subprocess.CalledProcessError as e:
                    logger.warning(f"[{self.tracing_id}] ⚠️ Erro no backup do volume {volume}: {e}")
            
            # Criar arquivo de metadados do backup
            backup_metadata = {
                "tracing_id": self.tracing_id,
                "backup_time": datetime.now().isoformat(),
                "phase": "phase2_microservices",
                "volumes": volumes
            }
            
            with open(backup_dir / "backup_metadata.json", "w") as f:
                json.dump(backup_metadata, f, indent=2)
            
            self.results["steps"].append({
                "step": "backup_volumes",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "backup_dir": str(backup_dir)
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro no backup: {e}")
            self.results["steps"].append({
                "step": "backup_volumes",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_3_deploy_microservices(self) -> bool:
        """
        Passo 3: Deploy dos microserviços.
        
        Executa docker-compose para ativar todos os serviços.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 3: Deploy dos Microserviços")
        
        try:
            # Parar serviços existentes se houver
            logger.info(f"[{self.tracing_id}] Parando serviços existentes...")
            subprocess.run([
                'docker-compose', '-f', self.docker_compose_file, 'down'
            ], capture_output=True)
            
            # Fazer pull das imagens
            logger.info(f"[{self.tracing_id}] Fazendo pull das imagens...")
            subprocess.run([
                'docker-compose', '-f', self.docker_compose_file, 'pull'
            ], check=True)
            
            # Deploy dos serviços
            logger.info(f"[{self.tracing_id}] Iniciando deploy dos microserviços...")
            subprocess.run([
                'docker-compose', '-f', self.docker_compose_file, 'up', '-d'
            ], check=True)
            
            # Aguardar inicialização
            logger.info(f"[{self.tracing_id}] Aguardando inicialização dos serviços...")
            time.sleep(30)
            
            # Verificar status dos serviços
            result = subprocess.run([
                'docker-compose', '-f', self.docker_compose_file, 'ps'
            ], capture_output=True, text=True, check=True)
            
            logger.info(f"[{self.tracing_id}] Status dos serviços:\n{result.stdout}")
            
            self.results["steps"].append({
                "step": "deploy_microservices",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "services_deployed": len(self.services)
            })
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro no deploy: {e}")
            self.results["steps"].append({
                "step": "deploy_microservices",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_4_configure_service_discovery(self) -> bool:
        """
        Passo 4: Configurar service discovery.
        
        Configura Consul ou alternativa para service discovery.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 4: Configuração de Service Discovery")
        
        try:
            # Criar configuração de service discovery
            service_discovery_config = {
                "consul": {
                    "enabled": True,
                    "host": "localhost",
                    "port": 8500,
                    "datacenter": "omniwriter-dc"
                },
                "services": [
                    {
                        "name": "article-service",
                        "port": 5001,
                        "health_check": "/health",
                        "tags": ["api", "generation"]
                    },
                    {
                        "name": "user-service", 
                        "port": 5002,
                        "health_check": "/health",
                        "tags": ["api", "auth"]
                    },
                    {
                        "name": "notification-service",
                        "port": 5003,
                        "health_check": "/health", 
                        "tags": ["api", "notifications"]
                    }
                ]
            }
            
            # Salvar configuração
            config_file = "config/service_discovery.json"
            os.makedirs("config", exist_ok=True)
            
            with open(config_file, "w") as f:
                json.dump(service_discovery_config, f, indent=2)
            
            logger.info(f"[{self.tracing_id}] ✅ Configuração de service discovery criada: {config_file}")
            
            # Criar script de registro de serviços
            registration_script = "scripts/register_services.py"
            
            script_content = f'''#!/usr/bin/env python3
"""
Script de registro de serviços no service discovery.
Prompt: Registro de serviços no service discovery
Ruleset: enterprise_control_layer.yaml
Data/Hora: {datetime.now().isoformat()}
"""

import requests
import json
import time
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("service_registration")

def register_service(service_name: str, service_port: int, health_check: str):
    """Registra serviço no Consul."""
    try:
        # Dados do serviço
        service_data = {{
            "ID": f"{{service_name}}-{{service_port}}",
            "Name": service_name,
            "Address": "localhost",
            "Port": service_port,
            "Check": {{
                "HTTP": f"http://localhost:{{service_port}}{{health_check}}",
                "Interval": "10s",
                "Timeout": "5s"
            }},
            "Tags": ["omniwriter", "microservice"]
        }}
        
        # Registrar no Consul
        response = requests.put(
            "http://localhost:8500/v1/agent/service/register",
            json=service_data,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"✅ Serviço {{service_name}} registrado com sucesso")
            return True
        else:
            logger.error(f"❌ Erro ao registrar {{service_name}}: {{response.status_code}}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Erro ao registrar {{service_name}}: {{e}}")
        return False

def main():
    """Função principal."""
    services = [
        ("article-service", 5001, "/health"),
        ("user-service", 5002, "/health"),
        ("notification-service", 5003, "/health")
    ]
    
    logger.info("🚀 Iniciando registro de serviços...")
    
    for service_name, port, health_check in services:
        register_service(service_name, port, health_check)
        time.sleep(2)
    
    logger.info("✅ Registro de serviços concluído")

if __name__ == "__main__":
    main()
'''
            
            with open(registration_script, "w") as f:
                f.write(script_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Script de registro criado: {registration_script}")
            
            self.results["steps"].append({
                "step": "configure_service_discovery",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "config_file": config_file,
                "registration_script": registration_script
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na configuração: {e}")
            self.results["steps"].append({
                "step": "configure_service_discovery",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False 