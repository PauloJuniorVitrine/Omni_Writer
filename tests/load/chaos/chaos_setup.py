#!/usr/bin/env python3
"""
Chaos Mesh Setup para Load Tests - Omni Writer
==============================================

Configuração e gerenciamento de experimentos de Chaos Engineering
durante testes de carga para validar resiliência do sistema.

Autor: Equipe de Performance
Data: 2025-01-27
Versão: 1.0
"""

import subprocess
import json
import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[CHAOS][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ChaosExperiment:
    """Estrutura para experimentos de Chaos Engineering."""
    name: str
    type: str  # 'pod-failure', 'network-delay', 'service-failure'
    target: str
    duration: int  # segundos
    parameters: Dict

class ChaosMeshManager:
    """Gerenciador de experimentos Chaos Mesh."""
    
    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self.experiments: List[ChaosExperiment] = []
        
    def install_chaos_mesh(self) -> bool:
        """
        Instala Chaos Mesh no cluster.
        
        Returns:
            bool: True se instalação foi bem-sucedida
        """
        try:
            logger.info("Instalando Chaos Mesh...")
            
            # Instalar Chaos Mesh via Helm
            cmd = [
                "helm", "repo", "add", "chaos-mesh", 
                "https://charts.chaos-mesh.org"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            cmd = [
                "helm", "repo", "update"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            cmd = [
                "helm", "install", "chaos-mesh", "chaos-mesh/chaos-mesh",
                "--namespace", "chaos-testing",
                "--create-namespace"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            logger.info("Chaos Mesh instalado com sucesso!")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro na instalação: {e}")
            return False
    
    def create_pod_failure_experiment(self, target_pod: str, duration: int = 30) -> ChaosExperiment:
        """
        Cria experimento de falha de pod.
        
        Args:
            target_pod: Nome do pod alvo
            duration: Duração da falha em segundos
            
        Returns:
            ChaosExperiment: Experimento configurado
        """
        experiment = ChaosExperiment(
            name=f"pod-failure-{target_pod}-{int(time.time())}",
            type="pod-failure",
            target=target_pod,
            duration=duration,
            parameters={
                "action": "pod-failure",
                "mode": "one",
                "value": "",
                "duration": f"{duration}s"
            }
        )
        
        self.experiments.append(experiment)
        return experiment
    
    def create_network_delay_experiment(self, target_service: str, delay: int = 1000) -> ChaosExperiment:
        """
        Cria experimento de latência de rede.
        
        Args:
            target_service: Serviço alvo
            delay: Latência em milissegundos
            
        Returns:
            ChaosExperiment: Experimento configurado
        """
        experiment = ChaosExperiment(
            name=f"network-delay-{target_service}-{int(time.time())}",
            type="network-delay",
            target=target_service,
            duration=60,
            parameters={
                "action": "delay",
                "mode": "one",
                "value": "",
                "delay": f"{delay}ms",
                "duration": "60s"
            }
        )
        
        self.experiments.append(experiment)
        return experiment
    
    def create_service_failure_experiment(self, target_service: str, duration: int = 30) -> ChaosExperiment:
        """
        Cria experimento de falha de serviço externo.
        
        Args:
            target_service: Serviço externo alvo (ex: OpenAI, DeepSeek)
            duration: Duração da falha em segundos
            
        Returns:
            ChaosExperiment: Experimento configurado
        """
        experiment = ChaosExperiment(
            name=f"service-failure-{target_service}-{int(time.time())}",
            type="service-failure",
            target=target_service,
            duration=duration,
            parameters={
                "action": "network-partition",
                "mode": "one",
                "value": "",
                "duration": f"{duration}s",
                "direction": "to"
            }
        )
        
        self.experiments.append(experiment)
        return experiment
    
    def apply_experiment(self, experiment: ChaosExperiment) -> bool:
        """
        Aplica experimento de Chaos Engineering.
        
        Args:
            experiment: Experimento a ser aplicado
            
        Returns:
            bool: True se aplicação foi bem-sucedida
        """
        try:
            logger.info(f"Aplicando experimento: {experiment.name}")
            
            # Criar YAML do experimento
            yaml_content = self._generate_experiment_yaml(experiment)
            
            # Aplicar via kubectl
            cmd = ["kubectl", "apply", "-f", "-"]
            result = subprocess.run(
                cmd, 
                input=yaml_content.encode(), 
                check=True, 
                capture_output=True
            )
            
            logger.info(f"Experimento {experiment.name} aplicado com sucesso!")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao aplicar experimento: {e}")
            return False
    
    def cleanup_experiment(self, experiment: ChaosExperiment) -> bool:
        """
        Remove experimento de Chaos Engineering.
        
        Args:
            experiment: Experimento a ser removido
            
        Returns:
            bool: True se remoção foi bem-sucedida
        """
        try:
            logger.info(f"Removendo experimento: {experiment.name}")
            
            cmd = [
                "kubectl", "delete", "podchaos", 
                experiment.name, 
                "--namespace", self.namespace
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            logger.info(f"Experimento {experiment.name} removido com sucesso!")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao remover experimento: {e}")
            return False
    
    def _generate_experiment_yaml(self, experiment: ChaosExperiment) -> str:
        """
        Gera YAML para experimento de Chaos Engineering.
        
        Args:
            experiment: Experimento para gerar YAML
            
        Returns:
            str: YAML do experimento
        """
        if experiment.type == "pod-failure":
            return f"""
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: {experiment.name}
  namespace: {self.namespace}
spec:
  action: pod-failure
  mode: one
  value: ""
  duration: "{experiment.duration}s"
  selector:
    namespaces:
      - {self.namespace}
    labelSelectors:
      app: {experiment.target}
"""
        elif experiment.type == "network-delay":
            return f"""
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {experiment.name}
  namespace: {self.namespace}
spec:
  action: delay
  mode: one
  value: ""
  delay:
    latency: "{experiment.parameters['delay']}"
  duration: "{experiment.duration}s"
  selector:
    namespaces:
      - {self.namespace}
    labelSelectors:
      app: {experiment.target}
"""
        else:
            raise ValueError(f"Tipo de experimento não suportado: {experiment.type}")

def main():
    """Função principal para demonstração."""
    logger.info("Iniciando configuração do Chaos Mesh...")
    
    # Criar gerenciador
    chaos_manager = ChaosMeshManager(namespace="omni-writer")
    
    # Instalar Chaos Mesh (comentado para evitar instalação automática)
    # if not chaos_manager.install_chaos_mesh():
    #     logger.error("Falha na instalação do Chaos Mesh")
    #     return
    
    # Criar experimentos de exemplo
    experiments = [
        chaos_manager.create_pod_failure_experiment("omni-writer-api", 30),
        chaos_manager.create_network_delay_experiment("openai-api", 2000),
        chaos_manager.create_service_failure_experiment("deepseek-api", 45)
    ]
    
    logger.info(f"Criados {len(experiments)} experimentos de exemplo")
    
    # Salvar experimentos em arquivo para uso posterior
    with open("chaos_experiments.json", "w") as f:
        json.dump([exp.__dict__ for exp in experiments], f, indent=2)
    
    logger.info("Configuração do Chaos Mesh concluída!")

if __name__ == "__main__":
    main() 