"""
Priority Management System - Omni Writer
========================================

Sistema de gerenciamento de prioridades para testes de carga.
Implementa tags, ordenação por criticidade e execução seletiva.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 14
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:10:00Z
"""

import os
import json
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Set
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import yaml
from collections import defaultdict, deque

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('priority_manager')

class PriorityLevel(Enum):
    """Níveis de prioridade."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class TestStatus(Enum):
    """Status dos testes."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class TestDefinition:
    """Definição de teste com prioridade."""
    test_id: str
    name: str
    file_path: str
    priority: PriorityLevel
    tags: Set[str]
    dependencies: List[str]
    estimated_duration: int  # segundos
    critical_path: bool
    last_run: Optional[datetime] = None
    status: TestStatus = TestStatus.PENDING
    failure_count: int = 0
    success_count: int = 0
    avg_duration: Optional[float] = None

@dataclass
class PriorityRule:
    """Regra de prioridade."""
    rule_id: str
    name: str
    conditions: Dict[str, Any]
    priority_boost: int
    description: str
    active: bool = True

class PriorityManager:
    """
    Gerenciador de prioridades para testes de carga.
    """
    
    def __init__(self, 
                 tests_dir: str = "tests/load",
                 config_file: str = "tests/load/priority/config.json"):
        """
        Inicializa o gerenciador de prioridades.
        
        Args:
            tests_dir: Diretório com testes
            config_file: Arquivo de configuração
        """
        self.tests_dir = Path(tests_dir)
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/priority/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Dados dos testes
        self.tests: Dict[str, TestDefinition] = {}
        self.priority_rules: List[PriorityRule] = []
        self.execution_queue: deque = deque()
        
        # Configurações
        self.priority_config = {
            "auto_discovery": True,
            "dependency_resolution": True,
            "max_concurrent_tests": 3,
            "retry_failed_tests": True,
            "max_retries": 2,
            "priority_weights": {
                "critical": 100,
                "high": 75,
                "medium": 50,
                "low": 25
            },
            "tag_weights": {
                "@performance": 20,
                "@security": 30,
                "@integration": 15,
                "@smoke": 40,
                "@regression": 10
            }
        }
        
        # Histórico de execução
        self.execution_history: List[Dict[str, Any]] = []
        
        # Carrega configuração
        self.load_config()
        
        # Descobre testes automaticamente
        if self.priority_config["auto_discovery"]:
            self.discover_tests()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Testes descobertos: {len(self.tests)}")

    def load_config(self) -> None:
        """
        Carrega configuração do arquivo ou usa padrões.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Carrega configurações
                self.priority_config.update(config.get('priority_config', {}))
                
                # Carrega regras de prioridade
                for rule_data in config.get('priority_rules', []):
                    rule = PriorityRule(**rule_data)
                    self.priority_rules.append(rule)
                
                logger.info("Configuração carregada do arquivo")
            else:
                self._create_default_rules()
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            self._create_default_rules()

    def _create_default_rules(self) -> None:
        """
        Cria regras de prioridade padrão baseadas no código real.
        """
        default_rules = [
            PriorityRule(
                rule_id="critical_endpoints",
                name="Critical Endpoints",
                conditions={"endpoints": ["/generate", "/download"]},
                priority_boost=50,
                description="Endpoints críticos recebem boost de prioridade"
            ),
            PriorityRule(
                rule_id="high_failure_rate",
                name="High Failure Rate",
                conditions={"failure_rate": 0.1},
                priority_boost=30,
                description="Testes com alta taxa de falha recebem boost"
            ),
            PriorityRule(
                rule_id="security_tests",
                name="Security Tests",
                conditions={"tags": ["@security"]},
                priority_boost=40,
                description="Testes de segurança têm prioridade alta"
            ),
            PriorityRule(
                rule_id="performance_tests",
                name="Performance Tests",
                conditions={"tags": ["@performance"]},
                priority_boost=25,
                description="Testes de performance têm prioridade média"
            ),
            PriorityRule(
                rule_id="smoke_tests",
                name="Smoke Tests",
                conditions={"tags": ["@smoke"]},
                priority_boost=60,
                description="Testes de fumaça têm prioridade máxima"
            )
        ]
        
        self.priority_rules = default_rules

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'priority_config': self.priority_config,
                'priority_rules': [asdict(rule) for rule in self.priority_rules],
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def discover_tests(self) -> None:
        """
        Descobre testes automaticamente no diretório.
        """
        logger.info("Descobrindo testes...")
        
        # Busca arquivos Locust
        locust_files = list(self.tests_dir.rglob("locustfile_*.py"))
        
        for locust_file in locust_files:
            try:
                test_info = self._analyze_test_file(locust_file)
                if test_info:
                    self.tests[test_info.test_id] = test_info
                    
            except Exception as e:
                logger.error(f"Erro ao analisar {locust_file}: {e}")
        
        # Busca outros tipos de teste
        test_files = list(self.tests_dir.rglob("*_test.py")) + list(self.tests_dir.rglob("test_*.py"))
        
        for test_file in test_files:
            try:
                test_info = self._analyze_test_file(test_file)
                if test_info:
                    self.tests[test_info.test_id] = test_info
                    
            except Exception as e:
                logger.error(f"Erro ao analisar {test_file}: {e}")
        
        logger.info(f"Descobertos {len(self.tests)} testes")

    def _analyze_test_file(self, file_path: Path) -> Optional[TestDefinition]:
        """
        Analisa arquivo de teste para extrair informações.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extrai nome do teste
            test_name = file_path.stem.replace('locustfile_', '').replace('test_', '')
            
            # Determina prioridade baseada no nome e conteúdo
            priority = self._determine_priority(test_name, content)
            
            # Extrai tags
            tags = self._extract_tags(content)
            
            # Determina se é critical path
            critical_path = self._is_critical_path(test_name, content)
            
            # Estima duração
            estimated_duration = self._estimate_duration(content)
            
            # Identifica dependências
            dependencies = self._extract_dependencies(content)
            
            test_info = TestDefinition(
                test_id=f"{test_name}_{int(time.time())}",
                name=test_name,
                file_path=str(file_path),
                priority=priority,
                tags=tags,
                dependencies=dependencies,
                estimated_duration=estimated_duration,
                critical_path=critical_path
            )
            
            return test_info
            
        except Exception as e:
            logger.error(f"Erro ao analisar {file_path}: {e}")
            return None

    def _determine_priority(self, test_name: str, content: str) -> PriorityLevel:
        """
        Determina prioridade baseada no nome e conteúdo do teste.
        """
        # Prioridade baseada no nome
        if any(keyword in test_name.lower() for keyword in ['smoke', 'critical', 'core']):
            return PriorityLevel.CRITICAL
        elif any(keyword in test_name.lower() for keyword in ['security', 'auth', 'generate']):
            return PriorityLevel.HIGH
        elif any(keyword in test_name.lower() for keyword in ['performance', 'load', 'stress']):
            return PriorityLevel.MEDIUM
        else:
            return PriorityLevel.LOW

    def _extract_tags(self, content: str) -> Set[str]:
        """
        Extrai tags do conteúdo do teste.
        """
        tags = set()
        
        # Busca tags no formato @tag
        tag_pattern = r'@(\w+)'
        found_tags = re.findall(tag_pattern, content)
        tags.update(f"@{tag}" for tag in found_tags)
        
        # Adiciona tags baseadas no conteúdo
        if 'security' in content.lower() or 'auth' in content.lower():
            tags.add('@security')
        if 'performance' in content.lower() or 'load' in content.lower():
            tags.add('@performance')
        if 'integration' in content.lower():
            tags.add('@integration')
        if 'smoke' in content.lower():
            tags.add('@smoke')
        if 'regression' in content.lower():
            tags.add('@regression')
        
        return tags

    def _is_critical_path(self, test_name: str, content: str) -> bool:
        """
        Determina se o teste é parte do critical path.
        """
        critical_keywords = ['generate', 'download', 'auth', 'core', 'smoke']
        return any(keyword in test_name.lower() for keyword in critical_keywords)

    def _estimate_duration(self, content: str) -> int:
        """
        Estima duração do teste baseado no conteúdo.
        """
        # Análise básica do conteúdo
        lines = content.split('\n')
        task_count = len([line for line in lines if '@task' in line])
        user_count = len([line for line in lines if 'wait_time' in line])
        
        # Estimativa baseada em características
        base_duration = 120  # 2 minutos base
        duration = base_duration + (task_count * 30) + (user_count * 10)
        
        return min(duration, 600)  # Máximo 10 minutos

    def _extract_dependencies(self, content: str) -> List[str]:
        """
        Extrai dependências do teste.
        """
        dependencies = []
        
        # Busca imports e dependências
        import_pattern = r'from\s+(\w+)\s+import'
        found_imports = re.findall(import_pattern, content)
        
        # Filtra dependências relevantes
        relevant_deps = ['utils_load', 'shared', 'domain', 'infrastructure']
        dependencies = [dep for dep in found_imports if dep in relevant_deps]
        
        return dependencies

    def calculate_priority_score(self, test: TestDefinition) -> int:
        """
        Calcula score de prioridade para um teste.
        """
        base_score = self.priority_config["priority_weights"][test.priority.value]
        
        # Adiciona peso das tags
        tag_score = 0
        for tag in test.tags:
            tag_score += self.priority_config["tag_weights"].get(tag, 0)
        
        # Aplica regras de prioridade
        rule_score = 0
        for rule in self.priority_rules:
            if rule.active and self._rule_matches(test, rule):
                rule_score += rule.priority_boost
        
        # Penaliza testes que falharam recentemente
        failure_penalty = test.failure_count * 10
        
        # Bonus para critical path
        critical_bonus = 20 if test.critical_path else 0
        
        total_score = base_score + tag_score + rule_score - failure_penalty + critical_bonus
        
        return max(total_score, 0)  # Não pode ser negativo

    def _rule_matches(self, test: TestDefinition, rule: PriorityRule) -> bool:
        """
        Verifica se uma regra se aplica ao teste.
        """
        try:
            conditions = rule.conditions
            
            # Verifica endpoints
            if 'endpoints' in conditions:
                test_endpoints = self._extract_endpoints(test.file_path)
                if not any(endpoint in test_endpoints for endpoint in conditions['endpoints']):
                    return False
            
            # Verifica tags
            if 'tags' in conditions:
                required_tags = conditions['tags']
                if not any(tag in test.tags for tag in required_tags):
                    return False
            
            # Verifica taxa de falha
            if 'failure_rate' in conditions:
                if test.success_count + test.failure_count > 0:
                    failure_rate = test.failure_count / (test.success_count + test.failure_count)
                    if failure_rate < conditions['failure_rate']:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao verificar regra {rule.rule_id}: {e}")
            return False

    def _extract_endpoints(self, file_path: str) -> List[str]:
        """
        Extrai endpoints do arquivo de teste.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Busca endpoints no código
            endpoint_pattern = r'["\']/(\w+)["\']'
            endpoints = re.findall(endpoint_pattern, content)
            
            return list(set(endpoints))  # Remove duplicatas
            
        except Exception as e:
            logger.error(f"Erro ao extrair endpoints de {file_path}: {e}")
            return []

    def build_execution_queue(self, filter_tags: List[str] = None, max_tests: int = None) -> List[TestDefinition]:
        """
        Constrói fila de execução ordenada por prioridade.
        """
        logger.info("Construindo fila de execução...")
        
        # Filtra testes se necessário
        candidate_tests = list(self.tests.values())
        
        if filter_tags:
            candidate_tests = [
                test for test in candidate_tests
                if any(tag in test.tags for tag in filter_tags)
            ]
        
        # Calcula scores de prioridade
        test_scores = []
        for test in candidate_tests:
            score = self.calculate_priority_score(test)
            test_scores.append((test, score))
        
        # Ordena por score (maior primeiro)
        test_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Resolve dependências se habilitado
        if self.priority_config["dependency_resolution"]:
            ordered_tests = self._resolve_dependencies([test for test, _ in test_scores])
        else:
            ordered_tests = [test for test, _ in test_scores]
        
        # Limita número de testes se especificado
        if max_tests:
            ordered_tests = ordered_tests[:max_tests]
        
        # Atualiza fila de execução
        self.execution_queue = deque(ordered_tests)
        
        logger.info(f"Fila construída com {len(ordered_tests)} testes")
        return ordered_tests

    def _resolve_dependencies(self, tests: List[TestDefinition]) -> List[TestDefinition]:
        """
        Resolve dependências entre testes usando ordenação topológica.
        """
        try:
            # Cria grafo de dependências
            graph = {}
            in_degree = {}
            
            for test in tests:
                graph[test.test_id] = []
                in_degree[test.test_id] = 0
            
            # Adiciona arestas
            for test in tests:
                for dep in test.dependencies:
                    # Busca teste dependente
                    for other_test in tests:
                        if dep in other_test.name or dep in other_test.file_path:
                            graph[other_test.test_id].append(test.test_id)
                            in_degree[test.test_id] += 1
            
            # Ordenação topológica
            queue = deque([test_id for test_id, degree in in_degree.items() if degree == 0])
            ordered = []
            
            while queue:
                current = queue.popleft()
                ordered.append(current)
                
                for neighbor in graph[current]:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        queue.append(neighbor)
            
            # Converte de volta para TestDefinition
            test_map = {test.test_id: test for test in tests}
            ordered_tests = [test_map[test_id] for test_id in ordered if test_id in test_map]
            
            return ordered_tests
            
        except Exception as e:
            logger.error(f"Erro ao resolver dependências: {e}")
            return tests

    def get_next_test(self) -> Optional[TestDefinition]:
        """
        Obtém próximo teste da fila.
        """
        if self.execution_queue:
            return self.execution_queue.popleft()
        return None

    def add_test_to_queue(self, test: TestDefinition, priority: str = "normal") -> None:
        """
        Adiciona teste à fila com prioridade específica.
        """
        if priority == "high":
            self.execution_queue.appendleft(test)
        else:
            self.execution_queue.append(test)
        
        logger.info(f"Teste {test.name} adicionado à fila com prioridade {priority}")

    def update_test_status(self, test_id: str, status: TestStatus, duration: float = None) -> None:
        """
        Atualiza status de um teste.
        """
        if test_id in self.tests:
            test = self.tests[test_id]
            test.status = status
            test.last_run = datetime.now()
            
            if status == TestStatus.COMPLETED:
                test.success_count += 1
                if duration:
                    if test.avg_duration:
                        test.avg_duration = (test.avg_duration + duration) / 2
                    else:
                        test.avg_duration = duration
            elif status == TestStatus.FAILED:
                test.failure_count += 1
            
            # Registra no histórico
            self.execution_history.append({
                'test_id': test_id,
                'status': status.value,
                'timestamp': datetime.now().isoformat(),
                'duration': duration
            })
            
            logger.info(f"Status atualizado: {test_id} -> {status.value}")

    def get_tests_by_priority(self, priority: PriorityLevel) -> List[TestDefinition]:
        """
        Obtém testes por nível de prioridade.
        """
        return [test for test in self.tests.values() if test.priority == priority]

    def get_tests_by_tag(self, tag: str) -> List[TestDefinition]:
        """
        Obtém testes por tag.
        """
        return [test for test in self.tests.values() if tag in test.tags]

    def get_critical_path_tests(self) -> List[TestDefinition]:
        """
        Obtém testes do critical path.
        """
        return [test for test in self.tests.values() if test.critical_path]

    def generate_priority_report(self) -> str:
        """
        Gera relatório de prioridades.
        """
        try:
            report_file = self.output_dir / f"priority_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Prioridades - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de testes:** {len(self.tests)}\n")
                f.write(f"- **Testes críticos:** {len(self.get_tests_by_priority(PriorityLevel.CRITICAL))}\n")
                f.write(f"- **Testes de alta prioridade:** {len(self.get_tests_by_priority(PriorityLevel.HIGH))}\n")
                f.write(f"- **Testes do critical path:** {len(self.get_critical_path_tests())}\n")
                f.write(f"- **Regras ativas:** {len([r for r in self.priority_rules if r.active])}\n\n")
                
                f.write("## Testes por Prioridade\n\n")
                
                for priority in PriorityLevel:
                    tests = self.get_tests_by_priority(priority)
                    f.write(f"### {priority.value.title()}\n")
                    f.write(f"- **Quantidade:** {len(tests)}\n")
                    
                    if tests:
                        f.write("- **Testes:**\n")
                        for test in tests[:5]:  # Mostra apenas os primeiros 5
                            f.write(f"  - {test.name} (Score: {self.calculate_priority_score(test)})\n")
                        if len(tests) > 5:
                            f.write(f"  - ... e mais {len(tests) - 5} testes\n")
                    f.write("\n")
                
                f.write("## Testes por Tag\n\n")
                
                # Agrupa por tag
                tag_groups = defaultdict(list)
                for test in self.tests.values():
                    for tag in test.tags:
                        tag_groups[tag].append(test)
                
                for tag, tests in tag_groups.items():
                    f.write(f"### {tag}\n")
                    f.write(f"- **Quantidade:** {len(tests)}\n")
                    f.write(f"- **Peso:** {self.priority_config['tag_weights'].get(tag, 0)}\n\n")
                
                f.write("## Regras de Prioridade\n\n")
                
                for rule in self.priority_rules:
                    f.write(f"### {rule.name}\n")
                    f.write(f"- **ID:** {rule.rule_id}\n")
                    f.write(f"- **Ativa:** {rule.active}\n")
                    f.write(f"- **Boost:** {rule.priority_boost}\n")
                    f.write(f"- **Descrição:** {rule.description}\n\n")
                
                f.write("## Histórico de Execução\n\n")
                
                if self.execution_history:
                    recent_history = self.execution_history[-10:]  # Últimos 10
                    f.write("| Teste | Status | Timestamp |\n")
                    f.write("|-------|--------|-----------|\n")
                    
                    for entry in recent_history:
                        f.write(f"| {entry['test_id']} | {entry['status']} | {entry['timestamp']} |\n")
                else:
                    f.write("Nenhum histórico disponível.\n")
                
                f.write("\n---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""

    def export_queue_to_yaml(self, output_file: str = None) -> str:
        """
        Exporta fila de execução para YAML.
        """
        try:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.output_dir / f"execution_queue_{timestamp}.yaml"
            
            queue_data = {
                'generated_at': datetime.now().isoformat(),
                'total_tests': len(self.execution_queue),
                'tests': []
            }
            
            for test in list(self.execution_queue):
                test_data = {
                    'test_id': test.test_id,
                    'name': test.name,
                    'priority': test.priority.value,
                    'tags': list(test.tags),
                    'estimated_duration': test.estimated_duration,
                    'critical_path': test.critical_path,
                    'priority_score': self.calculate_priority_score(test)
                }
                queue_data['tests'].append(test_data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(queue_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Fila exportada: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Erro ao exportar fila: {e}")
            return ""


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Priority Manager...")
    
    manager = PriorityManager()
    
    # Exemplo de uso
    try:
        # Constrói fila de execução
        execution_queue = manager.build_execution_queue(
            filter_tags=['@performance', '@security'],
            max_tests=10
        )
        
        # Gera relatório
        report_file = manager.generate_priority_report()
        
        # Exporta fila
        queue_file = manager.export_queue_to_yaml()
        
        logger.info("Priority Manager testado com sucesso!")
        logger.info(f"Fila construída: {len(execution_queue)} testes")
        logger.info(f"Relatório: {report_file}")
        logger.info(f"Fila exportada: {queue_file}")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    main() 