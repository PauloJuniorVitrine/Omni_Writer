"""
Log-based Generation - Omni Writer
==================================

Sistema de geração de testes baseado em análise de logs reais.
Extrai padrões e gera scripts de teste automaticamente.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 18
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:30:00Z
"""

import os
import json
import time
import re
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Set
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
import hashlib
import pickle

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('log_based_generator')

@dataclass
class LogPattern:
    """Padrão extraído dos logs."""
    pattern_id: str
    pattern_type: str  # 'endpoint', 'error', 'performance', 'user_behavior'
    regex_pattern: str
    frequency: int
    examples: List[str]
    confidence: float
    extracted_data: Dict[str, Any]
    timestamp: datetime

@dataclass
class GeneratedTest:
    """Teste gerado automaticamente."""
    test_id: str
    test_name: str
    test_type: str  # 'locust', 'pytest', 'jmeter'
    source_pattern: str
    script_content: str
    parameters: Dict[str, Any]
    validation_rules: List[str]
    confidence_score: float
    generated_at: datetime

@dataclass
class LogAnalysisResult:
    """Resultado da análise de logs."""
    log_file: str
    total_lines: int
    patterns_found: int
    endpoints_detected: List[str]
    error_patterns: List[str]
    performance_issues: List[str]
    user_behaviors: List[str]
    analysis_duration: float
    timestamp: datetime

class LogBasedGenerator:
    """
    Gerador de testes baseado em análise de logs reais.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/logs/config.json"):
        """
        Inicializa o gerador baseado em logs.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/logs/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações de análise
        self.analysis_config = {
            "log_patterns": {
                "endpoint_pattern": r'(\w+)\s+([A-Z]+)\s+([^\s]+)\s+(\d{3})',
                "error_pattern": r'(ERROR|CRITICAL|FATAL).*?(\d{4}-\d{2}-\d{2})',
                "performance_pattern": r'(\d+\.\d+)ms.*?([A-Z]+)\s+([^\s]+)',
                "user_agent_pattern": r'User-Agent:\s*([^\n]+)',
                "ip_pattern": r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                "timestamp_pattern": r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
            },
            "min_pattern_frequency": 5,
            "confidence_threshold": 0.7,
            "max_examples_per_pattern": 10,
            "enable_real_time_analysis": True,
            "enable_auto_generation": True,
            "test_templates": {
                "locust": "tests/load/logs/templates/locust_template.py",
                "pytest": "tests/load/logs/templates/pytest_template.py",
                "jmeter": "tests/load/logs/templates/jmeter_template.jmx"
            }
        }
        
        # Padrões extraídos
        self.log_patterns: List[LogPattern] = []
        self.pattern_cache: Dict[str, LogPattern] = {}
        
        # Testes gerados
        self.generated_tests: List[GeneratedTest] = []
        self.test_cache: Dict[str, GeneratedTest] = {}
        
        # Resultados de análise
        self.analysis_results: List[LogAnalysisResult] = []
        
        # Estado do sistema
        self.is_analyzing = False
        self.analysis_thread = None
        
        # Cache de análise
        self.analysis_cache_file = self.output_dir / "analysis_cache.pkl"
        self.load_analysis_cache()
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")

    def load_config(self) -> None:
        """
        Carrega configuração de análise de logs.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                self.analysis_config.update(config.get('analysis_config', {}))
                logger.info("Configuração carregada do arquivo")
            else:
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'analysis_config': self.analysis_config,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def load_analysis_cache(self) -> None:
        """
        Carrega cache de análise anterior.
        """
        try:
            if self.analysis_cache_file.exists():
                with open(self.analysis_cache_file, 'rb') as f:
                    cache_data = pickle.load(f)
                
                self.log_patterns = cache_data.get('patterns', [])
                self.generated_tests = cache_data.get('tests', [])
                
                # Reconstrói caches
                for pattern in self.log_patterns:
                    self.pattern_cache[pattern.pattern_id] = pattern
                
                for test in self.generated_tests:
                    self.test_cache[test.test_id] = test
                
                logger.info(f"Cache carregado: {len(self.log_patterns)} padrões, {len(self.generated_tests)} testes")
                
        except Exception as e:
            logger.error(f"Erro ao carregar cache: {e}")

    def save_analysis_cache(self) -> None:
        """
        Salva cache de análise atual.
        """
        try:
            cache_data = {
                'patterns': self.log_patterns,
                'tests': self.generated_tests,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.analysis_cache_file, 'wb') as f:
                pickle.dump(cache_data, f)
            
            logger.info("Cache salvo")
            
        except Exception as e:
            logger.error(f"Erro ao salvar cache: {e}")

    def analyze_log_file(self, log_file_path: str) -> LogAnalysisResult:
        """
        Analisa um arquivo de log específico.
        """
        start_time = time.time()
        
        try:
            log_file = Path(log_file_path)
            if not log_file.exists():
                raise FileNotFoundError(f"Arquivo de log não encontrado: {log_file_path}")
            
            logger.info(f"Analisando arquivo de log: {log_file_path}")
            
            # Lê o arquivo de log
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()
            
            total_lines = len(log_lines)
            
            # Extrai padrões
            patterns = self._extract_patterns_from_lines(log_lines)
            
            # Categoriza padrões
            endpoints = self._categorize_endpoints(patterns)
            errors = self._categorize_errors(patterns)
            performance = self._categorize_performance(patterns)
            behaviors = self._categorize_user_behaviors(patterns)
            
            # Cria resultado
            result = LogAnalysisResult(
                log_file=str(log_file),
                total_lines=total_lines,
                patterns_found=len(patterns),
                endpoints_detected=endpoints,
                error_patterns=errors,
                performance_issues=performance,
                user_behaviors=behaviors,
                analysis_duration=time.time() - start_time,
                timestamp=datetime.now()
            )
            
            self.analysis_results.append(result)
            
            logger.info(f"Análise concluída: {total_lines} linhas, {len(patterns)} padrões")
            return result
            
        except Exception as e:
            logger.error(f"Erro ao analisar arquivo {log_file_path}: {e}")
            return None

    def _extract_patterns_from_lines(self, log_lines: List[str]) -> List[LogPattern]:
        """
        Extrai padrões de uma lista de linhas de log.
        """
        patterns = []
        
        # Contadores para frequência
        pattern_counts = defaultdict(int)
        pattern_examples = defaultdict(list)
        pattern_data = defaultdict(lambda: defaultdict(list))
        
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            
            # Analisa cada tipo de padrão
            self._analyze_endpoint_pattern(line, pattern_counts, pattern_examples, pattern_data)
            self._analyze_error_pattern(line, pattern_counts, pattern_examples, pattern_data)
            self._analyze_performance_pattern(line, pattern_counts, pattern_examples, pattern_data)
            self._analyze_user_behavior_pattern(line, pattern_counts, pattern_examples, pattern_data)
        
        # Cria objetos LogPattern
        for pattern_key, count in pattern_counts.items():
            if count >= self.analysis_config["min_pattern_frequency"]:
                pattern_type, pattern_regex = pattern_key.split(":", 1)
                
                pattern = LogPattern(
                    pattern_id=self._generate_pattern_id(pattern_key),
                    pattern_type=pattern_type,
                    regex_pattern=pattern_regex,
                    frequency=count,
                    examples=pattern_examples[pattern_key][:self.analysis_config["max_examples_per_pattern"]],
                    confidence=self._calculate_pattern_confidence(count, len(log_lines)),
                    extracted_data=dict(pattern_data[pattern_key]),
                    timestamp=datetime.now()
                )
                
                patterns.append(pattern)
                self.pattern_cache[pattern.pattern_id] = pattern
        
        return patterns

    def _analyze_endpoint_pattern(self, line: str, counts: Dict, examples: Dict, data: Dict) -> None:
        """
        Analisa padrões de endpoints.
        """
        pattern = self.analysis_config["log_patterns"]["endpoint_pattern"]
        matches = re.findall(pattern, line)
        
        for match in matches:
            method, http_method, endpoint, status_code = match
            
            pattern_key = f"endpoint:{method} {http_method} {endpoint} {status_code}"
            counts[pattern_key] += 1
            
            if len(examples[pattern_key]) < self.analysis_config["max_examples_per_pattern"]:
                examples[pattern_key].append(line)
            
            # Extrai dados
            data[pattern_key]["methods"].append(method)
            data[pattern_key]["http_methods"].append(http_method)
            data[pattern_key]["endpoints"].append(endpoint)
            data[pattern_key]["status_codes"].append(status_code)

    def _analyze_error_pattern(self, line: str, counts: Dict, examples: Dict, data: Dict) -> None:
        """
        Analisa padrões de erro.
        """
        pattern = self.analysis_config["log_patterns"]["error_pattern"]
        matches = re.findall(pattern, line)
        
        for match in matches:
            error_level, timestamp = match
            
            pattern_key = f"error:{error_level}"
            counts[pattern_key] += 1
            
            if len(examples[pattern_key]) < self.analysis_config["max_examples_per_pattern"]:
                examples[pattern_key].append(line)
            
            # Extrai dados
            data[pattern_key]["error_levels"].append(error_level)
            data[pattern_key]["timestamps"].append(timestamp)

    def _analyze_performance_pattern(self, line: str, counts: Dict, examples: Dict, data: Dict) -> None:
        """
        Analisa padrões de performance.
        """
        pattern = self.analysis_config["log_patterns"]["performance_pattern"]
        matches = re.findall(pattern, line)
        
        for match in matches:
            response_time, http_method, endpoint = match
            
            pattern_key = f"performance:{response_time}ms {http_method} {endpoint}"
            counts[pattern_key] += 1
            
            if len(examples[pattern_key]) < self.analysis_config["max_examples_per_pattern"]:
                examples[pattern_key].append(line)
            
            # Extrai dados
            data[pattern_key]["response_times"].append(float(response_time))
            data[pattern_key]["http_methods"].append(http_method)
            data[pattern_key]["endpoints"].append(endpoint)

    def _analyze_user_behavior_pattern(self, line: str, counts: Dict, examples: Dict, data: Dict) -> None:
        """
        Analisa padrões de comportamento do usuário.
        """
        # User-Agent
        ua_pattern = self.analysis_config["log_patterns"]["user_agent_pattern"]
        ua_matches = re.findall(ua_pattern, line)
        
        for ua in ua_matches:
            pattern_key = f"user_behavior:user_agent"
            counts[pattern_key] += 1
            
            if len(examples[pattern_key]) < self.analysis_config["max_examples_per_pattern"]:
                examples[pattern_key].append(line)
            
            data[pattern_key]["user_agents"].append(ua)
        
        # IP Address
        ip_pattern = self.analysis_config["log_patterns"]["ip_pattern"]
        ip_matches = re.findall(ip_pattern, line)
        
        for ip in ip_matches:
            pattern_key = f"user_behavior:ip_address"
            counts[pattern_key] += 1
            
            if len(examples[pattern_key]) < self.analysis_config["max_examples_per_pattern"]:
                examples[pattern_key].append(line)
            
            data[pattern_key]["ip_addresses"].append(ip)

    def _categorize_endpoints(self, patterns: List[LogPattern]) -> List[str]:
        """
        Categoriza endpoints encontrados.
        """
        endpoints = set()
        
        for pattern in patterns:
            if pattern.pattern_type == "endpoint":
                endpoint_data = pattern.extracted_data.get("endpoints", [])
                endpoints.update(endpoint_data)
        
        return list(endpoints)

    def _categorize_errors(self, patterns: List[LogPattern]) -> List[str]:
        """
        Categoriza erros encontrados.
        """
        errors = []
        
        for pattern in patterns:
            if pattern.pattern_type == "error":
                error_levels = pattern.extracted_data.get("error_levels", [])
                errors.extend(error_levels)
        
        return list(set(errors))

    def _categorize_performance(self, patterns: List[LogPattern]) -> List[str]:
        """
        Categoriza problemas de performance.
        """
        performance_issues = []
        
        for pattern in patterns:
            if pattern.pattern_type == "performance":
                response_times = pattern.extracted_data.get("response_times", [])
                if response_times:
                    avg_time = np.mean(response_times)
                    if avg_time > 1000:  # Mais de 1 segundo
                        performance_issues.append(f"Slow endpoint: {avg_time:.2f}ms avg")
        
        return performance_issues

    def _categorize_user_behaviors(self, patterns: List[LogPattern]) -> List[str]:
        """
        Categoriza comportamentos do usuário.
        """
        behaviors = []
        
        for pattern in patterns:
            if pattern.pattern_type == "user_behavior":
                if "user_agents" in pattern.extracted_data:
                    behaviors.append("User-Agent tracking")
                if "ip_addresses" in pattern.extracted_data:
                    behaviors.append("IP tracking")
        
        return behaviors

    def _generate_pattern_id(self, pattern_key: str) -> str:
        """
        Gera ID único para um padrão.
        """
        return hashlib.md5(pattern_key.encode()).hexdigest()[:8]

    def _calculate_pattern_confidence(self, frequency: int, total_lines: int) -> float:
        """
        Calcula confiança de um padrão baseado na frequência.
        """
        if total_lines == 0:
            return 0.0
        
        # Confiança baseada na frequência relativa
        relative_frequency = frequency / total_lines
        
        # Ajusta confiança baseado no threshold mínimo
        if frequency < self.analysis_config["min_pattern_frequency"]:
            return 0.0
        
        # Confiança aumenta com a frequência, mas tem limite
        confidence = min(relative_frequency * 100, 1.0)
        
        return confidence

    def generate_test_from_pattern(self, pattern: LogPattern) -> GeneratedTest:
        """
        Gera teste a partir de um padrão.
        """
        try:
            test_id = f"test_{pattern.pattern_id}_{int(time.time())}"
            test_name = f"Generated Test - {pattern.pattern_type.title()}"
            
            # Determina tipo de teste baseado no padrão
            test_type = self._determine_test_type(pattern)
            
            # Gera script
            script_content = self._generate_test_script(pattern, test_type)
            
            # Extrai parâmetros
            parameters = self._extract_test_parameters(pattern)
            
            # Define regras de validação
            validation_rules = self._generate_validation_rules(pattern)
            
            # Calcula score de confiança
            confidence_score = pattern.confidence
            
            test = GeneratedTest(
                test_id=test_id,
                test_name=test_name,
                test_type=test_type,
                source_pattern=pattern.pattern_id,
                script_content=script_content,
                parameters=parameters,
                validation_rules=validation_rules,
                confidence_score=confidence_score,
                generated_at=datetime.now()
            )
            
            self.generated_tests.append(test)
            self.test_cache[test.test_id] = test
            
            logger.info(f"Teste gerado: {test_id} (confiança: {confidence_score:.2f})")
            return test
            
        except Exception as e:
            logger.error(f"Erro ao gerar teste do padrão {pattern.pattern_id}: {e}")
            return None

    def _determine_test_type(self, pattern: LogPattern) -> str:
        """
        Determina tipo de teste baseado no padrão.
        """
        if pattern.pattern_type == "endpoint":
            return "locust"
        elif pattern.pattern_type == "performance":
            return "locust"
        elif pattern.pattern_type == "error":
            return "pytest"
        elif pattern.pattern_type == "user_behavior":
            return "locust"
        else:
            return "locust"  # Padrão

    def _generate_test_script(self, pattern: LogPattern, test_type: str) -> str:
        """
        Gera script de teste.
        """
        if test_type == "locust":
            return self._generate_locust_script(pattern)
        elif test_type == "pytest":
            return self._generate_pytest_script(pattern)
        else:
            return self._generate_generic_script(pattern)

    def _generate_locust_script(self, pattern: LogPattern) -> str:
        """
        Gera script Locust.
        """
        if pattern.pattern_type == "endpoint":
            endpoints = pattern.extracted_data.get("endpoints", [])
            methods = pattern.extracted_data.get("http_methods", [])
            
            if endpoints and methods:
                endpoint = endpoints[0]
                method = methods[0]
                
                script = f'''
from locust import HttpUser, task, between

class GeneratedLoadTest(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def test_{pattern.pattern_id}(self):
        """Generated test based on pattern: {pattern.pattern_id}"""
        
        # Endpoint: {endpoint}
        # Method: {method}
        # Frequency: {pattern.frequency}
        
        headers = {{
            "Content-Type": "application/json",
            "User-Agent": "Generated Load Test"
        }}
        
        if "{method}" == "GET":
            response = self.client.get("{endpoint}", headers=headers)
        elif "{method}" == "POST":
            response = self.client.post("{endpoint}", headers=headers, json={{}})
        elif "{method}" == "PUT":
            response = self.client.put("{endpoint}", headers=headers, json={{}})
        elif "{method}" == "DELETE":
            response = self.client.delete("{endpoint}", headers=headers)
        else:
            response = self.client.get("{endpoint}", headers=headers)
        
        # Validation
        if response.status_code != 200:
            response.failure(f"Expected 200, got {{response.status_code}}")
'''
                return script
        
        # Script genérico
        return f'''
from locust import HttpUser, task, between

class GeneratedLoadTest(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def test_{pattern.pattern_id}(self):
        """Generated test based on pattern: {pattern.pattern_id}"""
        
        # Pattern type: {pattern.pattern_type}
        # Frequency: {pattern.frequency}
        # Confidence: {pattern.confidence:.2f}
        
        # TODO: Implement specific test logic based on pattern analysis
        pass
'''

    def _generate_pytest_script(self, pattern: LogPattern) -> str:
        """
        Gera script pytest.
        """
        return f'''
import pytest
import requests

class TestGeneratedFromPattern:
    """Generated test based on pattern: {pattern.pattern_id}"""
    
    def test_{pattern.pattern_id}(self):
        """Test generated from {pattern.pattern_type} pattern"""
        
        # Pattern details:
        # - Type: {pattern.pattern_type}
        # - Frequency: {pattern.frequency}
        # - Confidence: {pattern.confidence:.2f}
        # - Examples: {len(pattern.examples)}
        
        # TODO: Implement specific test logic
        # This test was generated automatically from log analysis
        
        assert True  # Placeholder assertion
'''

    def _generate_generic_script(self, pattern: LogPattern) -> str:
        """
        Gera script genérico.
        """
        return f'''
# Generated test script
# Pattern ID: {pattern.pattern_id}
# Pattern Type: {pattern.pattern_type}
# Frequency: {pattern.frequency}
# Confidence: {pattern.confidence:.2f}
# Generated at: {datetime.now().isoformat()}

# TODO: Implement test logic based on pattern analysis
# Examples from logs:
{chr(10).join(f"# {example}" for example in pattern.examples[:3])}
'''

    def _extract_test_parameters(self, pattern: LogPattern) -> Dict[str, Any]:
        """
        Extrai parâmetros para o teste.
        """
        params = {
            "pattern_id": pattern.pattern_id,
            "pattern_type": pattern.pattern_type,
            "frequency": pattern.frequency,
            "confidence": pattern.confidence
        }
        
        # Adiciona dados específicos do padrão
        if pattern.pattern_type == "endpoint":
            params.update({
                "endpoints": pattern.extracted_data.get("endpoints", []),
                "methods": pattern.extracted_data.get("http_methods", []),
                "status_codes": pattern.extracted_data.get("status_codes", [])
            })
        elif pattern.pattern_type == "performance":
            response_times = pattern.extracted_data.get("response_times", [])
            if response_times:
                params.update({
                    "avg_response_time": np.mean(response_times),
                    "max_response_time": np.max(response_times),
                    "min_response_time": np.min(response_times)
                })
        
        return params

    def _generate_validation_rules(self, pattern: LogPattern) -> List[str]:
        """
        Gera regras de validação para o teste.
        """
        rules = []
        
        if pattern.pattern_type == "endpoint":
            status_codes = pattern.extracted_data.get("status_codes", [])
            if status_codes:
                expected_codes = list(set(status_codes))
                rules.append(f"Status code should be one of: {expected_codes}")
        
        elif pattern.pattern_type == "performance":
            response_times = pattern.extracted_data.get("response_times", [])
            if response_times:
                avg_time = np.mean(response_times)
                rules.append(f"Response time should be <= {avg_time * 1.5:.0f}ms")
        
        elif pattern.pattern_type == "error":
            rules.append("Should not generate errors")
        
        # Regra genérica
        rules.append(f"Test should pass with confidence >= {pattern.confidence:.2f}")
        
        return rules

    def generate_all_tests(self) -> List[GeneratedTest]:
        """
        Gera testes para todos os padrões com confiança suficiente.
        """
        logger.info("Gerando testes para todos os padrões...")
        
        generated_tests = []
        
        for pattern in self.log_patterns:
            if pattern.confidence >= self.analysis_config["confidence_threshold"]:
                test = self.generate_test_from_pattern(pattern)
                if test:
                    generated_tests.append(test)
        
        logger.info(f"Testes gerados: {len(generated_tests)}")
        return generated_tests

    def save_generated_tests(self) -> str:
        """
        Salva testes gerados em arquivos.
        """
        try:
            tests_dir = self.output_dir / "generated_tests"
            tests_dir.mkdir(exist_ok=True)
            
            saved_files = []
            
            for test in self.generated_tests:
                # Determina extensão baseada no tipo
                extensions = {
                    "locust": ".py",
                    "pytest": ".py",
                    "jmeter": ".jmx"
                }
                
                ext = extensions.get(test.test_type, ".py")
                filename = f"{test.test_id}{ext}"
                filepath = tests_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(test.script_content)
                
                saved_files.append(str(filepath))
            
            logger.info(f"Testes salvos: {len(saved_files)} arquivos")
            return str(tests_dir)
            
        except Exception as e:
            logger.error(f"Erro ao salvar testes: {e}")
            return ""

    def generate_log_analysis_report(self) -> str:
        """
        Gera relatório de análise de logs.
        """
        try:
            report_file = self.output_dir / f"log_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Análise de Logs - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Arquivos analisados:** {len(self.analysis_results)}\n")
                f.write(f"- **Padrões encontrados:** {len(self.log_patterns)}\n")
                f.write(f"- **Testes gerados:** {len(self.generated_tests)}\n")
                f.write(f"- **Padrões com alta confiança:** {len([p for p in self.log_patterns if p.confidence >= 0.8])}\n\n")
                
                f.write("## Análises de Arquivos\n\n")
                
                for result in self.analysis_results:
                    f.write(f"### {Path(result.log_file).name}\n")
                    f.write(f"- **Linhas analisadas:** {result.total_lines:,}\n")
                    f.write(f"- **Padrões encontrados:** {result.patterns_found}\n")
                    f.write(f"- **Endpoints detectados:** {len(result.endpoints_detected)}\n")
                    f.write(f"- **Erros encontrados:** {len(result.error_patterns)}\n")
                    f.write(f"- **Problemas de performance:** {len(result.performance_issues)}\n")
                    f.write(f"- **Duração da análise:** {result.analysis_duration:.2f}s\n\n")
                
                f.write("## Padrões Mais Frequentes\n\n")
                
                # Ordena por frequência
                sorted_patterns = sorted(self.log_patterns, key=lambda p: p.frequency, reverse=True)
                
                f.write("| Tipo | Padrão | Frequência | Confiança |\n")
                f.write("|------|--------|------------|-----------|\n")
                
                for pattern in sorted_patterns[:20]:  # Top 20
                    f.write(f"| {pattern.pattern_type} | {pattern.regex_pattern[:50]}... | {pattern.frequency} | {pattern.confidence:.2f} |\n")
                
                f.write("\n## Testes Gerados\n\n")
                
                if self.generated_tests:
                    f.write("| ID | Tipo | Padrão Fonte | Confiança |\n")
                    f.write("|----|------|--------------|-----------|\n")
                    
                    for test in self.generated_tests[-20:]:  # Últimos 20
                        f.write(f"| {test.test_id} | {test.test_type} | {test.source_pattern} | {test.confidence_score:.2f} |\n")
                else:
                    f.write("Nenhum teste gerado ainda.\n")
                
                f.write("\n## Configurações\n\n")
                f.write(f"- **Frequência mínima:** {self.analysis_config['min_pattern_frequency']}\n")
                f.write(f"- **Threshold de confiança:** {self.analysis_config['confidence_threshold']}\n")
                f.write(f"- **Máximo de exemplos:** {self.analysis_config['max_examples_per_pattern']}\n")
                f.write(f"- **Análise em tempo real:** {self.analysis_config['enable_real_time_analysis']}\n")
                f.write(f"- **Geração automática:** {self.analysis_config['enable_auto_generation']}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""

    def analyze_logs_directory(self, logs_dir: str) -> List[LogAnalysisResult]:
        """
        Analisa todos os arquivos de log em um diretório.
        """
        logs_path = Path(logs_dir)
        if not logs_path.exists():
            logger.error(f"Diretório não encontrado: {logs_dir}")
            return []
        
        results = []
        
        # Encontra arquivos de log
        log_files = list(logs_path.glob("*.log")) + list(logs_path.glob("*.txt"))
        
        logger.info(f"Encontrados {len(log_files)} arquivos de log para análise")
        
        for log_file in log_files:
            try:
                result = self.analyze_log_file(str(log_file))
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Erro ao analisar {log_file}: {e}")
        
        # Salva cache após análise completa
        self.save_analysis_cache()
        
        return results


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Log-based Generator...")
    
    generator = LogBasedGenerator()
    
    try:
        # Analisa logs do projeto
        logs_dir = "logs"
        if Path(logs_dir).exists():
            results = generator.analyze_logs_directory(logs_dir)
            logger.info(f"Análise concluída: {len(results)} arquivos processados")
        
        # Gera testes
        generated_tests = generator.generate_all_tests()
        
        # Salva testes
        tests_dir = generator.save_generated_tests()
        
        # Gera relatório
        report_file = generator.generate_log_analysis_report()
        
        logger.info("Log-based Generator concluído com sucesso!")
        logger.info(f"Testes gerados: {len(generated_tests)}")
        logger.info(f"Diretório de testes: {tests_dir}")
        logger.info(f"Relatório: {report_file}")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 