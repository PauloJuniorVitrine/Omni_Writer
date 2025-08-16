#!/usr/bin/env python3
"""
🔍 FRAMEWORK DE DETECÇÃO DE NOVOS FLUXOS VIA LOGS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Framework para detecção automática de novos fluxos via análise de logs.
Identifica cenários não testados baseados em logs reais de produção.

Tracing ID: FLOW_DETECTION_FRAMEWORK_20250127_001
Data/Hora: 2025-01-27T18:30:00Z
Versão: 1.0
"""

import time
import json
import logging
import threading
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import uuid
from collections import defaultdict, Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "FLOW_DETECTION_FRAMEWORK_20250127_001"

@dataclass
class LogEntry:
    """Entrada de log para análise."""
    timestamp: datetime
    level: str
    message: str
    service: str
    endpoint: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    tracing_id: str = TRACING_ID

@dataclass
class FlowPattern:
    """Padrão de fluxo detectado nos logs."""
    pattern_id: str
    name: str
    description: str
    endpoints: List[str]
    services: List[str]
    frequency: int
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    is_tested: bool
    test_suggestions: List[str]
    tracing_id: str = TRACING_ID

@dataclass
class FlowDetectionResult:
    """Resultado da detecção de fluxos."""
    detection_id: str
    timestamp: datetime
    total_logs_analyzed: int
    new_flows_detected: int
    existing_flows_updated: int
    test_suggestions_generated: int
    high_risk_flows: List[str]
    untested_flows: List[str]
    tracing_id: str = TRACING_ID

@dataclass
class LogSource:
    """Configuração de fonte de logs."""
    source_name: str
    source_type: str  # "file", "api", "database"
    source_path: str
    log_format: str
    enabled: bool
    filters: Dict[str, str]
    tracing_id: str = TRACING_ID

class FlowDetectionFramework:
    """
    Framework de detecção de novos fluxos via logs.
    
    Analisa logs reais para identificar fluxos não testados
    e gerar sugestões de testes automaticamente.
    """
    
    def __init__(self, db_path: str = "tests/integration/flow_detection.db"):
        self.tracing_id = TRACING_ID
        self.db_path = db_path
        self.active_detections: Dict[str, FlowDetectionResult] = {}
        self.results: List[FlowDetectionResult] = []
        self.lock = threading.Lock()
        
        # Configuração de fontes de logs (baseado em código real do Omni Writer)
        self.log_sources = self._load_log_sources()
        
        # Padrões conhecidos de fluxos testados
        self.known_flows = self._load_known_flows()
        
        # Configuração de análise
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # Inicializa banco de dados
        self._init_database()
        
        logger.info(f"[{self.tracing_id}] FlowDetectionFramework inicializado")
        logger.info(f"[{self.tracing_id}] Fontes de log: {len(self.log_sources)}")
        logger.info(f"[{self.tracing_id}] Fluxos conhecidos: {len(self.known_flows)}")
    
    def _load_log_sources(self) -> List[LogSource]:
        """
        Carrega configuração de fontes de logs baseada em código real.
        
        Fontes identificadas através de análise do código do Omni Writer:
        - Logs de aplicação (Flask)
        - Logs de acesso (nginx/apache)
        - Logs de erro (error logs)
        - Logs de performance (metrics)
        """
        return [
            LogSource(
                source_name="application_logs",
                source_type="file",
                source_path="/var/log/omni_writer/app.log",
                log_format="json",
                enabled=True,
                filters={
                    "level": "INFO,ERROR,WARNING",
                    "service": "omni_writer"
                }
            ),
            LogSource(
                source_name="access_logs",
                source_type="file",
                source_path="/var/log/nginx/access.log",
                log_format="combined",
                enabled=True,
                filters={
                    "status_code": "200,201,400,401,403,404,500",
                    "method": "GET,POST,PUT,DELETE"
                }
            ),
            LogSource(
                source_name="error_logs",
                source_type="file",
                source_path="/var/log/omni_writer/error.log",
                log_format="json",
                enabled=True,
                filters={
                    "level": "ERROR,CRITICAL"
                }
            ),
            LogSource(
                source_name="performance_logs",
                source_type="file",
                source_path="/var/log/omni_writer/performance.log",
                log_format="json",
                enabled=True,
                filters={
                    "response_time": ">1000"
                }
            )
        ]
    
    def _load_known_flows(self) -> Dict[str, FlowPattern]:
        """
        Carrega fluxos conhecidos baseados em testes existentes.
        
        Fluxos extraídos dos testes reais do Omni Writer:
        - Fluxo de geração de artigos
        - Fluxo de CRUD de blogs
        - Fluxo de download/exportação
        - Fluxo de autenticação
        """
        return {
            "article_generation_flow": FlowPattern(
                pattern_id="article_generation_flow",
                name="Geração de Artigos",
                description="Fluxo completo de geração de artigos via OpenAI",
                endpoints=["/generate", "/status", "/download"],
                services=["openai_gateway", "generation_service"],
                frequency=100,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                risk_score=150,
                is_tested=True,
                test_suggestions=[]
            ),
            "blog_crud_flow": FlowPattern(
                pattern_id="blog_crud_flow",
                name="CRUD de Blogs",
                description="Operações CRUD completas de blogs",
                endpoints=["/blogs", "/blogs/create", "/blogs/update", "/blogs/delete"],
                services=["blog_service", "postgresql"],
                frequency=50,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                risk_score=120,
                is_tested=True,
                test_suggestions=[]
            ),
            "authentication_flow": FlowPattern(
                pattern_id="authentication_flow",
                name="Autenticação",
                description="Fluxo de login/logout e autenticação",
                endpoints=["/login", "/logout", "/auth"],
                services=["auth_service", "redis"],
                frequency=200,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                risk_score=100,
                is_tested=True,
                test_suggestions=[]
            ),
            "payment_flow": FlowPattern(
                pattern_id="payment_flow",
                name="Processamento de Pagamentos",
                description="Fluxo de pagamentos via Stripe",
                endpoints=["/payment", "/webhook"],
                services=["stripe_gateway", "payment_service"],
                frequency=30,
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                risk_score=140,
                is_tested=True,
                test_suggestions=[]
            )
        }
    
    def _init_database(self):
        """Inicializa banco de dados SQLite para detecção de fluxos."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de entradas de log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    entry_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    service TEXT NOT NULL,
                    endpoint TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    request_id TEXT,
                    metadata TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de padrões de fluxo
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flow_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    endpoints TEXT NOT NULL,
                    services TEXT NOT NULL,
                    frequency INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    is_tested BOOLEAN NOT NULL,
                    test_suggestions TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de resultados de detecção
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS flow_detection_results (
                    detection_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    total_logs_analyzed INTEGER NOT NULL,
                    new_flows_detected INTEGER NOT NULL,
                    existing_flows_updated INTEGER NOT NULL,
                    test_suggestions_generated INTEGER NOT NULL,
                    high_risk_flows TEXT,
                    untested_flows TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insere fluxos conhecidos
            for flow_id, flow in self.known_flows.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO flow_patterns (
                        pattern_id, name, description, endpoints, services,
                        frequency, first_seen, last_seen, risk_score,
                        is_tested, test_suggestions, tracing_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    flow.pattern_id, flow.name, flow.description,
                    json.dumps(flow.endpoints), json.dumps(flow.services),
                    flow.frequency, flow.first_seen.isoformat(),
                    flow.last_seen.isoformat(), flow.risk_score,
                    flow.is_tested, json.dumps(flow.test_suggestions),
                    flow.tracing_id
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"[{self.tracing_id}] Banco de dados inicializado: {self.db_path}")
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao inicializar banco: {e}")
    
    def _parse_log_entry(self, log_line: str, source: LogSource) -> Optional[LogEntry]:
        """
        Parse uma linha de log baseado no formato da fonte.
        
        Args:
            log_line: Linha de log
            source: Configuração da fonte
            
        Returns:
            Entrada de log parseada ou None se inválida
        """
        try:
            if source.log_format == "json":
                data = json.loads(log_line)
                return LogEntry(
                    timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat())),
                    level=data.get("level", "INFO"),
                    message=data.get("message", ""),
                    service=data.get("service", "unknown"),
                    endpoint=data.get("endpoint"),
                    user_id=data.get("user_id"),
                    session_id=data.get("session_id"),
                    request_id=data.get("request_id"),
                    metadata=data.get("metadata", {})
                )
            
            elif source.log_format == "combined":
                # Parse formato nginx combined
                parts = log_line.split()
                if len(parts) >= 9:
                    return LogEntry(
                        timestamp=datetime.strptime(f"{parts[3]} {parts[4]}", "[%d/%b/%Y:%H:%M:%S %z]"),
                        level="INFO",
                        message=log_line,
                        service="nginx",
                        endpoint=parts[6],
                        metadata={
                            "method": parts[5][1:],
                            "status_code": parts[8],
                            "user_agent": " ".join(parts[11:])
                        }
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao parsear log: {e}")
            return None
    
    def _extract_flow_patterns(self, log_entries: List[LogEntry]) -> List[FlowPattern]:
        """
        Extrai padrões de fluxo dos logs.
        
        Args:
            log_entries: Lista de entradas de log
            
        Returns:
            Lista de padrões de fluxo detectados
        """
        patterns = []
        
        # Agrupa logs por request_id para identificar fluxos
        request_groups = defaultdict(list)
        for entry in log_entries:
            if entry.request_id:
                request_groups[entry.request_id].append(entry)
        
        # Analisa cada grupo de request
        for request_id, entries in request_groups.items():
            if len(entries) < 2:  # Precisa de pelo menos 2 entradas para formar fluxo
                continue
            
            # Ordena por timestamp
            entries.sort(key=lambda x: x.timestamp)
            
            # Extrai endpoints e serviços
            endpoints = [e.endpoint for e in entries if e.endpoint]
            services = [e.service for e in entries if e.service]
            
            if not endpoints:
                continue
            
            # Cria padrão de fluxo
            pattern_id = hashlib.md5(f"{request_id}_{endpoints[0]}".encode()).hexdigest()[:8]
            
            # Calcula frequência (simulado)
            frequency = len(request_groups)
            
            # Calcula risk score baseado nos serviços
            risk_score = self._calculate_flow_risk_score(endpoints, services)
            
            # Verifica se já é conhecido
            is_tested = self._is_flow_tested(endpoints, services)
            
            # Gera sugestões de teste
            test_suggestions = self._generate_test_suggestions(endpoints, services)
            
            pattern = FlowPattern(
                pattern_id=pattern_id,
                name=f"Fluxo {pattern_id}",
                description=f"Fluxo detectado: {' -> '.join(endpoints)}",
                endpoints=endpoints,
                services=list(set(services)),
                frequency=frequency,
                first_seen=entries[0].timestamp,
                last_seen=entries[-1].timestamp,
                risk_score=risk_score,
                is_tested=is_tested,
                test_suggestions=test_suggestions
            )
            
            patterns.append(pattern)
        
        return patterns
    
    def _calculate_flow_risk_score(self, endpoints: List[str], services: List[str]) -> int:
        """
        Calcula risk score para um fluxo baseado em endpoints e serviços.
        
        Args:
            endpoints: Lista de endpoints
            services: Lista de serviços
            
        Returns:
            Risk score calculado
        """
        score = 0
        
        # Pontuação por endpoints críticos
        critical_endpoints = ["/generate", "/payment", "/webhook", "/download"]
        for endpoint in endpoints:
            if endpoint in critical_endpoints:
                score += 30
        
        # Pontuação por serviços críticos
        critical_services = ["openai_gateway", "stripe_gateway", "postgresql"]
        for service in services:
            if service in critical_services:
                score += 25
        
        # Pontuação por complexidade (número de endpoints)
        score += len(endpoints) * 10
        
        return score
    
    def _is_flow_tested(self, endpoints: List[str], services: List[str]) -> bool:
        """
        Verifica se um fluxo já é testado.
        
        Args:
            endpoints: Lista de endpoints
            services: Lista de serviços
            
        Returns:
            True se o fluxo é testado
        """
        # Compara com fluxos conhecidos
        for known_flow in self.known_flows.values():
            if known_flow.is_tested:
                # Verifica se endpoints e serviços coincidem
                endpoint_match = any(ep in known_flow.endpoints for ep in endpoints)
                service_match = any(sv in known_flow.services for sv in services)
                
                if endpoint_match and service_match:
                    return True
        
        return False
    
    def _generate_test_suggestions(self, endpoints: List[str], services: List[str]) -> List[str]:
        """
        Gera sugestões de teste para um fluxo.
        
        Args:
            endpoints: Lista de endpoints
            services: Lista de serviços
            
        Returns:
            Lista de sugestões de teste
        """
        suggestions = []
        
        # Sugestões baseadas em endpoints
        if "/generate" in endpoints:
            suggestions.append("Implementar teste de geração de artigos com diferentes prompts")
        
        if "/payment" in endpoints:
            suggestions.append("Implementar teste de processamento de pagamentos com diferentes métodos")
        
        if "/download" in endpoints:
            suggestions.append("Implementar teste de download com diferentes tipos de arquivo")
        
        # Sugestões baseadas em serviços
        if "openai_gateway" in services:
            suggestions.append("Implementar teste de fallback para falhas da OpenAI")
        
        if "stripe_gateway" in services:
            suggestions.append("Implementar teste de webhooks do Stripe")
        
        if "postgresql" in services:
            suggestions.append("Implementar teste de transações de banco de dados")
        
        # Sugestões gerais
        if len(endpoints) > 3:
            suggestions.append("Implementar teste de fluxo completo end-to-end")
        
        if len(services) > 2:
            suggestions.append("Implementar teste de integração entre múltiplos serviços")
        
        return suggestions
    
    def analyze_logs(self, log_file_path: str, source_name: str = "application_logs") -> FlowDetectionResult:
        """
        Analisa logs para detectar novos fluxos.
        
        Args:
            log_file_path: Caminho do arquivo de log
            source_name: Nome da fonte de log
            
        Returns:
            Resultado da detecção de fluxos
        """
        detection_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        logger.info(f"[{self.tracing_id}] Analisando logs: {log_file_path}")
        
        try:
            # Encontra configuração da fonte
            source = next((s for s in self.log_sources if s.source_name == source_name), None)
            if not source:
                raise ValueError(f"Fonte de log não encontrada: {source_name}")
            
            # Lê e parseia logs
            log_entries = []
            with open(log_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = self._parse_log_entry(line.strip(), source)
                    if entry:
                        log_entries.append(entry)
            
            # Extrai padrões de fluxo
            new_patterns = self._extract_flow_patterns(log_entries)
            
            # Identifica novos fluxos
            new_flows = []
            existing_flows_updated = 0
            
            for pattern in new_patterns:
                if pattern.pattern_id not in self.known_flows:
                    new_flows.append(pattern)
                    self.known_flows[pattern.pattern_id] = pattern
                else:
                    # Atualiza fluxo existente
                    existing_flow = self.known_flows[pattern.pattern_id]
                    existing_flow.frequency += pattern.frequency
                    existing_flow.last_seen = pattern.last_seen
                    existing_flows_updated += 1
            
            # Identifica fluxos de alto risco não testados
            high_risk_flows = [
                flow.pattern_id for flow in new_flows
                if flow.risk_score >= 100 and not flow.is_tested
            ]
            
            untested_flows = [
                flow.pattern_id for flow in new_flows
                if not flow.is_tested
            ]
            
            # Gera sugestões de teste
            test_suggestions_generated = sum(
                len(flow.test_suggestions) for flow in new_flows
            )
            
            # Cria resultado
            result = FlowDetectionResult(
                detection_id=detection_id,
                timestamp=timestamp,
                total_logs_analyzed=len(log_entries),
                new_flows_detected=len(new_flows),
                existing_flows_updated=existing_flows_updated,
                test_suggestions_generated=test_suggestions_generated,
                high_risk_flows=high_risk_flows,
                untested_flows=untested_flows
            )
            
            # Salva resultados
            self._save_detection_result(result)
            self._save_new_patterns(new_flows)
            
            logger.info(f"[{self.tracing_id}] Análise concluída: {len(new_flows)} novos fluxos detectados")
            
            return result
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro na análise: {e}")
            
            result = FlowDetectionResult(
                detection_id=detection_id,
                timestamp=timestamp,
                total_logs_analyzed=0,
                new_flows_detected=0,
                existing_flows_updated=0,
                test_suggestions_generated=0,
                high_risk_flows=[],
                untested_flows=[]
            )
            
            self._save_detection_result(result)
            return result
    
    def _save_detection_result(self, result: FlowDetectionResult):
        """Salva resultado de detecção no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO flow_detection_results (
                    detection_id, timestamp, total_logs_analyzed, new_flows_detected,
                    existing_flows_updated, test_suggestions_generated,
                    high_risk_flows, untested_flows, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.detection_id, result.timestamp.isoformat(),
                result.total_logs_analyzed, result.new_flows_detected,
                result.existing_flows_updated, result.test_suggestions_generated,
                json.dumps(result.high_risk_flows), json.dumps(result.untested_flows),
                result.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar resultado: {e}")
    
    def _save_new_patterns(self, patterns: List[FlowPattern]):
        """Salva novos padrões no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for pattern in patterns:
                cursor.execute('''
                    INSERT OR REPLACE INTO flow_patterns (
                        pattern_id, name, description, endpoints, services,
                        frequency, first_seen, last_seen, risk_score,
                        is_tested, test_suggestions, tracing_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.pattern_id, pattern.name, pattern.description,
                    json.dumps(pattern.endpoints), json.dumps(pattern.services),
                    pattern.frequency, pattern.first_seen.isoformat(),
                    pattern.last_seen.isoformat(), pattern.risk_score,
                    pattern.is_tested, json.dumps(pattern.test_suggestions),
                    pattern.tracing_id
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar padrões: {e}")
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Gera relatório completo de detecção de fluxos.
        
        Returns:
            Relatório em formato JSON
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Estatísticas gerais
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_patterns,
                    SUM(CASE WHEN is_tested THEN 1 ELSE 0 END) as tested_patterns,
                    SUM(CASE WHEN risk_score >= 100 THEN 1 ELSE 0 END) as high_risk_patterns,
                    AVG(risk_score) as avg_risk_score
                FROM flow_patterns
            ''')
            
            stats = cursor.fetchone()
            
            # Fluxos não testados de alto risco
            cursor.execute('''
                SELECT pattern_id, name, description, risk_score, test_suggestions
                FROM flow_patterns
                WHERE is_tested = FALSE AND risk_score >= 100
                ORDER BY risk_score DESC
                LIMIT 10
            ''')
            
            high_risk_untested = [
                {
                    "pattern_id": row[0],
                    "name": row[1],
                    "description": row[2],
                    "risk_score": row[3],
                    "suggestions": json.loads(row[4]) if row[4] else []
                }
                for row in cursor.fetchall()
            ]
            
            # Fluxos mais frequentes
            cursor.execute('''
                SELECT name, frequency, risk_score, is_tested
                FROM flow_patterns
                ORDER BY frequency DESC
                LIMIT 10
            ''')
            
            most_frequent = [
                {
                    "name": row[0],
                    "frequency": row[1],
                    "risk_score": row[2],
                    "is_tested": bool(row[3])
                }
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                "tracing_id": self.tracing_id,
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_patterns": stats[0] or 0,
                    "tested_patterns": stats[1] or 0,
                    "high_risk_patterns": stats[2] or 0,
                    "avg_risk_score": stats[3] or 0.0,
                    "coverage_rate": (stats[1] / stats[0] * 100) if stats[0] > 0 else 0
                },
                "high_risk_untested": high_risk_untested,
                "most_frequent_flows": most_frequent,
                "log_sources": [
                    {
                        "name": source.source_name,
                        "type": source.source_type,
                        "enabled": source.enabled
                    }
                    for source in self.log_sources
                ]
            }
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao gerar relatório: {e}")
            return {"error": str(e)}

# Instância global do framework
flow_detection = FlowDetectionFramework()

def analyze_logs_for_flows(log_file_path: str, source_name: str = "application_logs"):
    """Analisa logs para detectar novos fluxos."""
    return flow_detection.analyze_logs(log_file_path, source_name)

def get_flow_detection_report():
    """Retorna relatório de detecção de fluxos."""
    return flow_detection.generate_report()

if __name__ == "__main__":
    # Teste do framework
    logger.info(f"[{TRACING_ID}] Testando framework de detecção de fluxos")
    
    # Exemplo de análise de logs
    result = analyze_logs_for_flows(
        log_file_path="tests/integration/sample_logs.json",
        source_name="application_logs"
    )
    
    # Gera relatório
    report = get_flow_detection_report()
    
    print(json.dumps(report, indent=2)) 