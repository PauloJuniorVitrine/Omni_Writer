"""
Auto Checklist Generator - Omni Writer
======================================

Sistema de geração automática de checklists baseado em fluxos testados.
Analisa métricas e gera checklists personalizados para validação.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 13
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:05:00Z
"""

import os
import json
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
from jinja2 import Template

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('auto_checklist')

@dataclass
class ChecklistItem:
    """Item de checklist."""
    id: str
    category: str
    description: str
    status: str  # 'pending', 'passed', 'failed', 'warning'
    priority: str  # 'low', 'medium', 'high', 'critical'
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    notes: str = ""
    timestamp: datetime = None

@dataclass
class ChecklistTemplate:
    """Template para geração de checklists."""
    name: str
    description: str
    categories: List[str]
    rules: List[Dict[str, Any]]
    conditions: List[Dict[str, Any]]

class AutoChecklistGenerator:
    """
    Gerador automático de checklists baseado em fluxos testados e métricas.
    """
    
    def __init__(self, 
                 results_dir: str = "tests/load/results",
                 templates_dir: str = "tests/load/checklists/templates"):
        """
        Inicializa o gerador de checklists automáticos.
        
        Args:
            results_dir: Diretório com resultados dos testes
            templates_dir: Diretório com templates de checklist
        """
        self.results_dir = Path(results_dir)
        self.templates_dir = Path(templates_dir)
        self.output_dir = Path("tests/load/checklists/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Histórico de checklists gerados
        self.generated_checklists: List[Dict[str, Any]] = []
        
        # Configurações
        self.checklist_config = {
            "auto_generate": True,
            "include_metrics": True,
            "include_recommendations": True,
            "max_items_per_category": 20,
            "priority_thresholds": {
                "critical": 0.95,  # 95% de falha = crítico
                "high": 0.8,       # 80% de falha = alto
                "medium": 0.5,     # 50% de falha = médio
                "low": 0.2         # 20% de falha = baixo
            }
        }
        
        # Templates padrão baseados no código real
        self.default_templates = self._create_default_templates()
        
        # Carrega templates customizados
        self.templates = self.load_templates()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Diretório de resultados: {self.results_dir}")
        logger.info(f"Templates carregados: {len(self.templates)}")

    def _create_default_templates(self) -> Dict[str, ChecklistTemplate]:
        """
        Cria templates padrão baseados nos fluxos críticos identificados.
        """
        templates = {}
        
        # Template para testes de geração
        templates['generate_test'] = ChecklistTemplate(
            name="Generate Test Checklist",
            description="Checklist para validação de testes de geração de artigos",
            categories=["performance", "reliability", "security", "monitoring"],
            rules=[
                {
                    "metric": "response_time_avg",
                    "threshold": 800,
                    "operator": "lt",
                    "priority": "high",
                    "description": "Tempo de resposta médio deve ser menor que 800ms"
                },
                {
                    "metric": "error_rate",
                    "threshold": 0.02,
                    "operator": "lt",
                    "priority": "critical",
                    "description": "Taxa de erro deve ser menor que 2%"
                },
                {
                    "metric": "throughput",
                    "threshold": 10,
                    "operator": "gt",
                    "priority": "medium",
                    "description": "Throughput deve ser maior que 10 req/s"
                }
            ],
            conditions=[
                {
                    "test_type": "generate",
                    "min_users": 10,
                    "min_duration": "2m"
                }
            ]
        )
        
        # Template para testes de download
        templates['download_test'] = ChecklistTemplate(
            name="Download Test Checklist",
            description="Checklist para validação de testes de download",
            categories=["performance", "reliability", "storage"],
            rules=[
                {
                    "metric": "response_time_avg",
                    "threshold": 2000,
                    "operator": "lt",
                    "priority": "high",
                    "description": "Tempo de download deve ser menor que 2s"
                },
                {
                    "metric": "error_rate",
                    "threshold": 0.01,
                    "operator": "lt",
                    "priority": "critical",
                    "description": "Taxa de erro deve ser menor que 1%"
                }
            ],
            conditions=[
                {
                    "test_type": "download",
                    "min_users": 5,
                    "min_duration": "1m"
                }
            ]
        )
        
        # Template para testes multi-tenant
        templates['multitenant_test'] = ChecklistTemplate(
            name="Multi-tenant Test Checklist",
            description="Checklist para validação de testes multi-tenant",
            categories=["isolation", "security", "performance", "scalability"],
            rules=[
                {
                    "metric": "tenant_isolation_score",
                    "threshold": 0.95,
                    "operator": "gt",
                    "priority": "critical",
                    "description": "Isolamento entre tenants deve ser maior que 95%"
                },
                {
                    "metric": "resource_contention",
                    "threshold": 0.1,
                    "operator": "lt",
                    "priority": "high",
                    "description": "Contenção de recursos deve ser menor que 10%"
                }
            ],
            conditions=[
                {
                    "test_type": "multitenant",
                    "min_tenants": 3,
                    "min_users_per_tenant": 10
                }
            ]
        )
        
        return templates

    def load_templates(self) -> Dict[str, ChecklistTemplate]:
        """
        Carrega templates de checklist.
        """
        templates = self.default_templates.copy()
        
        # Carrega templates customizados se existirem
        if self.templates_dir.exists():
            for template_file in self.templates_dir.glob("*.json"):
                try:
                    with open(template_file, 'r', encoding='utf-8') as f:
                        template_data = json.load(f)
                    
                    template = ChecklistTemplate(**template_data)
                    templates[template.name] = template
                    logger.info(f"Template carregado: {template.name}")
                    
                except Exception as e:
                    logger.error(f"Erro ao carregar template {template_file}: {e}")
        
        return templates

    def analyze_test_results(self, test_type: str = None) -> Dict[str, Any]:
        """
        Analisa resultados de testes para gerar checklist.
        """
        logger.info("Analisando resultados de testes...")
        
        analysis_results = {
            'test_summary': {},
            'metrics': {},
            'anomalies': [],
            'recommendations': []
        }
        
        # Busca arquivos CSV de resultados
        csv_files = list(self.results_dir.glob("*.csv"))
        
        if not csv_files:
            logger.warning("Nenhum arquivo CSV encontrado")
            return analysis_results
        
        # Filtra por tipo de teste se especificado
        if test_type:
            csv_files = [f for f in csv_files if test_type in f.name.lower()]
        
        for csv_file in csv_files:
            try:
                logger.info(f"Analisando: {csv_file}")
                
                df = pd.read_csv(csv_file)
                if df.empty:
                    continue
                
                # Extrai tipo de teste do nome do arquivo
                file_test_type = csv_file.stem.split('_')[0]
                
                # Calcula métricas
                metrics = self._calculate_metrics(df)
                
                # Identifica anomalias
                anomalies = self._detect_anomalies(metrics, file_test_type)
                
                # Gera recomendações
                recommendations = self._generate_recommendations(metrics, anomalies)
                
                # Adiciona ao resultado
                analysis_results['test_summary'][file_test_type] = {
                    'file': csv_file.name,
                    'total_requests': len(df),
                    'metrics': metrics
                }
                
                analysis_results['metrics'].update(metrics)
                analysis_results['anomalies'].extend(anomalies)
                analysis_results['recommendations'].extend(recommendations)
                
            except Exception as e:
                logger.error(f"Erro ao analisar {csv_file}: {e}")
                continue
        
        logger.info(f"Análise concluída - {len(analysis_results['test_summary'])} testes processados")
        return analysis_results

    def _calculate_metrics(self, df: pd.DataFrame) -> Dict[str, float]:
        """
        Calcula métricas dos dados de teste.
        """
        metrics = {}
        
        try:
            # Métricas básicas
            if 'Average Response Time' in df.columns:
                metrics['response_time_avg'] = df['Average Response Time'].mean()
                metrics['response_time_p95'] = df['Average Response Time'].quantile(0.95)
                metrics['response_time_p99'] = df['Average Response Time'].quantile(0.99)
            
            if 'Failure Count' in df.columns and 'Request Count' in df.columns:
                total_failures = df['Failure Count'].sum()
                total_requests = df['Request Count'].sum()
                metrics['error_rate'] = total_failures / total_requests if total_requests > 0 else 0
            
            if 'Requests/s' in df.columns:
                metrics['throughput'] = df['Requests/s'].mean()
                metrics['throughput_max'] = df['Requests/s'].max()
            
            # Métricas derivadas
            if 'response_time_avg' in metrics and 'throughput' in metrics:
                metrics['efficiency_score'] = metrics['throughput'] / (metrics['response_time_avg'] / 1000)
            
            # Score de estabilidade
            if 'response_time_avg' in metrics and 'response_time_p95' in metrics:
                stability_ratio = metrics['response_time_p95'] / metrics['response_time_avg']
                metrics['stability_score'] = 1.0 / stability_ratio if stability_ratio > 0 else 0
            
        except Exception as e:
            logger.error(f"Erro ao calcular métricas: {e}")
        
        return metrics

    def _detect_anomalies(self, metrics: Dict[str, float], test_type: str) -> List[Dict[str, Any]]:
        """
        Detecta anomalias baseado nas métricas.
        """
        anomalies = []
        
        # Thresholds baseados no código real
        thresholds = {
            'response_time_avg': 800,
            'response_time_p95': 1500,
            'error_rate': 0.02,
            'throughput': 10
        }
        
        for metric, value in metrics.items():
            if metric in thresholds:
                threshold = thresholds[metric]
                
                # Determina se é anomalia baseado no tipo de métrica
                is_anomaly = False
                if metric in ['response_time_avg', 'response_time_p95']:
                    is_anomaly = value > threshold
                elif metric == 'error_rate':
                    is_anomaly = value > threshold
                elif metric == 'throughput':
                    is_anomaly = value < threshold
                
                if is_anomaly:
                    anomaly = {
                        'metric': metric,
                        'value': value,
                        'threshold': threshold,
                        'test_type': test_type,
                        'severity': 'high' if value > threshold * 1.5 else 'medium'
                    }
                    anomalies.append(anomaly)
        
        return anomalies

    def _generate_recommendations(self, metrics: Dict[str, float], anomalies: List[Dict[str, Any]]) -> List[str]:
        """
        Gera recomendações baseadas nas métricas e anomalias.
        """
        recommendations = []
        
        # Recomendações baseadas em anomalias
        for anomaly in anomalies:
            if anomaly['metric'] == 'response_time_avg':
                recommendations.append("Otimizar processamento de requisições para reduzir latência")
            elif anomaly['metric'] == 'error_rate':
                recommendations.append("Investigar causas dos erros e implementar correções")
            elif anomaly['metric'] == 'throughput':
                recommendations.append("Aumentar capacidade de processamento ou otimizar código")
        
        # Recomendações baseadas em métricas
        if 'stability_score' in metrics and metrics['stability_score'] < 0.8:
            recommendations.append("Melhorar estabilidade do sistema - alta variabilidade detectada")
        
        if 'efficiency_score' in metrics and metrics['efficiency_score'] < 1.0:
            recommendations.append("Otimizar eficiência do sistema - baixo throughput por latência")
        
        # Recomendações gerais
        if len(anomalies) > 3:
            recommendations.append("Realizar análise profunda de performance - múltiplas anomalias detectadas")
        
        return list(set(recommendations))  # Remove duplicatas

    def generate_checklist(self, template_name: str, analysis_results: Dict[str, Any]) -> List[ChecklistItem]:
        """
        Gera checklist baseado em template e resultados de análise.
        """
        logger.info(f"Gerando checklist usando template: {template_name}")
        
        if template_name not in self.templates:
            logger.error(f"Template não encontrado: {template_name}")
            return []
        
        template = self.templates[template_name]
        checklist_items = []
        
        # Gera itens baseados nas regras do template
        for rule in template.rules:
            metric = rule['metric']
            threshold = rule['threshold']
            operator = rule['operator']
            priority = rule['priority']
            description = rule['description']
            
            # Obtém valor da métrica
            metric_value = analysis_results['metrics'].get(metric, None)
            
            if metric_value is not None:
                # Avalia condição
                status = 'pending'
                if operator == 'lt':
                    status = 'passed' if metric_value < threshold else 'failed'
                elif operator == 'gt':
                    status = 'passed' if metric_value > threshold else 'failed'
                elif operator == 'eq':
                    status = 'passed' if abs(metric_value - threshold) < 0.01 else 'failed'
                
                # Ajusta prioridade baseado na severidade
                if status == 'failed':
                    if abs(metric_value - threshold) / threshold > 0.5:
                        priority = 'critical'
                    elif abs(metric_value - threshold) / threshold > 0.2:
                        priority = 'high'
                
                # Cria item de checklist
                item = ChecklistItem(
                    id=f"{template_name}_{metric}_{int(time.time())}",
                    category=template.categories[0] if template.categories else "general",
                    description=description,
                    status=status,
                    priority=priority,
                    metric_value=metric_value,
                    threshold=threshold,
                    timestamp=datetime.now()
                )
                
                checklist_items.append(item)
        
        # Adiciona itens baseados em anomalias
        for anomaly in analysis_results['anomalies']:
            item = ChecklistItem(
                id=f"anomaly_{anomaly['metric']}_{int(time.time())}",
                category="anomalies",
                description=f"Anomalia detectada em {anomaly['metric']}: {anomaly['value']:.2f}",
                status="failed",
                priority=anomaly['severity'],
                metric_value=anomaly['value'],
                threshold=anomaly['threshold'],
                notes=f"Teste: {anomaly['test_type']}",
                timestamp=datetime.now()
            )
            checklist_items.append(item)
        
        # Adiciona itens de recomendação
        for i, recommendation in enumerate(analysis_results['recommendations']):
            item = ChecklistItem(
                id=f"recommendation_{i}_{int(time.time())}",
                category="recommendations",
                description=recommendation,
                status="pending",
                priority="medium",
                timestamp=datetime.now()
            )
            checklist_items.append(item)
        
        logger.info(f"Checklist gerado com {len(checklist_items)} itens")
        return checklist_items

    def save_checklist(self, checklist_items: List[ChecklistItem], template_name: str) -> str:
        """
        Salva checklist em arquivo.
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            checklist_file = self.output_dir / f"checklist_{template_name}_{timestamp}.json"
            
            # Converte para formato serializável
            checklist_data = {
                'template_name': template_name,
                'generated_at': datetime.now().isoformat(),
                'total_items': len(checklist_items),
                'items': [asdict(item) for item in checklist_items],
                'summary': self._generate_checklist_summary(checklist_items)
            }
            
            with open(checklist_file, 'w', encoding='utf-8') as f:
                json.dump(checklist_data, f, indent=2, default=str)
            
            # Adiciona ao histórico
            self.generated_checklists.append(checklist_data)
            
            logger.info(f"Checklist salvo: {checklist_file}")
            return str(checklist_file)
            
        except Exception as e:
            logger.error(f"Erro ao salvar checklist: {e}")
            return ""

    def _generate_checklist_summary(self, checklist_items: List[ChecklistItem]) -> Dict[str, Any]:
        """
        Gera resumo do checklist.
        """
        summary = {
            'total_items': len(checklist_items),
            'passed': len([item for item in checklist_items if item.status == 'passed']),
            'failed': len([item for item in checklist_items if item.status == 'failed']),
            'pending': len([item for item in checklist_items if item.status == 'pending']),
            'critical_items': len([item for item in checklist_items if item.priority == 'critical']),
            'high_priority_items': len([item for item in checklist_items if item.priority == 'high']),
            'categories': {}
        }
        
        # Agrupa por categoria
        for item in checklist_items:
            if item.category not in summary['categories']:
                summary['categories'][item.category] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'pending': 0
                }
            
            summary['categories'][item.category]['total'] += 1
            summary['categories'][item.category][item.status] += 1
        
        return summary

    def generate_html_report(self, checklist_items: List[ChecklistItem], template_name: str) -> str:
        """
        Gera relatório HTML do checklist.
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_file = self.output_dir / f"checklist_{template_name}_{timestamp}.html"
            
            # Template HTML
            html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Checklist Report - {{ template_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { background: #e8f4f8; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .passed { border-left: 5px solid #4CAF50; }
        .failed { border-left: 5px solid #f44336; }
        .pending { border-left: 5px solid #ff9800; }
        .critical { background: #ffebee; }
        .high { background: #fff3e0; }
        .medium { background: #f1f8e9; }
        .low { background: #fafafa; }
        .metric { font-weight: bold; color: #2196F3; }
        .status { font-weight: bold; }
        .status.passed { color: #4CAF50; }
        .status.failed { color: #f44336; }
        .status.pending { color: #ff9800; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Checklist Report - {{ template_name }}</h1>
        <p>Generated: {{ generated_at }}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Items:</strong> {{ summary.total_items }}</p>
        <p><strong>Passed:</strong> {{ summary.passed }} ({{ "%.1f"|format(summary.passed / summary.total_items * 100) }}%)</p>
        <p><strong>Failed:</strong> {{ summary.failed }} ({{ "%.1f"|format(summary.failed / summary.total_items * 100) }}%)</p>
        <p><strong>Pending:</strong> {{ summary.pending }} ({{ "%.1f"|format(summary.pending / summary.total_items * 100) }}%)</p>
        <p><strong>Critical Items:</strong> {{ summary.critical_items }}</p>
        <p><strong>High Priority Items:</strong> {{ summary.high_priority_items }}</p>
    </div>
    
    <h2>Checklist Items</h2>
    {% for item in items %}
    <div class="item {{ item.status }} {{ item.priority }}">
        <h3>{{ item.description }}</h3>
        <p><span class="status {{ item.status }}">{{ item.status.upper() }}</span> | 
           Priority: <strong>{{ item.priority.upper() }}</strong> | 
           Category: <strong>{{ item.category }}</strong></p>
        {% if item.metric_value is not none %}
        <p class="metric">Metric: {{ "%.2f"|format(item.metric_value) }}
           {% if item.threshold is not none %} | Threshold: {{ "%.2f"|format(item.threshold) }}{% endif %}</p>
        {% endif %}
        {% if item.notes %}
        <p><em>Notes: {{ item.notes }}</em></p>
        {% endif %}
        <p><small>Generated: {{ item.timestamp }}</small></p>
    </div>
    {% endfor %}
</body>
</html>
            """
            
            # Renderiza template
            template = Template(html_template)
            summary = self._generate_checklist_summary(checklist_items)
            
            html_content = template.render(
                template_name=template_name,
                generated_at=datetime.now().isoformat(),
                summary=summary,
                items=checklist_items
            )
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Relatório HTML gerado: {html_file}")
            return str(html_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório HTML: {e}")
            return ""

    def run_complete_checklist_generation(self) -> Dict[str, str]:
        """
        Executa geração completa de checklists para todos os templates.
        """
        logger.info("Iniciando geração completa de checklists...")
        
        generated_files = {}
        
        # Analisa resultados
        analysis_results = self.analyze_test_results()
        
        if not analysis_results['test_summary']:
            logger.warning("Nenhum resultado de teste encontrado")
            return generated_files
        
        # Gera checklists para cada template
        for template_name in self.templates.keys():
            try:
                # Gera checklist
                checklist_items = self.generate_checklist(template_name, analysis_results)
                
                if checklist_items:
                    # Salva checklist JSON
                    json_file = self.save_checklist(checklist_items, template_name)
                    if json_file:
                        generated_files[f"{template_name}_json"] = json_file
                    
                    # Gera relatório HTML
                    html_file = self.generate_html_report(checklist_items, template_name)
                    if html_file:
                        generated_files[f"{template_name}_html"] = html_file
                
            except Exception as e:
                logger.error(f"Erro ao gerar checklist {template_name}: {e}")
        
        logger.info(f"Geração concluída - {len(generated_files)} arquivos criados")
        return generated_files


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Auto Checklist Generator...")
    
    generator = AutoChecklistGenerator()
    generated_files = generator.run_complete_checklist_generation()
    
    if generated_files:
        logger.info("Geração de checklists concluída com sucesso!")
        logger.info(f"Arquivos gerados: {list(generated_files.keys())}")
    else:
        logger.warning("Nenhum checklist foi gerado")


if __name__ == "__main__":
    main() 