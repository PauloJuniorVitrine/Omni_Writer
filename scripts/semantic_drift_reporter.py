#!/usr/bin/env python3
"""
📊 SEMANTIC DRIFT REPORTER - Sistema de Relatórios de Divergências Semânticas
Tracing ID: SEMANTIC_DRIFT_REPORTER_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Gerar relatórios detalhados de divergências semânticas entre
versões de schemas e fornecer insights para manutenção de contratos.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Importa o validador semântico
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from semantic_validator import SemanticValidator, SemanticField, SemanticDriftReport

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/semantic_drift_reporter.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('semantic_drift_reporter')

@dataclass
class DriftTrend:
    """Tendência de drift semântico ao longo do tempo."""
    schema_name: str
    dates: List[datetime]
    drift_scores: List[float]
    field_counts: List[int]
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    trend_strength: float  # 0-1

@dataclass
class DriftImpact:
    """Impacto de drift semântico."""
    schema_name: str
    impact_level: str  # 'low', 'medium', 'high', 'critical'
    affected_endpoints: List[str]
    risk_score: float
    mitigation_effort: str  # 'low', 'medium', 'high'
    estimated_issues: int

class SemanticDriftReporter:
    """
    Gerador de relatórios de divergências semânticas.
    
    Funcionalidades:
    - Analisa tendências de drift ao longo do tempo
    - Calcula impacto de divergências
    - Gera visualizações e insights
    - Sugere ações de mitigação
    """
    
    def __init__(self, 
                 reports_path: str = "reports/semantic_drift/",
                 history_days: int = 30):
        """
        Inicializa o reporter de drift semântico.
        
        Args:
            reports_path: Caminho para salvar relatórios
            history_days: Número de dias para análise histórica
        """
        self.reports_path = Path(reports_path)
        self.history_days = history_days
        self.validator = SemanticValidator()
        
        # Cria diretório se não existir
        self.reports_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"SemanticDriftReporter inicializado - History: {history_days} dias")
    
    def analyze_drift_history(self, schema_name: str) -> DriftTrend:
        """
        Analisa histórico de drift para um schema.
        
        Args:
            schema_name: Nome do schema
            
        Returns:
            Tendência de drift
        """
        # Busca relatórios históricos
        history_files = list(self.reports_path.glob(f"{schema_name}_*.json"))
        history_files.sort()
        
        dates = []
        drift_scores = []
        field_counts = []
        
        for file_path in history_files[-self.history_days:]:  # Últimos N dias
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                # Extrai data do nome do arquivo
                date_str = file_path.stem.split('_')[-1]
                date = datetime.fromisoformat(date_str)
                
                dates.append(date)
                drift_scores.append(report_data.get('drift_score', 0.0))
                field_counts.append(len(report_data.get('affected_fields', [])))
                
            except Exception as e:
                logger.error(f"Erro ao processar arquivo histórico {file_path}: {e}")
        
        # Calcula tendência
        trend_direction, trend_strength = self._calculate_trend(drift_scores)
        
        return DriftTrend(
            schema_name=schema_name,
            dates=dates,
            drift_scores=drift_scores,
            field_counts=field_counts,
            trend_direction=trend_direction,
            trend_strength=trend_strength
        )
    
    def _calculate_trend(self, values: List[float]) -> Tuple[str, float]:
        """Calcula direção e força da tendência."""
        if len(values) < 2:
            return 'stable', 0.0
        
        # Calcula correlação com tempo
        x = list(range(len(values)))
        correlation = np.corrcoef(x, values)[0, 1]
        
        if abs(correlation) < 0.1:
            return 'stable', abs(correlation)
        elif correlation > 0:
            return 'increasing', abs(correlation)
        else:
            return 'decreasing', abs(correlation)
    
    def calculate_drift_impact(self, 
                              drift_report: SemanticDriftReport,
                              schema_usage: Dict[str, List[str]] = None) -> DriftImpact:
        """
        Calcula impacto de um drift semântico.
        
        Args:
            drift_report: Relatório de drift
            schema_usage: Uso do schema em endpoints
            
        Returns:
            Impacto do drift
        """
        # Calcula score de risco baseado no drift
        risk_score = drift_report.drift_score
        
        # Ajusta baseado no número de campos afetados
        field_impact = min(len(drift_report.affected_fields) / 10, 1.0)
        risk_score = (risk_score + field_impact) / 2
        
        # Determina nível de impacto
        if risk_score < 0.2:
            impact_level = 'low'
        elif risk_score < 0.5:
            impact_level = 'medium'
        elif risk_score < 0.8:
            impact_level = 'high'
        else:
            impact_level = 'critical'
        
        # Estima esforço de mitigação
        if len(drift_report.affected_fields) < 3:
            mitigation_effort = 'low'
        elif len(drift_report.affected_fields) < 10:
            mitigation_effort = 'medium'
        else:
            mitigation_effort = 'high'
        
        # Estima número de problemas
        estimated_issues = len(drift_report.affected_fields) * 2  # 2 problemas por campo afetado
        
        # Identifica endpoints afetados
        affected_endpoints = []
        if schema_usage:
            affected_endpoints = schema_usage.get(drift_report.schema_name, [])
        
        return DriftImpact(
            schema_name=drift_report.schema_name,
            impact_level=impact_level,
            affected_endpoints=affected_endpoints,
            risk_score=risk_score,
            mitigation_effort=mitigation_effort,
            estimated_issues=estimated_issues
        )
    
    def generate_drift_visualization(self, 
                                   drift_trend: DriftTrend,
                                   output_path: str = None) -> str:
        """
        Gera visualização de tendência de drift.
        
        Args:
            drift_trend: Tendência de drift
            output_path: Caminho para salvar visualização
            
        Returns:
            Caminho da visualização gerada
        """
        if not drift_trend.dates:
            logger.warning(f"Nenhum dado histórico para {drift_trend.schema_name}")
            return ""
        
        # Configura estilo
        plt.style.use('seaborn-v0_8')
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Gráfico de drift score
        ax1.plot(drift_trend.dates, drift_trend.drift_scores, 
                marker='o', linewidth=2, markersize=6)
        ax1.set_title(f'Drift Semântico - {drift_trend.schema_name}', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Drift Score', fontsize=12)
        ax1.grid(True, alpha=0.3)
        
        # Adiciona linha de tendência
        if len(drift_trend.drift_scores) > 1:
            z = np.polyfit(range(len(drift_trend.drift_scores)), drift_trend.drift_scores, 1)
            p = np.poly1d(z)
            ax1.plot(drift_trend.dates, p(range(len(drift_trend.drift_scores))), 
                    "r--", alpha=0.8, label=f'Tendência: {drift_trend.trend_direction}')
            ax1.legend()
        
        # Gráfico de campos afetados
        ax2.bar(drift_trend.dates, drift_trend.field_counts, 
               alpha=0.7, color='orange')
        ax2.set_title('Campos Afetados', fontsize=12, fontweight='bold')
        ax2.set_ylabel('Número de Campos', fontsize=12)
        ax2.set_xlabel('Data', fontsize=12)
        ax2.grid(True, alpha=0.3)
        
        # Rotaciona labels do eixo X
        plt.setp(ax1.get_xticklabels(), rotation=45)
        plt.setp(ax2.get_xticklabels(), rotation=45)
        
        plt.tight_layout()
        
        # Salva visualização
        if output_path is None:
            output_path = self.reports_path / f"{drift_trend.schema_name}_drift_trend.png"
        
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Visualização salva em {output_path}")
        return str(output_path)
    
    def generate_comprehensive_report(self, 
                                    schemas_path: str = "shared/schemas/",
                                    include_visualizations: bool = True) -> Dict[str, Any]:
        """
        Gera relatório abrangente de drift semântico.
        
        Args:
            schemas_path: Caminho para schemas
            include_visualizations: Se deve incluir visualizações
            
        Returns:
            Relatório estruturado
        """
        schemas_dir = Path(schemas_path)
        schema_files = list(schemas_dir.glob('*.json')) + list(schemas_dir.glob('*.yaml')) + list(schemas_dir.glob('*.yml'))
        
        all_drift_reports = []
        all_impact_analyses = []
        drift_trends = []
        visualizations = []
        
        for schema_file in schema_files:
            try:
                schema_name = schema_file.stem
                
                # Carrega schema atual
                with open(schema_file, 'r', encoding='utf-8') as f:
                    if schema_file.suffix == '.json':
                        schema_data = json.load(f)
                    else:
                        import yaml
                        schema_data = yaml.safe_load(f)
                
                # Analisa semântica atual
                current_fields = self.validator.analyze_schema_semantics(schema_data, schema_name)
                
                # Busca schema de referência (versão anterior)
                reference_fields = self._get_reference_schema(schema_name)
                
                if reference_fields:
                    # Detecta drift
                    drift_report = self.validator.detect_semantic_drift(
                        current_fields, reference_fields, schema_name
                    )
                    all_drift_reports.append(drift_report)
                    
                    # Calcula impacto
                    impact = self.calculate_drift_impact(drift_report)
                    all_impact_analyses.append(impact)
                    
                    # Analisa tendência histórica
                    trend = self.analyze_drift_history(schema_name)
                    drift_trends.append(trend)
                    
                    # Gera visualização se solicitado
                    if include_visualizations and trend.dates:
                        viz_path = self.generate_drift_visualization(trend)
                        if viz_path:
                            visualizations.append(viz_path)
                
            except Exception as e:
                logger.error(f"Erro ao processar schema {schema_file}: {e}")
        
        # Calcula métricas gerais
        total_schemas = len(schema_files)
        schemas_with_drift = len([r for r in all_drift_reports if r.drift_detected])
        avg_drift_score = sum(r.drift_score for r in all_drift_reports) / len(all_drift_reports) if all_drift_reports else 0.0
        
        # Categoriza por nível de impacto
        impact_distribution = {
            'low': len([i for i in all_impact_analyses if i.impact_level == 'low']),
            'medium': len([i for i in all_impact_analyses if i.impact_level == 'medium']),
            'high': len([i for i in all_impact_analyses if i.impact_level == 'high']),
            'critical': len([i for i in all_impact_analyses if i.impact_level == 'critical'])
        }
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_schemas': total_schemas,
                'schemas_with_drift': schemas_with_drift,
                'drift_percentage': (schemas_with_drift / total_schemas * 100) if total_schemas > 0 else 0,
                'avg_drift_score': avg_drift_score,
                'impact_distribution': impact_distribution
            },
            'drift_reports': [asdict(report) for report in all_drift_reports],
            'impact_analyses': [asdict(impact) for impact in all_impact_analyses],
            'drift_trends': [asdict(trend) for trend in drift_trends],
            'visualizations': visualizations,
            'recommendations': self._generate_drift_recommendations(all_drift_reports, all_impact_analyses),
            'priority_actions': self._generate_priority_actions(all_impact_analyses)
        }
        
        # Salva relatório
        report_path = self.reports_path / f"comprehensive_drift_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Relatório abrangente salvo em {report_path}")
        return report
    
    def _get_reference_schema(self, schema_name: str) -> List[SemanticField]:
        """Obtém schema de referência (versão anterior)."""
        # Busca versão anterior nos relatórios históricos
        history_files = list(self.reports_path.glob(f"{schema_name}_*.json"))
        if not history_files:
            return []
        
        # Pega o arquivo mais recente
        latest_file = max(history_files, key=lambda x: x.stat().st_mtime)
        
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # Reconstrói campos semânticos
            reference_fields = []
            for field_data in report_data.get('reference_fields', []):
                field = SemanticField(
                    field_name=field_data['field_name'],
                    field_type=field_data['field_type'],
                    description=field_data['description']
                )
                reference_fields.append(field)
            
            return reference_fields
            
        except Exception as e:
            logger.error(f"Erro ao carregar schema de referência: {e}")
            return []
    
    def _generate_drift_recommendations(self, 
                                      drift_reports: List[SemanticDriftReport],
                                      impact_analyses: List[DriftImpact]) -> List[str]:
        """Gera recomendações baseadas nos relatórios de drift."""
        recommendations = []
        
        # Conta tipos de problemas
        high_drift_schemas = [r for r in drift_reports if r.drift_score > 0.5]
        critical_impact = [i for i in impact_analyses if i.impact_level == 'critical']
        
        if critical_impact:
            recommendations.append(f"ATENÇÃO: {len(critical_impact)} schemas com impacto crítico")
            recommendations.append("Priorizar correção imediata destes schemas")
        
        if high_drift_schemas:
            recommendations.append(f"Revisar {len(high_drift_schemas)} schemas com alto drift semântico")
        
        # Recomendações baseadas em tendências
        increasing_trends = [r for r in drift_reports if r.drift_score > 0.3]
        if increasing_trends:
            recommendations.append("Implementar processo de revisão semântica regular")
        
        # Recomendações de mitigação
        high_effort = [i for i in impact_analyses if i.mitigation_effort == 'high']
        if high_effort:
            recommendations.append(f"Planejar esforço de mitigação para {len(high_effort)} schemas")
        
        if not recommendations:
            recommendations.append("Drift semântico está sob controle")
        
        return recommendations
    
    def _generate_priority_actions(self, impact_analyses: List[DriftImpact]) -> List[Dict[str, Any]]:
        """Gera ações prioritárias baseadas no impacto."""
        # Ordena por score de risco
        sorted_impacts = sorted(impact_analyses, key=lambda x: x.risk_score, reverse=True)
        
        priority_actions = []
        for i, impact in enumerate(sorted_impacts[:5]):  # Top 5
            action = {
                'priority': i + 1,
                'schema_name': impact.schema_name,
                'action': self._get_action_for_impact(impact),
                'estimated_effort': impact.mitigation_effort,
                'risk_score': impact.risk_score,
                'affected_endpoints': len(impact.affected_endpoints)
            }
            priority_actions.append(action)
        
        return priority_actions
    
    def _get_action_for_impact(self, impact: DriftImpact) -> str:
        """Determina ação baseada no nível de impacto."""
        if impact.impact_level == 'critical':
            return "Correção imediata - Revisar e corrigir schema"
        elif impact.impact_level == 'high':
            return "Revisão urgente - Analisar e planejar correção"
        elif impact.impact_level == 'medium':
            return "Monitoramento - Acompanhar evolução do drift"
        else:
            return "Manutenção - Revisar quando possível"
    
    def save_drift_snapshot(self, 
                           schema_name: str, 
                           current_fields: List[SemanticField],
                           drift_report: SemanticDriftReport) -> str:
        """
        Salva snapshot do drift para análise histórica.
        
        Args:
            schema_name: Nome do schema
            current_fields: Campos atuais
            drift_report: Relatório de drift
            
        Returns:
            Caminho do snapshot salvo
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        snapshot_path = self.reports_path / f"{schema_name}_{timestamp}.json"
        
        snapshot_data = {
            'schema_name': schema_name,
            'timestamp': datetime.now().isoformat(),
            'current_fields': [asdict(field) for field in current_fields],
            'drift_report': asdict(drift_report),
            'metadata': {
                'total_fields': len(current_fields),
                'affected_fields': len(drift_report.affected_fields),
                'drift_score': drift_report.drift_score
            }
        }
        
        with open(snapshot_path, 'w', encoding='utf-8') as f:
            json.dump(snapshot_data, f, indent=2, default=str)
        
        logger.info(f"Snapshot salvo em {snapshot_path}")
        return str(snapshot_path)

# Instância global
drift_reporter = SemanticDriftReporter()

def get_semantic_drift_reporter() -> SemanticDriftReporter:
    """Retorna instância global do reporter de drift semântico."""
    return drift_reporter

if __name__ == "__main__":
    # Teste do sistema
    reporter = SemanticDriftReporter()
    
    # Testa análise de drift
    print("📊 Testando SemanticDriftReporter...")
    
    # Simula dados de teste
    test_fields = [
        SemanticField("user_id", "integer", "Identificador do usuário"),
        SemanticField("email", "string", "Email do usuário"),
        SemanticField("created_at", "datetime", "Data de criação")
    ]
    
    reference_fields = [
        SemanticField("user_id", "integer", "ID do usuário"),
        SemanticField("email", "string", "Endereço de email"),
        SemanticField("created_at", "datetime", "Timestamp de criação")
    ]
    
    # Detecta drift
    drift_report = reporter.validator.detect_semantic_drift(
        test_fields, reference_fields, "test_schema"
    )
    
    print(f"✅ Drift detectado: {drift_report.drift_detected}")
    print(f"📈 Score de drift: {drift_report.drift_score:.2f}")
    print(f"🎯 Campos afetados: {len(drift_report.affected_fields)}")
    
    # Calcula impacto
    impact = reporter.calculate_drift_impact(drift_report)
    print(f"⚠️ Nível de impacto: {impact.impact_level}")
    print(f"🔧 Esforço de mitigação: {impact.mitigation_effort}")
    
    print("✅ SemanticDriftReporter testado com sucesso!") 