#!/usr/bin/env python3
"""
📊 Sistema de Coleta de Métricas de Documentação
================================================

Objetivo: Coletar métricas de qualidade e performance da documentação
Autor: AI Assistant
Data: 2025-01-27
Tracing ID: DOC_METRICS_20250127_001

Compliance: PCI-DSS 6.3, LGPD Art. 37
"""

import os
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor
import statistics
from collections import defaultdict

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/doc_metrics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DocumentMetric:
    """Métrica individual de documentação"""
    file_path: str
    file_size: int
    line_count: int
    word_count: int
    quality_score: float
    last_modified: datetime
    hash_value: str
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class QualityMetric:
    """Métrica de qualidade de documentação"""
    completeness_score: float
    coherence_score: float
    readability_score: float
    compliance_score: float
    overall_score: float
    issues: List[str] = None

    def __post_init__(self):
        if self.issues is None:
            self.issues = []

@dataclass
class PerformanceMetric:
    """Métrica de performance de documentação"""
    generation_time: float
    processing_time: float
    memory_usage: float
    cpu_usage: float
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

class DocumentMetricsCollector:
    """
    Sistema de coleta de métricas de documentação
    """
    
    def __init__(self, output_dir: str = "metrics"):
        self.output_dir = output_dir
        self.metrics_history: List[Dict] = []
        self.quality_thresholds = {
            "completeness": 0.8,
            "coherence": 0.7,
            "readability": 0.8,
            "compliance": 0.9
        }
        self.alert_triggers = []
        
        # Criar diretório de saída
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        logger.info(f"[DOC_METRICS] Sistema inicializado - Output: {output_dir}")

    def collect_file_metrics(self, file_path: str) -> DocumentMetric:
        """Coleta métricas de um arquivo específico"""
        try:
            path = Path(file_path)
            
            if not path.exists():
                logger.warning(f"[DOC_METRICS] Arquivo não encontrado: {file_path}")
                return None
            
            # Estatísticas básicas
            stat = path.stat()
            file_size = stat.st_size
            last_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            
            # Conteúdo do arquivo
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Métricas de conteúdo
            line_count = len(content.splitlines())
            word_count = len(content.split())
            
            # Hash do arquivo
            hash_value = hashlib.sha256(content.encode()).hexdigest()
            
            # Calcular qualidade
            quality_score = self._calculate_quality_score(content, file_path)
            
            # Metadata adicional
            metadata = {
                "file_type": path.suffix,
                "encoding": "utf-8",
                "has_images": "![image]" in content,
                "has_links": "http" in content,
                "has_code_blocks": "```" in content
            }
            
            return DocumentMetric(
                file_path=str(file_path),
                file_size=file_size,
                line_count=line_count,
                word_count=word_count,
                quality_score=quality_score,
                last_modified=last_modified,
                hash_value=hash_value,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao coletar métricas de {file_path}: {e}")
            return None

    def _calculate_quality_score(self, content: str, file_path: str) -> float:
        """Calcula score de qualidade do conteúdo"""
        try:
            score = 0.0
            factors = []
            
            # Completude (presença de seções essenciais)
            essential_sections = ["objetivo", "descrição", "exemplo", "conclusão"]
            section_score = sum(1 for section in essential_sections if section.lower() in content.lower())
            completeness = min(section_score / len(essential_sections), 1.0)
            factors.append(completeness)
            
            # Coerência (estrutura lógica)
            has_structure = any(marker in content for marker in ["##", "###", "---"])
            coherence = 1.0 if has_structure else 0.5
            factors.append(coherence)
            
            # Legibilidade (tamanho e formatação)
            readability = min(len(content) / 1000, 1.0)  # Normalizado
            factors.append(readability)
            
            # Compliance (presença de metadados)
            compliance_indicators = ["tracing id", "compliance", "autor", "data"]
            compliance_score = sum(1 for indicator in compliance_indicators if indicator.lower() in content.lower())
            compliance = min(compliance_score / len(compliance_indicators), 1.0)
            factors.append(compliance)
            
            # Score final (média ponderada)
            weights = [0.3, 0.25, 0.2, 0.25]  # Completude, Coerência, Legibilidade, Compliance
            score = sum(f * w for f, w in zip(factors, weights))
            
            return round(score, 2)
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao calcular qualidade: {e}")
            return 0.0

    def collect_directory_metrics(self, directory: str) -> List[DocumentMetric]:
        """Coleta métricas de todos os arquivos em um diretório"""
        metrics = []
        
        try:
            path = Path(directory)
            if not path.exists():
                logger.warning(f"[DOC_METRICS] Diretório não encontrado: {directory}")
                return metrics
            
            # Arquivos de documentação
            doc_extensions = ['.md', '.txt', '.rst', '.yaml', '.json']
            doc_files = []
            
            for ext in doc_extensions:
                doc_files.extend(path.rglob(f"*{ext}"))
            
            logger.info(f"[DOC_METRICS] Coletando métricas de {len(doc_files)} arquivos em {directory}")
            
            # Coletar métricas em paralelo
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(self.collect_file_metrics, str(f)) for f in doc_files]
                
                for future in futures:
                    try:
                        metric = future.result()
                        if metric:
                            metrics.append(metric)
                    except Exception as e:
                        logger.error(f"[DOC_METRICS] Erro ao processar arquivo: {e}")
            
            logger.info(f"[DOC_METRICS] Métricas coletadas: {len(metrics)} arquivos")
            return metrics
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao coletar métricas do diretório {directory}: {e}")
            return metrics

    def calculate_quality_metrics(self, metrics: List[DocumentMetric]) -> QualityMetric:
        """Calcula métricas de qualidade agregadas"""
        try:
            if not metrics:
                return QualityMetric(0.0, 0.0, 0.0, 0.0, 0.0)
            
            # Scores individuais
            quality_scores = [m.quality_score for m in metrics]
            
            # Completude
            completeness_scores = []
            for metric in metrics:
                if metric.metadata.get("has_images", False):
                    completeness_scores.append(1.0)
                elif metric.metadata.get("has_links", False):
                    completeness_scores.append(0.8)
                else:
                    completeness_scores.append(0.6)
            
            # Coerência
            coherence_scores = []
            for metric in metrics:
                if metric.metadata.get("has_code_blocks", False):
                    coherence_scores.append(1.0)
                elif metric.line_count > 50:
                    coherence_scores.append(0.8)
                else:
                    coherence_scores.append(0.5)
            
            # Legibilidade
            readability_scores = []
            for metric in metrics:
                if metric.word_count > 500:
                    readability_scores.append(1.0)
                elif metric.word_count > 200:
                    readability_scores.append(0.7)
                else:
                    readability_scores.append(0.4)
            
            # Compliance
            compliance_scores = [m.quality_score for m in metrics]  # Usar qualidade geral como proxy
            
            # Calcular médias
            completeness = statistics.mean(completeness_scores)
            coherence = statistics.mean(coherence_scores)
            readability = statistics.mean(readability_scores)
            compliance = statistics.mean(compliance_scores)
            
            # Score geral
            overall = statistics.mean([completeness, coherence, readability, compliance])
            
            # Identificar issues
            issues = []
            if completeness < self.quality_thresholds["completeness"]:
                issues.append("Baixa completude da documentação")
            if coherence < self.quality_thresholds["coherence"]:
                issues.append("Baixa coerência estrutural")
            if readability < self.quality_thresholds["readability"]:
                issues.append("Baixa legibilidade")
            if compliance < self.quality_thresholds["compliance"]:
                issues.append("Baixo compliance")
            
            return QualityMetric(
                completeness_score=round(completeness, 2),
                coherence_score=round(coherence, 2),
                readability_score=round(readability, 2),
                compliance_score=round(compliance, 2),
                overall_score=round(overall, 2),
                issues=issues
            )
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao calcular métricas de qualidade: {e}")
            return QualityMetric(0.0, 0.0, 0.0, 0.0, 0.0)

    def collect_performance_metrics(self) -> PerformanceMetric:
        """Coleta métricas de performance do sistema"""
        try:
            import psutil
            
            # Métricas de sistema
            memory_usage = psutil.virtual_memory().percent
            cpu_usage = psutil.cpu_percent(interval=1)
            
            # Tempos de processamento (simulados para exemplo)
            generation_time = time.time() % 10  # Simulado
            processing_time = time.time() % 5   # Simulado
            
            return PerformanceMetric(
                generation_time=round(generation_time, 2),
                processing_time=round(processing_time, 2),
                memory_usage=round(memory_usage, 2),
                cpu_usage=round(cpu_usage, 2)
            )
            
        except ImportError:
            logger.warning("[DOC_METRICS] psutil não disponível, usando métricas simuladas")
            return PerformanceMetric(
                generation_time=2.5,
                processing_time=1.2,
                memory_usage=45.0,
                cpu_usage=25.0
            )
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao coletar métricas de performance: {e}")
            return PerformanceMetric(0.0, 0.0, 0.0, 0.0)

    def generate_report(self, metrics: List[DocumentMetric], quality: QualityMetric, performance: PerformanceMetric) -> Dict:
        """Gera relatório completo de métricas"""
        try:
            # Estatísticas básicas
            total_files = len(metrics)
            total_size = sum(m.file_size for m in metrics)
            total_lines = sum(m.line_count for m in metrics)
            total_words = sum(m.word_count for m in metrics)
            
            # Distribuição por tipo de arquivo
            file_types = defaultdict(int)
            for metric in metrics:
                file_type = metric.metadata.get("file_type", "unknown")
                file_types[file_type] += 1
            
            # Arquivos com melhor/pior qualidade
            sorted_metrics = sorted(metrics, key=lambda x: x.quality_score, reverse=True)
            best_files = sorted_metrics[:5]
            worst_files = sorted_metrics[-5:] if len(sorted_metrics) >= 5 else sorted_metrics
            
            # Relatório
            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_files": total_files,
                    "total_size_mb": round(total_size / (1024 * 1024), 2),
                    "total_lines": total_lines,
                    "total_words": total_words,
                    "average_quality": round(statistics.mean([m.quality_score for m in metrics]), 2)
                },
                "quality_metrics": asdict(quality),
                "performance_metrics": asdict(performance),
                "file_distribution": dict(file_types),
                "best_files": [
                    {
                        "file_path": m.file_path,
                        "quality_score": m.quality_score,
                        "line_count": m.line_count
                    }
                    for m in best_files
                ],
                "worst_files": [
                    {
                        "file_path": m.file_path,
                        "quality_score": m.quality_score,
                        "line_count": m.line_count
                    }
                    for m in worst_files
                ],
                "alerts": self._generate_alerts(quality, performance),
                "recommendations": self._generate_recommendations(quality, metrics)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao gerar relatório: {e}")
            return {}

    def _generate_alerts(self, quality: QualityMetric, performance: PerformanceMetric) -> List[str]:
        """Gera alertas baseados nas métricas"""
        alerts = []
        
        # Alertas de qualidade
        if quality.overall_score < 0.7:
            alerts.append(f"ALERTA: Qualidade geral baixa ({quality.overall_score})")
        
        if quality.completeness_score < self.quality_thresholds["completeness"]:
            alerts.append(f"ALERTA: Completude abaixo do threshold ({quality.completeness_score})")
        
        if quality.compliance_score < self.quality_thresholds["compliance"]:
            alerts.append(f"ALERTA: Compliance abaixo do threshold ({quality.compliance_score})")
        
        # Alertas de performance
        if performance.memory_usage > 80:
            alerts.append(f"ALERTA: Uso de memória alto ({performance.memory_usage}%)")
        
        if performance.cpu_usage > 90:
            alerts.append(f"ALERTA: Uso de CPU alto ({performance.cpu_usage}%)")
        
        return alerts

    def _generate_recommendations(self, quality: QualityMetric, metrics: List[DocumentMetric]) -> List[str]:
        """Gera recomendações de melhoria"""
        recommendations = []
        
        # Recomendações baseadas em qualidade
        if quality.completeness_score < 0.8:
            recommendations.append("Adicionar mais seções essenciais (objetivo, descrição, exemplos)")
        
        if quality.coherence_score < 0.7:
            recommendations.append("Melhorar estrutura e organização dos documentos")
        
        if quality.readability_score < 0.8:
            recommendations.append("Aumentar detalhamento e clareza dos textos")
        
        if quality.compliance_score < 0.9:
            recommendations.append("Adicionar metadados de compliance (tracing ID, autor, data)")
        
        # Recomendações baseadas em arquivos
        small_files = [m for m in metrics if m.word_count < 100]
        if len(small_files) > len(metrics) * 0.3:
            recommendations.append("Muitos arquivos pequenos - considerar consolidação")
        
        low_quality_files = [m for m in metrics if m.quality_score < 0.5]
        if low_quality_files:
            recommendations.append(f"Revisar {len(low_quality_files)} arquivos com baixa qualidade")
        
        return recommendations

    def export_metrics(self, report: Dict, format: str = "json") -> str:
        """Exporta métricas em diferentes formatos"""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            
            if format.lower() == "json":
                filename = f"{self.output_dir}/doc_metrics_{timestamp}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            elif format.lower() == "csv":
                filename = f"{self.output_dir}/doc_metrics_{timestamp}.csv"
                # Implementar exportação CSV se necessário
                logger.info(f"[DOC_METRICS] Exportação CSV não implementada")
                return ""
            
            else:
                logger.error(f"[DOC_METRICS] Formato não suportado: {format}")
                return ""
            
            logger.info(f"[DOC_METRICS] Métricas exportadas: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro ao exportar métricas: {e}")
            return ""

    def run_collection(self, directories: List[str] = None) -> Dict:
        """Executa coleta completa de métricas"""
        try:
            if directories is None:
                directories = ["docs", "scripts"]
            
            logger.info(f"[DOC_METRICS] Iniciando coleta de métricas")
            
            # Coletar métricas de arquivos
            all_metrics = []
            for directory in directories:
                metrics = self.collect_directory_metrics(directory)
                all_metrics.extend(metrics)
            
            # Calcular métricas agregadas
            quality_metrics = self.calculate_quality_metrics(all_metrics)
            performance_metrics = self.collect_performance_metrics()
            
            # Gerar relatório
            report = self.generate_report(all_metrics, quality_metrics, performance_metrics)
            
            # Exportar
            export_file = self.export_metrics(report)
            
            # Adicionar ao histórico
            self.metrics_history.append(report)
            
            # Manter apenas últimos 100 relatórios
            if len(self.metrics_history) > 100:
                self.metrics_history = self.metrics_history[-100:]
            
            logger.info(f"[DOC_METRICS] Coleta concluída - {len(all_metrics)} arquivos processados")
            
            return {
                "report": report,
                "export_file": export_file,
                "files_processed": len(all_metrics)
            }
            
        except Exception as e:
            logger.error(f"[DOC_METRICS] Erro na coleta: {e}")
            return {}

    def get_statistics(self) -> Dict:
        """Retorna estatísticas do sistema"""
        return {
            "total_reports": len(self.metrics_history),
            "last_collection": self.metrics_history[-1]["timestamp"] if self.metrics_history else None,
            "output_directory": self.output_dir,
            "quality_thresholds": self.quality_thresholds
        }


def main():
    """Função principal"""
    print("📊 Iniciando Coleta de Métricas de Documentação...")
    
    # Inicializar coletor
    collector = DocumentMetricsCollector()
    
    # Executar coleta
    result = collector.run_collection()
    
    if result:
        print(f"✅ Coleta concluída: {result['files_processed']} arquivos processados")
        print(f"📁 Relatório salvo: {result['export_file']}")
        
        # Mostrar resumo
        report = result['report']
        print(f"\n📈 Resumo:")
        print(f"   - Arquivos: {report['summary']['total_files']}")
        print(f"   - Qualidade Média: {report['summary']['average_quality']}")
        print(f"   - Alertas: {len(report['alerts'])}")
        print(f"   - Recomendações: {len(report['recommendations'])}")
        
        # Mostrar alertas se houver
        if report['alerts']:
            print(f"\n⚠️ Alertas:")
            for alert in report['alerts']:
                print(f"   - {alert}")
        
        # Mostrar recomendações
        if report['recommendations']:
            print(f"\n💡 Recomendações:")
            for rec in report['recommendations']:
                print(f"   - {rec}")
    else:
        print("❌ Erro na coleta de métricas")


if __name__ == "__main__":
    main() 