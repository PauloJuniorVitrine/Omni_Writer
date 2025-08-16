"""
Statistical Analysis - Omni Writer
==================================

Sistema de análise estatística avançada para testes de carga.
Cálculo de coeficiente de variação, desvio padrão, skewness e detecção de volatilidade.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 17
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:25:00Z
"""

import os
import json
import time
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Union
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
from scipy import stats
from scipy.stats import skew, kurtosis
import matplotlib.pyplot as plt
import seaborn as sns
from collections import deque, defaultdict

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('statistical_analysis')

@dataclass
class StatisticalMetrics:
    """Métricas estatísticas calculadas."""
    metric_name: str
    count: int
    mean: float
    median: float
    std_dev: float
    variance: float
    coefficient_of_variation: float
    skewness: float
    kurtosis: float
    min_value: float
    max_value: float
    range_value: float
    q1: float
    q3: float
    iqr: float
    volatility_score: float
    timestamp: datetime

@dataclass
class AnomalyDetection:
    """Detecção de anomalias estatísticas."""
    metric_name: str
    anomaly_type: str  # 'outlier', 'trend', 'volatility', 'seasonal'
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    value: float
    threshold: float
    confidence: float
    timestamp: datetime

@dataclass
class TrendAnalysis:
    """Análise de tendências."""
    metric_name: str
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    trend_strength: float  # 0-1
    slope: float
    r_squared: float
    p_value: float
    confidence_interval: Tuple[float, float]
    timestamp: datetime

class StatisticalAnalyzer:
    """
    Analisador estatístico avançado para testes de carga.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/stats/config.json"):
        """
        Inicializa o analisador estatístico.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/stats/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações de análise
        self.analysis_config = {
            "window_size": 100,  # Tamanho da janela para análise móvel
            "outlier_threshold": 3.0,  # Desvios padrão para detectar outliers
            "volatility_threshold": 0.5,  # Threshold para volatilidade
            "trend_confidence": 0.95,  # Confiança para análise de tendência
            "min_data_points": 10,  # Mínimo de pontos para análise
            "enable_real_time": True,
            "enable_anomaly_detection": True,
            "enable_trend_analysis": True,
            "enable_volatility_detection": True
        }
        
        # Dados de métricas
        self.metric_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metric_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Resultados de análise
        self.statistical_results: List[StatisticalMetrics] = []
        self.anomaly_results: List[AnomalyDetection] = []
        self.trend_results: List[TrendAnalysis] = []
        
        # Estado da análise
        self.is_analyzing = False
        self.analysis_thread = None
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")

    def load_config(self) -> None:
        """
        Carrega configuração de análise estatística.
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

    def add_metric_data(self, metric_name: str, value: float, timestamp: datetime = None) -> None:
        """
        Adiciona dados de métrica para análise.
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        self.metric_data[metric_name].append(value)
        self.metric_timestamps[metric_name].append(timestamp)
        
        # Análise em tempo real se habilitada
        if self.analysis_config["enable_real_time"]:
            self._analyze_metric_realtime(metric_name)

    def calculate_basic_statistics(self, data: List[float]) -> Dict[str, float]:
        """
        Calcula estatísticas básicas.
        """
        if len(data) < 2:
            return {}
        
        try:
            stats_dict = {
                "count": len(data),
                "mean": np.mean(data),
                "median": np.median(data),
                "std_dev": np.std(data, ddof=1),
                "variance": np.var(data, ddof=1),
                "min_value": np.min(data),
                "max_value": np.max(data),
                "range_value": np.max(data) - np.min(data)
            }
            
            # Coeficiente de variação
            if stats_dict["mean"] != 0:
                stats_dict["coefficient_of_variation"] = stats_dict["std_dev"] / stats_dict["mean"]
            else:
                stats_dict["coefficient_of_variation"] = 0
            
            # Quartis
            q1, q3 = np.percentile(data, [25, 75])
            stats_dict["q1"] = q1
            stats_dict["q3"] = q3
            stats_dict["iqr"] = q3 - q1
            
            # Skewness e Kurtosis
            if len(data) >= 3:
                stats_dict["skewness"] = float(skew(data))
                stats_dict["kurtosis"] = float(kurtosis(data))
            else:
                stats_dict["skewness"] = 0
                stats_dict["kurtosis"] = 0
            
            return stats_dict
            
        except Exception as e:
            logger.error(f"Erro ao calcular estatísticas básicas: {e}")
            return {}

    def calculate_volatility_score(self, data: List[float], window_size: int = None) -> float:
        """
        Calcula score de volatilidade.
        """
        if window_size is None:
            window_size = self.analysis_config["window_size"]
        
        if len(data) < window_size:
            return 0.0
        
        try:
            # Usa janela móvel para calcular volatilidade
            volatility_scores = []
            
            for i in range(len(data) - window_size + 1):
                window_data = data[i:i + window_size]
                
                # Calcula coeficiente de variação da janela
                window_mean = np.mean(window_data)
                window_std = np.std(window_data, ddof=1)
                
                if window_mean != 0:
                    cv = window_std / window_mean
                else:
                    cv = 0
                
                volatility_scores.append(cv)
            
            # Retorna a média dos scores de volatilidade
            return np.mean(volatility_scores) if volatility_scores else 0.0
            
        except Exception as e:
            logger.error(f"Erro ao calcular volatilidade: {e}")
            return 0.0

    def detect_outliers(self, data: List[float], method: str = "zscore") -> List[int]:
        """
        Detecta outliers usando diferentes métodos.
        """
        outliers = []
        
        if len(data) < 3:
            return outliers
        
        try:
            if method == "zscore":
                # Método Z-Score
                z_scores = np.abs(stats.zscore(data))
                threshold = self.analysis_config["outlier_threshold"]
                outliers = [i for i, z in enumerate(z_scores) if z > threshold]
                
            elif method == "iqr":
                # Método IQR (Interquartile Range)
                q1, q3 = np.percentile(data, [25, 75])
                iqr = q3 - q1
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                
                outliers = [i for i, value in enumerate(data) 
                           if value < lower_bound or value > upper_bound]
                
            elif method == "modified_zscore":
                # Método Z-Score modificado (mais robusto)
                median = np.median(data)
                mad = np.median(np.abs(data - median))
                
                if mad != 0:
                    modified_z_scores = 0.6745 * (data - median) / mad
                    threshold = self.analysis_config["outlier_threshold"]
                    outliers = [i for i, z in enumerate(modified_z_scores) if abs(z) > threshold]
            
            return outliers
            
        except Exception as e:
            logger.error(f"Erro ao detectar outliers: {e}")
            return []

    def analyze_trend(self, data: List[float], timestamps: List[datetime] = None) -> TrendAnalysis:
        """
        Analisa tendência dos dados.
        """
        if len(data) < self.analysis_config["min_data_points"]:
            return None
        
        try:
            # Prepara dados para análise
            x = np.arange(len(data))
            y = np.array(data)
            
            # Regressão linear
            slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
            r_squared = r_value ** 2
            
            # Determina direção da tendência
            if abs(slope) < 0.01:
                trend_direction = "stable"
            elif slope > 0:
                trend_direction = "increasing"
            else:
                trend_direction = "decreasing"
            
            # Força da tendência (0-1)
            trend_strength = min(abs(r_squared), 1.0)
            
            # Intervalo de confiança
            confidence_level = self.analysis_config["trend_confidence"]
            n = len(data)
            t_critical = stats.t.ppf((1 + confidence_level) / 2, n - 2)
            
            slope_se = std_err
            slope_ci_lower = slope - t_critical * slope_se
            slope_ci_upper = slope + t_critical * slope_se
            confidence_interval = (slope_ci_lower, slope_ci_upper)
            
            return TrendAnalysis(
                metric_name="",  # Será preenchido pelo chamador
                trend_direction=trend_direction,
                trend_strength=trend_strength,
                slope=slope,
                r_squared=r_squared,
                p_value=p_value,
                confidence_interval=confidence_interval,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Erro ao analisar tendência: {e}")
            return None

    def detect_anomalies(self, metric_name: str, data: List[float]) -> List[AnomalyDetection]:
        """
        Detecta anomalias nos dados.
        """
        anomalies = []
        
        if len(data) < self.analysis_config["min_data_points"]:
            return anomalies
        
        try:
            # Detecta outliers
            outlier_indices = self.detect_outliers(data)
            
            for idx in outlier_indices:
                anomaly = AnomalyDetection(
                    metric_name=metric_name,
                    anomaly_type="outlier",
                    severity=self._determine_anomaly_severity(data[idx], data),
                    description=f"Outlier detectado: valor {data[idx]:.2f}",
                    value=data[idx],
                    threshold=np.mean(data) + 2 * np.std(data),
                    confidence=0.95,
                    timestamp=datetime.now()
                )
                anomalies.append(anomaly)
            
            # Detecta volatilidade
            volatility_score = self.calculate_volatility_score(data)
            if volatility_score > self.analysis_config["volatility_threshold"]:
                anomaly = AnomalyDetection(
                    metric_name=metric_name,
                    anomaly_type="volatility",
                    severity="high" if volatility_score > 1.0 else "medium",
                    description=f"Alta volatilidade detectada: score {volatility_score:.3f}",
                    value=volatility_score,
                    threshold=self.analysis_config["volatility_threshold"],
                    confidence=0.90,
                    timestamp=datetime.now()
                )
                anomalies.append(anomaly)
            
            # Detecta tendências significativas
            trend_analysis = self.analyze_trend(data)
            if trend_analysis and trend_analysis.p_value < 0.05:
                anomaly = AnomalyDetection(
                    metric_name=metric_name,
                    anomaly_type="trend",
                    severity="medium" if trend_analysis.trend_strength > 0.7 else "low",
                    description=f"Tendência {trend_analysis.trend_direction} detectada",
                    value=trend_analysis.trend_strength,
                    threshold=0.5,
                    confidence=1 - trend_analysis.p_value,
                    timestamp=datetime.now()
                )
                anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Erro ao detectar anomalias: {e}")
            return []

    def _determine_anomaly_severity(self, value: float, data: List[float]) -> str:
        """
        Determina severidade de uma anomalia.
        """
        mean = np.mean(data)
        std = np.std(data, ddof=1)
        
        if std == 0:
            return "low"
        
        z_score = abs((value - mean) / std)
        
        if z_score > 4:
            return "critical"
        elif z_score > 3:
            return "high"
        elif z_score > 2:
            return "medium"
        else:
            return "low"

    def _analyze_metric_realtime(self, metric_name: str) -> None:
        """
        Análise em tempo real de uma métrica.
        """
        data = list(self.metric_data[metric_name])
        
        if len(data) < self.analysis_config["min_data_points"]:
            return
        
        try:
            # Calcula estatísticas
            basic_stats = self.calculate_basic_statistics(data)
            if not basic_stats:
                return
            
            # Calcula volatilidade
            volatility_score = self.calculate_volatility_score(data)
            
            # Cria objeto de métricas estatísticas
            stats_metrics = StatisticalMetrics(
                metric_name=metric_name,
                count=basic_stats["count"],
                mean=basic_stats["mean"],
                median=basic_stats["median"],
                std_dev=basic_stats["std_dev"],
                variance=basic_stats["variance"],
                coefficient_of_variation=basic_stats["coefficient_of_variation"],
                skewness=basic_stats["skewness"],
                kurtosis=basic_stats["kurtosis"],
                min_value=basic_stats["min_value"],
                max_value=basic_stats["max_value"],
                range_value=basic_stats["range_value"],
                q1=basic_stats["q1"],
                q3=basic_stats["q3"],
                iqr=basic_stats["iqr"],
                volatility_score=volatility_score,
                timestamp=datetime.now()
            )
            
            self.statistical_results.append(stats_metrics)
            
            # Detecta anomalias se habilitado
            if self.analysis_config["enable_anomaly_detection"]:
                anomalies = self.detect_anomalies(metric_name, data)
                self.anomaly_results.extend(anomalies)
                
                for anomaly in anomalies:
                    logger.warning(f"Anomalia detectada em {metric_name}: {anomaly.description}")
            
            # Analisa tendências se habilitado
            if self.analysis_config["enable_trend_analysis"]:
                trend_analysis = self.analyze_trend(data)
                if trend_analysis:
                    trend_analysis.metric_name = metric_name
                    self.trend_results.append(trend_analysis)
            
        except Exception as e:
            logger.error(f"Erro na análise em tempo real de {metric_name}: {e}")

    def analyze_all_metrics(self) -> Dict[str, Any]:
        """
        Analisa todas as métricas disponíveis.
        """
        logger.info("Iniciando análise completa de todas as métricas...")
        
        analysis_summary = {
            "total_metrics": len(self.metric_data),
            "metrics_analyzed": 0,
            "anomalies_found": 0,
            "trends_detected": 0,
            "high_volatility_metrics": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        for metric_name, data in self.metric_data.items():
            if len(data) >= self.analysis_config["min_data_points"]:
                self._analyze_metric_realtime(metric_name)
                analysis_summary["metrics_analyzed"] += 1
        
        # Conta resultados
        analysis_summary["anomalies_found"] = len(self.anomaly_results)
        analysis_summary["trends_detected"] = len(self.trend_results)
        analysis_summary["high_volatility_metrics"] = len([
            r for r in self.statistical_results 
            if r.volatility_score > self.analysis_config["volatility_threshold"]
        ])
        
        logger.info(f"Análise completa finalizada: {analysis_summary}")
        return analysis_summary

    def generate_statistical_report(self) -> str:
        """
        Gera relatório estatístico completo.
        """
        try:
            report_file = self.output_dir / f"statistical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Análise Estatística - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Métricas analisadas:** {len(self.statistical_results)}\n")
                f.write(f"- **Anomalias detectadas:** {len(self.anomaly_results)}\n")
                f.write(f"- **Tendências identificadas:** {len(self.trend_results)}\n")
                f.write(f"- **Métricas com alta volatilidade:** {len([r for r in self.statistical_results if r.volatility_score > 0.5])}\n\n")
                
                f.write("## Métricas Estatísticas\n\n")
                
                for result in self.statistical_results[-10:]:  # Últimas 10 análises
                    f.write(f"### {result.metric_name}\n")
                    f.write(f"- **Contagem:** {result.count}\n")
                    f.write(f"- **Média:** {result.mean:.2f}\n")
                    f.write(f"- **Mediana:** {result.median:.2f}\n")
                    f.write(f"- **Desvio Padrão:** {result.std_dev:.2f}\n")
                    f.write(f"- **Coeficiente de Variação:** {result.coefficient_of_variation:.3f}\n")
                    f.write(f"- **Skewness:** {result.skewness:.3f}\n")
                    f.write(f"- **Kurtosis:** {result.kurtosis:.3f}\n")
                    f.write(f"- **Volatilidade:** {result.volatility_score:.3f}\n")
                    f.write(f"- **Range:** {result.range_value:.2f}\n")
                    f.write(f"- **IQR:** {result.iqr:.2f}\n\n")
                
                f.write("## Anomalias Detectadas\n\n")
                
                if self.anomaly_results:
                    f.write("| Métrica | Tipo | Severidade | Descrição | Valor |\n")
                    f.write("|---------|------|------------|-----------|-------|\n")
                    
                    for anomaly in self.anomaly_results[-20:]:  # Últimas 20 anomalias
                        f.write(f"| {anomaly.metric_name} | {anomaly.anomaly_type} | {anomaly.severity} | {anomaly.description[:50]}... | {anomaly.value:.2f} |\n")
                else:
                    f.write("Nenhuma anomalia detectada.\n")
                
                f.write("\n## Análise de Tendências\n\n")
                
                if self.trend_results:
                    f.write("| Métrica | Direção | Força | R² | P-valor |\n")
                    f.write("|---------|---------|-------|----|---------|\n")
                    
                    for trend in self.trend_results[-10:]:  # Últimas 10 tendências
                        f.write(f"| {trend.metric_name} | {trend.trend_direction} | {trend.trend_strength:.3f} | {trend.r_squared:.3f} | {trend.p_value:.4f} |\n")
                else:
                    f.write("Nenhuma tendência significativa detectada.\n")
                
                f.write("\n## Configurações\n\n")
                f.write(f"- **Tamanho da janela:** {self.analysis_config['window_size']}\n")
                f.write(f"- **Threshold de outliers:** {self.analysis_config['outlier_threshold']}\n")
                f.write(f"- **Threshold de volatilidade:** {self.analysis_config['volatility_threshold']}\n")
                f.write(f"- **Confiança para tendências:** {self.analysis_config['trend_confidence']}\n")
                f.write(f"- **Mínimo de pontos:** {self.analysis_config['min_data_points']}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório estatístico gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório estatístico: {e}")
            return ""

    def generate_visualizations(self) -> List[str]:
        """
        Gera visualizações estatísticas.
        """
        try:
            viz_files = []
            
            for metric_name, data in self.metric_data.items():
                if len(data) < self.analysis_config["min_data_points"]:
                    continue
                
                # Cria figura com múltiplos subplots
                fig, axes = plt.subplots(2, 2, figsize=(15, 10))
                fig.suptitle(f'Análise Estatística - {metric_name}', fontsize=16)
                
                data_array = np.array(data)
                
                # Histograma
                axes[0, 0].hist(data_array, bins=30, alpha=0.7, color='skyblue', edgecolor='black')
                axes[0, 0].set_title('Distribuição de Frequência')
                axes[0, 0].set_xlabel('Valor')
                axes[0, 0].set_ylabel('Frequência')
                
                # Box plot
                axes[0, 1].boxplot(data_array)
                axes[0, 1].set_title('Box Plot')
                axes[0, 1].set_ylabel('Valor')
                
                # Série temporal
                timestamps = list(self.metric_timestamps[metric_name])
                if timestamps:
                    # Converte timestamps para números para plotagem
                    time_nums = [(t - timestamps[0]).total_seconds() for t in timestamps]
                    axes[1, 0].plot(time_nums, data_array, 'b-', alpha=0.7)
                    axes[1, 0].set_title('Série Temporal')
                    axes[1, 0].set_xlabel('Tempo (segundos)')
                    axes[1, 0].set_ylabel('Valor')
                
                # Q-Q Plot
                stats.probplot(data_array, dist="norm", plot=axes[1, 1])
                axes[1, 1].set_title('Q-Q Plot (Normalidade)')
                
                plt.tight_layout()
                
                # Salva figura
                viz_file = self.output_dir / f"stats_{metric_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                plt.savefig(viz_file, dpi=300, bbox_inches='tight')
                plt.close()
                
                viz_files.append(str(viz_file))
            
            logger.info(f"Visualizações geradas: {len(viz_files)} arquivos")
            return viz_files
            
        except Exception as e:
            logger.error(f"Erro ao gerar visualizações: {e}")
            return []

    def get_metric_summary(self, metric_name: str) -> Dict[str, Any]:
        """
        Obtém resumo estatístico de uma métrica específica.
        """
        if metric_name not in self.metric_data:
            return {}
        
        data = list(self.metric_data[metric_name])
        
        if len(data) < self.analysis_config["min_data_points"]:
            return {"error": "Dados insuficientes para análise"}
        
        try:
            # Estatísticas básicas
            basic_stats = self.calculate_basic_statistics(data)
            
            # Volatilidade
            volatility_score = self.calculate_volatility_score(data)
            
            # Anomalias
            anomalies = self.detect_anomalies(metric_name, data)
            
            # Tendência
            trend_analysis = self.analyze_trend(data)
            
            summary = {
                "metric_name": metric_name,
                "data_points": len(data),
                "statistics": basic_stats,
                "volatility_score": volatility_score,
                "anomalies_count": len(anomalies),
                "trend_analysis": asdict(trend_analysis) if trend_analysis else None,
                "last_updated": datetime.now().isoformat()
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Erro ao gerar resumo de {metric_name}: {e}")
            return {"error": str(e)}


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Statistical Analyzer...")
    
    analyzer = StatisticalAnalyzer()
    
    try:
        # Simula dados de métricas para teste
        test_metrics = {
            "response_time": [100, 120, 95, 150, 110, 200, 105, 130, 140, 125],
            "throughput": [50, 45, 55, 40, 60, 35, 65, 50, 45, 55],
            "error_rate": [0.01, 0.02, 0.005, 0.03, 0.015, 0.025, 0.01, 0.02, 0.015, 0.03]
        }
        
        # Adiciona dados com algumas anomalias
        for metric_name, values in test_metrics.items():
            for i, value in enumerate(values):
                # Adiciona algumas anomalias
                if i == 5:  # Anomalia no meio
                    value *= 3
                
                analyzer.add_metric_data(metric_name, value)
        
        # Analisa todas as métricas
        analysis_summary = analyzer.analyze_all_metrics()
        
        # Gera relatório
        report_file = analyzer.generate_statistical_report()
        
        # Gera visualizações
        viz_files = analyzer.generate_visualizations()
        
        logger.info("Análise estatística concluída com sucesso!")
        logger.info(f"Resumo: {analysis_summary}")
        logger.info(f"Relatório: {report_file}")
        logger.info(f"Visualizações: {len(viz_files)} arquivos")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main()) 