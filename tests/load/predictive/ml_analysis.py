"""
Predictive Analysis - Omni Writer
=================================

Sistema de análise preditiva usando machine learning para prever pontos de quebra
e tendências de performance baseado em dados históricos reais.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 10
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T15:45:00Z
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import logging
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('predictive_analysis')

class PredictiveAnalyzer:
    """
    Analisador preditivo para testes de carga usando machine learning.
    Baseado em dados históricos reais dos testes de carga.
    """
    
    def __init__(self, results_dir: str = "tests/load/results", models_dir: str = "tests/load/predictive/models"):
        """
        Inicializa o analisador preditivo.
        
        Args:
            results_dir: Diretório com resultados históricos
            models_dir: Diretório para salvar modelos treinados
        """
        self.results_dir = Path(results_dir)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.output_dir = Path("tests/load/predictive/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações baseadas no código real
        self.metrics = [
            'response_time', 'throughput', 'error_rate', 'cpu_usage', 
            'memory_usage', 'concurrent_users', 'request_count'
        ]
        
        self.endpoints = [
            "/generate", "/download", "/feedback", "/webhook", "/status"
        ]
        
        # Thresholds para detecção de anomalias
        self.anomaly_thresholds = {
            'response_time': 1000,  # ms
            'error_rate': 0.05,     # 5%
            'cpu_usage': 90,        # %
            'memory_usage': 85      # %
        }
        
        # Modelos ML
        self.models = {
            'response_time': RandomForestRegressor(n_estimators=100, random_state=42),
            'throughput': RandomForestRegressor(n_estimators=100, random_state=42),
            'error_rate': RandomForestRegressor(n_estimators=100, random_state=42),
            'anomaly_detector': IsolationForest(contamination=0.1, random_state=42)
        }
        
        # Scaler para normalização
        self.scaler = StandardScaler()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Diretório de resultados: {self.results_dir}")
        logger.info(f"Diretório de modelos: {self.models_dir}")

    def load_historical_data(self) -> pd.DataFrame:
        """
        Carrega dados históricos dos testes de carga.
        Baseado nos arquivos CSV reais gerados pelos testes.
        """
        logger.info("Carregando dados históricos...")
        
        all_data = []
        
        # Busca arquivos CSV de resultados
        csv_files = list(self.results_dir.glob("*.csv"))
        
        if not csv_files:
            logger.warning("Nenhum arquivo CSV encontrado")
            return pd.DataFrame()
        
        for csv_file in csv_files:
            try:
                logger.info(f"Carregando: {csv_file}")
                
                df = pd.read_csv(csv_file)
                
                # Adiciona metadados do arquivo
                df['source_file'] = csv_file.name
                df['test_date'] = csv_file.stat().st_mtime
                df['test_type'] = csv_file.stem.split('_')[0]
                
                # Normaliza colunas baseado no formato real
                if 'Average Response Time' in df.columns:
                    df['response_time'] = df['Average Response Time']
                if 'Failure Count' in df.columns:
                    df['failures'] = df['Failure Count']
                if 'Request Count' in df.columns:
                    df['requests'] = df['Request Count']
                    df['error_rate'] = df['failures'] / df['requests']
                if 'Requests/s' in df.columns:
                    df['throughput'] = df['Requests/s']
                
                all_data.append(df)
                
            except Exception as e:
                logger.error(f"Erro ao carregar {csv_file}: {e}")
                continue
        
        if not all_data:
            logger.warning("Nenhum dado válido encontrado")
            return pd.DataFrame()
        
        # Combina todos os dados
        combined_data = pd.concat(all_data, ignore_index=True)
        
        # Limpa e prepara dados
        combined_data = self._clean_and_prepare_data(combined_data)
        
        logger.info(f"Dados carregados: {len(combined_data)} registros")
        return combined_data

    def _clean_and_prepare_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Limpa e prepara dados para análise preditiva.
        """
        # Remove linhas com valores nulos críticos
        data = data.dropna(subset=['response_time', 'requests'])
        
        # Remove outliers extremos
        for metric in ['response_time', 'throughput', 'error_rate']:
            if metric in data.columns:
                Q1 = data[metric].quantile(0.25)
                Q3 = data[metric].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR
                data = data[(data[metric] >= lower_bound) & (data[metric] <= upper_bound)]
        
        # Adiciona features temporais
        if 'test_date' in data.columns:
            data['timestamp'] = pd.to_datetime(data['test_date'], unit='s')
            data['hour'] = data['timestamp'].dt.hour
            data['day_of_week'] = data['timestamp'].dt.dayofweek
            data['month'] = data['timestamp'].dt.month
        
        # Adiciona features derivadas
        if 'requests' in data.columns and 'response_time' in data.columns:
            data['load_factor'] = data['requests'] * data['response_time'] / 1000
        
        return data

    def extract_features(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, pd.Series]]:
        """
        Extrai features para treinamento dos modelos.
        """
        logger.info("Extraindo features...")
        
        features = pd.DataFrame()
        targets = {}
        
        # Features básicas
        if 'requests' in data.columns:
            features['request_count'] = data['requests']
        if 'hour' in data.columns:
            features['hour'] = data['hour']
        if 'day_of_week' in data.columns:
            features['day_of_week'] = data['day_of_week']
        if 'month' in data.columns:
            features['month'] = data['month']
        if 'load_factor' in data.columns:
            features['load_factor'] = data['load_factor']
        
        # Targets para predição
        if 'response_time' in data.columns:
            targets['response_time'] = data['response_time']
        if 'throughput' in data.columns:
            targets['throughput'] = data['throughput']
        if 'error_rate' in data.columns:
            targets['error_rate'] = data['error_rate']
        
        # Adiciona features de lag (valores anteriores)
        for target_name, target_values in targets.items():
            if len(target_values) > 1:
                features[f'{target_name}_lag1'] = target_values.shift(1)
                features[f'{target_name}_lag2'] = target_values.shift(2)
        
        # Remove linhas com valores nulos
        features = features.dropna()
        
        # Alinha targets com features
        aligned_targets = {}
        for target_name, target_values in targets.items():
            aligned_targets[target_name] = target_values[features.index]
        
        logger.info(f"Features extraídas: {features.shape}")
        return features, aligned_targets

    def train_models(self, features: pd.DataFrame, targets: Dict[str, pd.Series]) -> Dict[str, Any]:
        """
        Treina modelos de machine learning para predição.
        """
        logger.info("Treinando modelos...")
        
        model_results = {}
        
        # Normaliza features
        features_scaled = self.scaler.fit_transform(features)
        
        for target_name, target_values in targets.items():
            if target_name in self.models and len(target_values) > 10:
                try:
                    logger.info(f"Treinando modelo para {target_name}")
                    
                    # Remove valores nulos
                    valid_indices = ~(target_values.isna() | np.isinf(target_values))
                    X = features_scaled[valid_indices]
                    y = target_values[valid_indices]
                    
                    if len(X) < 5:
                        logger.warning(f"Dados insuficientes para {target_name}")
                        continue
                    
                    # Split treino/teste
                    X_train, X_test, y_train, y_test = train_test_split(
                        X, y, test_size=0.2, random_state=42
                    )
                    
                    # Treina modelo
                    model = self.models[target_name]
                    model.fit(X_train, y_train)
                    
                    # Avalia modelo
                    y_pred = model.predict(X_test)
                    mse = mean_squared_error(y_test, y_pred)
                    mae = mean_absolute_error(y_test, y_pred)
                    r2 = model.score(X_test, y_test)
                    
                    model_results[target_name] = {
                        'model': model,
                        'mse': mse,
                        'mae': mae,
                        'r2': r2,
                        'feature_importance': dict(zip(features.columns, model.feature_importances_))
                    }
                    
                    logger.info(f"Modelo {target_name} treinado - R²: {r2:.3f}, MSE: {mse:.3f}")
                    
                except Exception as e:
                    logger.error(f"Erro ao treinar modelo {target_name}: {e}")
        
        # Treina detector de anomalias
        try:
            logger.info("Treinando detector de anomalias")
            anomaly_data = features_scaled
            self.models['anomaly_detector'].fit(anomaly_data)
            model_results['anomaly_detector'] = {
                'model': self.models['anomaly_detector'],
                'contamination': 0.1
            }
        except Exception as e:
            logger.error(f"Erro ao treinar detector de anomalias: {e}")
        
        return model_results

    def predict_breakpoint(self, features: pd.DataFrame, models: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prediz pontos de quebra baseado nos modelos treinados.
        """
        logger.info("Predizendo pontos de quebra...")
        
        predictions = {}
        
        # Normaliza features
        features_scaled = self.scaler.transform(features)
        
        for target_name, model_info in models.items():
            if target_name == 'anomaly_detector':
                continue
                
            try:
                model = model_info['model']
                y_pred = model.predict(features_scaled)
                
                # Identifica pontos de quebra
                threshold = self.anomaly_thresholds.get(target_name, None)
                if threshold:
                    breakpoint_indices = np.where(y_pred > threshold)[0]
                    if len(breakpoint_indices) > 0:
                        predictions[target_name] = {
                            'predicted_values': y_pred,
                            'breakpoint_indices': breakpoint_indices,
                            'breakpoint_threshold': threshold,
                            'breakpoint_probability': len(breakpoint_indices) / len(y_pred)
                        }
                    else:
                        predictions[target_name] = {
                            'predicted_values': y_pred,
                            'breakpoint_indices': [],
                            'breakpoint_threshold': threshold,
                            'breakpoint_probability': 0.0
                        }
                else:
                    predictions[target_name] = {
                        'predicted_values': y_pred,
                        'trend': self._analyze_trend(y_pred)
                    }
                    
            except Exception as e:
                logger.error(f"Erro ao predizer {target_name}: {e}")
        
        return predictions

    def _analyze_trend(self, values: np.ndarray) -> str:
        """
        Analisa tendência dos valores preditos.
        """
        if len(values) < 2:
            return "insufficient_data"
        
        # Calcula slope da linha de tendência
        x = np.arange(len(values))
        slope, _, r_value, _, _ = stats.linregress(x, values)
        
        if r_value**2 > 0.7:  # R² > 0.7 indica tendência clara
            if slope > 0.1:
                return "increasing"
            elif slope < -0.1:
                return "decreasing"
            else:
                return "stable"
        else:
            return "no_clear_trend"

    def detect_anomalies(self, features: pd.DataFrame, models: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detecta anomalias nos dados usando Isolation Forest.
        """
        logger.info("Detectando anomalias...")
        
        try:
            features_scaled = self.scaler.transform(features)
            anomaly_detector = models.get('anomaly_detector', {}).get('model')
            
            if anomaly_detector:
                # Prediz anomalias (-1 para anomalia, 1 para normal)
                anomaly_scores = anomaly_detector.predict(features_scaled)
                anomaly_indices = np.where(anomaly_scores == -1)[0]
                
                return {
                    'anomaly_indices': anomaly_indices,
                    'anomaly_count': len(anomaly_indices),
                    'anomaly_percentage': len(anomaly_indices) / len(features_scaled) * 100,
                    'anomaly_scores': anomaly_scores
                }
            else:
                return {'error': 'Anomaly detector not available'}
                
        except Exception as e:
            logger.error(f"Erro ao detectar anomalias: {e}")
            return {'error': str(e)}

    def generate_predictions_report(self, predictions: Dict[str, Any], anomalies: Dict[str, Any]) -> str:
        """
        Gera relatório de predições e anomalias.
        """
        try:
            report_file = self.output_dir / f"predictions_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Análise Preditiva - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de métricas analisadas:** {len(predictions)}\n")
                f.write(f"- **Anomalias detectadas:** {anomalies.get('anomaly_count', 0)}\n")
                f.write(f"- **Percentual de anomalias:** {anomalies.get('anomaly_percentage', 0):.2f}%\n\n")
                
                f.write("## Predições por Métrica\n\n")
                
                for metric, pred_info in predictions.items():
                    f.write(f"### {metric.title()}\n\n")
                    
                    if 'breakpoint_probability' in pred_info:
                        f.write(f"- **Probabilidade de quebra:** {pred_info['breakpoint_probability']:.2%}\n")
                        f.write(f"- **Threshold:** {pred_info['breakpoint_threshold']}\n")
                        f.write(f"- **Pontos de quebra:** {len(pred_info['breakpoint_indices'])}\n")
                    elif 'trend' in pred_info:
                        f.write(f"- **Tendência:** {pred_info['trend']}\n")
                    
                    f.write("\n")
                
                f.write("## Análise de Anomalias\n\n")
                
                if 'anomaly_count' in anomalies:
                    f.write(f"- **Total de anomalias:** {anomalies['anomaly_count']}\n")
                    f.write(f"- **Percentual:** {anomalies['anomaly_percentage']:.2f}%\n")
                    
                    if anomalies['anomaly_count'] > 0:
                        f.write("- **Recomendação:** Investigar pontos de anomalia\n")
                    else:
                        f.write("- **Status:** Sem anomalias detectadas\n")
                else:
                    f.write("- **Status:** Análise de anomalias não disponível\n")
                
                f.write("\n## Recomendações\n\n")
                
                # Gera recomendações baseadas nas predições
                high_risk_metrics = []
                for metric, pred_info in predictions.items():
                    if pred_info.get('breakpoint_probability', 0) > 0.3:
                        high_risk_metrics.append(metric)
                
                if high_risk_metrics:
                    f.write("### Métricas de Alto Risco\n\n")
                    for metric in high_risk_metrics:
                        f.write(f"- **{metric}:** Alta probabilidade de quebra\n")
                    f.write("\n")
                
                f.write("### Ações Recomendadas\n\n")
                f.write("1. **Monitoramento contínuo** das métricas preditas\n")
                f.write("2. **Investigação** de anomalias detectadas\n")
                f.write("3. **Otimização** de endpoints com tendência crescente\n")
                f.write("4. **Planejamento de capacidade** baseado nas predições\n")
                f.write("5. **Testes de stress** nos pontos de quebra identificados\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""

    def save_models(self, models: Dict[str, Any]) -> None:
        """
        Salva modelos treinados para uso futuro.
        """
        try:
            for model_name, model_info in models.items():
                if 'model' in model_info:
                    model_file = self.models_dir / f"{model_name}_model.pkl"
                    
                    import pickle
                    with open(model_file, 'wb') as f:
                        pickle.dump(model_info['model'], f)
                    
                    # Salva metadados do modelo
                    metadata_file = self.models_dir / f"{model_name}_metadata.json"
                    metadata = {
                        'model_name': model_name,
                        'training_date': datetime.now().isoformat(),
                        'metrics': {k: v for k, v in model_info.items() if k != 'model'}
                    }
                    
                    with open(metadata_file, 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2)
                    
                    logger.info(f"Modelo salvo: {model_file}")
                    
        except Exception as e:
            logger.error(f"Erro ao salvar modelos: {e}")

    def run_complete_analysis(self) -> Dict[str, Any]:
        """
        Executa análise preditiva completa.
        """
        logger.info("Iniciando análise preditiva completa...")
        
        # Carrega dados históricos
        historical_data = self.load_historical_data()
        
        if historical_data.empty:
            logger.error("Nenhum dado histórico disponível")
            return {}
        
        # Extrai features
        features, targets = self.extract_features(historical_data)
        
        if features.empty or not targets:
            logger.error("Features insuficientes para análise")
            return {}
        
        # Treina modelos
        trained_models = self.train_models(features, targets)
        
        if not trained_models:
            logger.error("Falha no treinamento dos modelos")
            return {}
        
        # Gera predições
        predictions = self.predict_breakpoint(features, trained_models)
        
        # Detecta anomalias
        anomalies = self.detect_anomalies(features, trained_models)
        
        # Gera relatório
        report_file = self.generate_predictions_report(predictions, anomalies)
        
        # Salva modelos
        self.save_models(trained_models)
        
        results = {
            'predictions': predictions,
            'anomalies': anomalies,
            'report_file': report_file,
            'models_trained': len(trained_models),
            'data_points': len(features)
        }
        
        logger.info("Análise preditiva concluída")
        return results


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Predictive Analyzer...")
    
    analyzer = PredictiveAnalyzer()
    results = analyzer.run_complete_analysis()
    
    if results:
        logger.info("Análise concluída com sucesso!")
        logger.info(f"Modelos treinados: {results['models_trained']}")
        logger.info(f"Pontos de dados: {results['data_points']}")
        logger.info(f"Relatório: {results['report_file']}")
    else:
        logger.error("Análise falhou")


if __name__ == "__main__":
    main() 