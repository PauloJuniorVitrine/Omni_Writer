"""
Heatmap Generator - Omni Writer
===============================

Gerador de heatmaps visuais para análise de performance dos testes de carga.
Baseado nos dados reais coletados dos testes de carga.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 2, Item 8
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T15:35:00Z
"""

import os
import json
import csv
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import pandas as pd
from pathlib import Path

class HeatmapGenerator:
    """
    Gerador de heatmaps para análise de performance dos testes de carga.
    Baseado nos dados reais dos fluxos críticos identificados.
    """
    
    def __init__(self, results_dir: str = "tests/load/results"):
        """
        Inicializa o gerador de heatmaps.
        
        Args:
            results_dir: Diretório com os resultados dos testes
        """
        self.results_dir = Path(results_dir)
        self.output_dir = Path("tests/load/visualization/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações baseadas no código real
        self.endpoints = [
            "/generate",      # Fluxo crítico 1
            "/download",      # Fluxo crítico 2
            "/export_prompts", # Fluxo crítico 3
            "/export_artigos_csv", # Fluxo crítico 4
            "/feedback",      # Fluxo crítico 5
            "/webhook",       # Fluxo crítico 6
            "/status"         # Fluxo crítico 7
        ]
        
        # Thresholds baseados no código real
        self.thresholds = {
            "response_time_ms": 800,
            "fail_rate": 0.02,  # 2%
            "cpu_usage": 90,
            "memory_usage": 85
        }
        
        print(f"[INFO] [heatmap] Inicializado - {datetime.now().isoformat()}")
        print(f"[INFO] [heatmap] Diretório de resultados: {self.results_dir}")
        print(f"[INFO] [heatmap] Diretório de saída: {self.output_dir}")

    def load_csv_data(self, file_path: Path) -> pd.DataFrame:
        """
        Carrega dados CSV dos testes de carga.
        Baseado no formato real dos arquivos de resultados.
        """
        try:
            df = pd.read_csv(file_path)
            
            # Normaliza colunas baseado no formato real
            if 'Average Response Time' in df.columns:
                df['response_time'] = df['Average Response Time']
            if 'Failure Count' in df.columns:
                df['failures'] = df['Failure Count']
            if 'Request Count' in df.columns:
                df['requests'] = df['Request Count']
            
            return df
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao carregar {file_path}: {e}")
            return pd.DataFrame()

    def generate_latency_heatmap(self, data: pd.DataFrame, title: str = "Latência por Endpoint e Carga") -> str:
        """
        Gera heatmap de latência baseado nos dados reais.
        """
        try:
            # Prepara dados para heatmap
            if data.empty:
                print("[WARNING] [heatmap] Dados vazios para heatmap de latência")
                return ""
            
            # Agrupa por endpoint e carga (usuários)
            pivot_data = data.pivot_table(
                values='response_time',
                index=data.index,  # Timestamp ou período
                columns='endpoint',
                aggfunc='mean'
            )
            
            # Configura visualização
            plt.figure(figsize=(12, 8))
            sns.set_style("whitegrid")
            
            # Gera heatmap
            heatmap = sns.heatmap(
                pivot_data,
                annot=True,
                fmt='.0f',
                cmap='RdYlBu_r',
                cbar_kws={'label': 'Latência (ms)'},
                linewidths=0.5
            )
            
            plt.title(f"{title}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            plt.xlabel('Endpoint')
            plt.ylabel('Período de Teste')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Salva arquivo
            output_file = self.output_dir / f"latency_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"[SUCCESS] [heatmap] Heatmap de latência gerado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar heatmap de latência: {e}")
            return ""

    def generate_throughput_heatmap(self, data: pd.DataFrame, title: str = "Throughput por Endpoint e Carga") -> str:
        """
        Gera heatmap de throughput baseado nos dados reais.
        """
        try:
            if data.empty:
                print("[WARNING] [heatmap] Dados vazios para heatmap de throughput")
                return ""
            
            # Calcula throughput (requests por segundo)
            data['throughput'] = data['requests'] / data.get('duration', 60)  # Assume 60s se não especificado
            
            # Agrupa por endpoint e carga
            pivot_data = data.pivot_table(
                values='throughput',
                index=data.index,
                columns='endpoint',
                aggfunc='mean'
            )
            
            plt.figure(figsize=(12, 8))
            sns.set_style("whitegrid")
            
            heatmap = sns.heatmap(
                pivot_data,
                annot=True,
                fmt='.1f',
                cmap='Greens',
                cbar_kws={'label': 'Throughput (req/s)'},
                linewidths=0.5
            )
            
            plt.title(f"{title}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            plt.xlabel('Endpoint')
            plt.ylabel('Período de Teste')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            output_file = self.output_dir / f"throughput_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"[SUCCESS] [heatmap] Heatmap de throughput gerado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar heatmap de throughput: {e}")
            return ""

    def generate_error_rate_heatmap(self, data: pd.DataFrame, title: str = "Taxa de Erro por Endpoint e Carga") -> str:
        """
        Gera heatmap de taxa de erro baseado nos dados reais.
        """
        try:
            if data.empty:
                print("[WARNING] [heatmap] Dados vazios para heatmap de erro")
                return ""
            
            # Calcula taxa de erro
            data['error_rate'] = (data['failures'] / data['requests']) * 100
            
            # Agrupa por endpoint e carga
            pivot_data = data.pivot_table(
                values='error_rate',
                index=data.index,
                columns='endpoint',
                aggfunc='mean'
            )
            
            plt.figure(figsize=(12, 8))
            sns.set_style("whitegrid")
            
            heatmap = sns.heatmap(
                pivot_data,
                annot=True,
                fmt='.2f',
                cmap='Reds',
                cbar_kws={'label': 'Taxa de Erro (%)'},
                linewidths=0.5
            )
            
            plt.title(f"{title}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            plt.xlabel('Endpoint')
            plt.ylabel('Período de Teste')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            output_file = self.output_dir / f"error_rate_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"[SUCCESS] [heatmap] Heatmap de taxa de erro gerado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar heatmap de taxa de erro: {e}")
            return ""

    def generate_multi_tenant_heatmap(self, data: pd.DataFrame, title: str = "Performance por Tenant") -> str:
        """
        Gera heatmap específico para análise multi-tenant.
        Baseado nos dados reais dos testes multi-tenant.
        """
        try:
            if data.empty or 'tenant_id' not in data.columns:
                print("[WARNING] [heatmap] Dados multi-tenant não encontrados")
                return ""
            
            # Agrupa por tenant e endpoint
            pivot_data = data.pivot_table(
                values='response_time',
                index='tenant_id',
                columns='endpoint',
                aggfunc='mean'
            )
            
            plt.figure(figsize=(14, 10))
            sns.set_style("whitegrid")
            
            heatmap = sns.heatmap(
                pivot_data,
                annot=True,
                fmt='.0f',
                cmap='viridis',
                cbar_kws={'label': 'Latência (ms)'},
                linewidths=0.5
            )
            
            plt.title(f"{title}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            plt.xlabel('Endpoint')
            plt.ylabel('Tenant ID')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            output_file = self.output_dir / f"multitenant_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"[SUCCESS] [heatmap] Heatmap multi-tenant gerado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar heatmap multi-tenant: {e}")
            return ""

    def generate_time_series_heatmap(self, data: pd.DataFrame, title: str = "Performance ao Longo do Tempo") -> str:
        """
        Gera heatmap de série temporal para análise de degradação.
        """
        try:
            if data.empty or 'timestamp' not in data.columns:
                print("[WARNING] [heatmap] Dados de timestamp não encontrados")
                return ""
            
            # Converte timestamp para período
            data['period'] = pd.to_datetime(data['timestamp']).dt.floor('5min')
            
            # Agrupa por período e endpoint
            pivot_data = data.pivot_table(
                values='response_time',
                index='period',
                columns='endpoint',
                aggfunc='mean'
            )
            
            plt.figure(figsize=(16, 10))
            sns.set_style("whitegrid")
            
            heatmap = sns.heatmap(
                pivot_data,
                annot=False,  # Muitos dados
                cmap='RdYlBu_r',
                cbar_kws={'label': 'Latência (ms)'},
                linewidths=0.1
            )
            
            plt.title(f"{title}\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            plt.xlabel('Endpoint')
            plt.ylabel('Período de Tempo')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            output_file = self.output_dir / f"timeseries_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"[SUCCESS] [heatmap] Heatmap de série temporal gerado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar heatmap de série temporal: {e}")
            return ""

    def process_all_results(self) -> Dict[str, str]:
        """
        Processa todos os resultados e gera heatmaps.
        """
        print(f"[INFO] [heatmap] Iniciando processamento de todos os resultados...")
        
        generated_files = {}
        
        # Busca todos os arquivos CSV
        csv_files = list(self.results_dir.glob("*.csv"))
        
        if not csv_files:
            print("[WARNING] [heatmap] Nenhum arquivo CSV encontrado")
            return generated_files
        
        # Combina dados de todos os arquivos
        all_data = []
        
        for csv_file in csv_files:
            df = self.load_csv_data(csv_file)
            if not df.empty:
                # Adiciona metadados do arquivo
                df['source_file'] = csv_file.name
                df['test_type'] = csv_file.stem.split('_')[0]  # generate, download, etc.
                all_data.append(df)
        
        if not all_data:
            print("[WARNING] [heatmap] Nenhum dado válido encontrado")
            return generated_files
        
        # Combina todos os dados
        combined_data = pd.concat(all_data, ignore_index=True)
        
        # Gera heatmaps
        try:
            # Heatmap de latência
            latency_file = self.generate_latency_heatmap(combined_data)
            if latency_file:
                generated_files['latency'] = latency_file
            
            # Heatmap de throughput
            throughput_file = self.generate_throughput_heatmap(combined_data)
            if throughput_file:
                generated_files['throughput'] = throughput_file
            
            # Heatmap de taxa de erro
            error_file = self.generate_error_rate_heatmap(combined_data)
            if error_file:
                generated_files['error_rate'] = error_file
            
            # Heatmap multi-tenant (se houver dados)
            if 'tenant_id' in combined_data.columns:
                tenant_file = self.generate_multi_tenant_heatmap(combined_data)
                if tenant_file:
                    generated_files['multitenant'] = tenant_file
            
            # Heatmap de série temporal (se houver timestamp)
            if 'timestamp' in combined_data.columns:
                timeseries_file = self.generate_time_series_heatmap(combined_data)
                if timeseries_file:
                    generated_files['timeseries'] = timeseries_file
                    
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro durante processamento: {e}")
        
        # Gera relatório
        self.generate_report(generated_files, combined_data)
        
        print(f"[SUCCESS] [heatmap] Processamento concluído - {len(generated_files)} heatmaps gerados")
        return generated_files

    def generate_report(self, generated_files: Dict[str, str], data: pd.DataFrame) -> str:
        """
        Gera relatório com análise dos heatmaps.
        """
        try:
            report_file = self.output_dir / f"heatmap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Heatmaps - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de heatmaps gerados:** {len(generated_files)}\n")
                f.write(f"- **Período analisado:** {data.get('timestamp', 'N/A').min()} a {data.get('timestamp', 'N/A').max()}\n")
                f.write(f"- **Total de endpoints testados:** {len(self.endpoints)}\n\n")
                
                f.write("## Heatmaps Gerados\n\n")
                for heatmap_type, file_path in generated_files.items():
                    f.write(f"### {heatmap_type.title()}\n")
                    f.write(f"- **Arquivo:** {file_path}\n")
                    f.write(f"- **Descrição:** Análise de {heatmap_type}\n\n")
                
                f.write("## Análise de Performance\n\n")
                
                # Análise por endpoint
                if 'endpoint' in data.columns:
                    f.write("### Performance por Endpoint\n\n")
                    endpoint_stats = data.groupby('endpoint')['response_time'].agg(['mean', 'std', 'max']).round(2)
                    f.write(endpoint_stats.to_markdown())
                    f.write("\n\n")
                
                # Análise de thresholds
                f.write("### Análise de Thresholds\n\n")
                f.write(f"- **Threshold de latência:** {self.thresholds['response_time_ms']}ms\n")
                f.write(f"- **Threshold de erro:** {self.thresholds['fail_rate']*100}%\n")
                
                # Identifica violações
                if 'response_time' in data.columns:
                    slow_requests = data[data['response_time'] > self.thresholds['response_time_ms']]
                    if not slow_requests.empty:
                        f.write(f"- **Requests lentos:** {len(slow_requests)} ({len(slow_requests)/len(data)*100:.1f}%)\n")
                
                if 'failures' in data.columns and 'requests' in data.columns:
                    high_error_endpoints = data[data['failures']/data['requests'] > self.thresholds['fail_rate']]
                    if not high_error_endpoints.empty:
                        f.write(f"- **Endpoints com alta taxa de erro:** {len(high_error_endpoints)}\n")
                
                f.write("\n## Recomendações\n\n")
                f.write("1. **Monitoramento contínuo** dos endpoints com maior latência\n")
                f.write("2. **Investigação** de endpoints com alta taxa de erro\n")
                f.write("3. **Otimização** de endpoints que excedem thresholds\n")
                f.write("4. **Análise de capacidade** para planejamento de infraestrutura\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            print(f"[SUCCESS] [heatmap] Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao gerar relatório: {e}")
            return ""

    def export_to_grafana_format(self, data: pd.DataFrame) -> str:
        """
        Exporta dados em formato compatível com Grafana.
        """
        try:
            grafana_file = self.output_dir / f"grafana_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Formata dados para Grafana
            grafana_data = {
                "targets": [],
                "timeRange": {
                    "from": data.get('timestamp', pd.Timestamp.now()).min().isoformat(),
                    "to": data.get('timestamp', pd.Timestamp.now()).max().isoformat()
                }
            }
            
            # Adiciona métricas por endpoint
            for endpoint in self.endpoints:
                endpoint_data = data[data['endpoint'] == endpoint]
                if not endpoint_data.empty:
                    grafana_data["targets"].append({
                        "target": f"latency_{endpoint}",
                        "datapoints": endpoint_data[['timestamp', 'response_time']].values.tolist()
                    })
            
            with open(grafana_file, 'w', encoding='utf-8') as f:
                json.dump(grafana_data, f, indent=2, default=str)
            
            print(f"[SUCCESS] [heatmap] Dados exportados para Grafana: {grafana_file}")
            return str(grafana_file)
            
        except Exception as e:
            print(f"[ERROR] [heatmap] Erro ao exportar para Grafana: {e}")
            return ""


def main():
    """
    Função principal para execução direta.
    """
    print("[INFO] [heatmap] Iniciando gerador de heatmaps...")
    
    generator = HeatmapGenerator()
    generated_files = generator.process_all_results()
    
    print(f"[SUCCESS] [heatmap] Processamento concluído!")
    print(f"[INFO] [heatmap] Arquivos gerados: {list(generated_files.keys())}")


if __name__ == "__main__":
    main() 