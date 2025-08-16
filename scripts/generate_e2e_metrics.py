#!/usr/bin/env python3
"""
Script de Geração de Métricas E2E
- Analisa resultados de testes E2E
- Gera métricas de performance e qualidade
- Cria relatórios HTML e JSON

📐 CoCoT: Baseado em métricas padrão de qualidade de testes E2E
🌲 ToT: Múltiplas estratégias de análise implementadas
♻️ ReAct: Simulado para diferentes cenários de métricas

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T11:20:00Z
**Tracing ID:** GENERATE_E2E_METRICS_md1ppfhs
**Origem:** Necessidade de métricas de performance e qualidade para testes E2E
"""

import os
import json
import argparse
import glob
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import statistics

@dataclass
class TestMetrics:
    """Métricas de um teste específico"""
    test_name: str
    duration: float
    status: str
    browser: str
    shard: int
    timestamp: str
    error_message: Optional[str] = None
    screenshot_path: Optional[str] = None
    video_path: Optional[str] = None

@dataclass
class SuiteMetrics:
    """Métricas da suite completa"""
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    total_duration: float
    avg_duration: float
    median_duration: float
    min_duration: float
    max_duration: float
    success_rate: float
    browsers: List[str]
    shards: List[int]
    execution_time: str

class E2EMetricsGenerator:
    """Gerador de métricas E2E"""
    
    def __init__(self, results_dir: str = 'test-results'):
        self.results_dir = results_dir
        self.metrics: List[TestMetrics] = []
        
    def load_results(self) -> None:
        """Carrega resultados dos testes"""
        # Procurar por arquivos de resultados
        result_files = glob.glob(f"{self.results_dir}/**/*.json", recursive=True)
        
        for file_path in result_files:
            if 'results.json' in file_path or 'test-results.json' in file_path:
                self._parse_result_file(file_path)
    
    def _parse_result_file(self, file_path: str) -> None:
        """Parse um arquivo de resultados específico"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extrair métricas baseado na estrutura do Playwright
            if 'suites' in data:
                self._parse_playwright_results(data)
            elif 'tests' in data:
                self._parse_simple_results(data)
                
        except Exception as e:
            print(f"⚠️ Erro ao parsear {file_path}: {e}")
    
    def _parse_playwright_results(self, data: Dict[str, Any]) -> None:
        """Parse resultados do Playwright"""
        for suite in data.get('suites', []):
            for spec in suite.get('specs', []):
                for test in spec.get('tests', []):
                    for result in test.get('results', []):
                        metrics = TestMetrics(
                            test_name=f"{spec['title']} - {test['title']}",
                            duration=result.get('duration', 0) / 1000,  # Converter para segundos
                            status=result.get('status', 'unknown'),
                            browser=result.get('workerIndex', 'unknown'),
                            shard=result.get('workerIndex', 0),
                            timestamp=result.get('startTime', datetime.now().isoformat()),
                            error_message=result.get('error', {}).get('message') if result.get('error') else None,
                            screenshot_path=self._find_screenshot(test['title']),
                            video_path=self._find_video(test['title'])
                        )
                        self.metrics.append(metrics)
    
    def _parse_simple_results(self, data: Dict[str, Any]) -> None:
        """Parse resultados simples"""
        for test in data.get('tests', []):
            metrics = TestMetrics(
                test_name=test.get('name', 'Unknown Test'),
                duration=test.get('duration', 0),
                status=test.get('status', 'unknown'),
                browser=test.get('browser', 'unknown'),
                shard=test.get('shard', 0),
                timestamp=test.get('timestamp', datetime.now().isoformat()),
                error_message=test.get('error'),
                screenshot_path=test.get('screenshot'),
                video_path=test.get('video')
            )
            self.metrics.append(metrics)
    
    def _find_screenshot(self, test_name: str) -> Optional[str]:
        """Encontra screenshot para um teste"""
        screenshot_pattern = f"{self.results_dir}/**/*{test_name.replace(' ', '_')}*.png"
        screenshots = glob.glob(screenshot_pattern, recursive=True)
        return screenshots[0] if screenshots else None
    
    def _find_video(self, test_name: str) -> Optional[str]:
        """Encontra vídeo para um teste"""
        video_pattern = f"{self.results_dir}/**/*{test_name.replace(' ', '_')}*.webm"
        videos = glob.glob(video_pattern, recursive=True)
        return videos[0] if videos else None
    
    def generate_suite_metrics(self) -> SuiteMetrics:
        """Gera métricas da suite completa"""
        if not self.metrics:
            return SuiteMetrics(
                total_tests=0,
                passed_tests=0,
                failed_tests=0,
                skipped_tests=0,
                total_duration=0,
                avg_duration=0,
                median_duration=0,
                min_duration=0,
                max_duration=0,
                success_rate=0,
                browsers=[],
                shards=[],
                execution_time='0s'
            )
        
        durations = [m.duration for m in self.metrics]
        passed = len([m for m in self.metrics if m.status == 'passed'])
        failed = len([m for m in self.metrics if m.status == 'failed'])
        skipped = len([m for m in self.metrics if m.status == 'skipped'])
        browsers = list(set([m.browser for m in self.metrics]))
        shards = list(set([m.shard for m in self.metrics]))
        
        return SuiteMetrics(
            total_tests=len(self.metrics),
            passed_tests=passed,
            failed_tests=failed,
            skipped_tests=skipped,
            total_duration=sum(durations),
            avg_duration=statistics.mean(durations) if durations else 0,
            median_duration=statistics.median(durations) if durations else 0,
            min_duration=min(durations) if durations else 0,
            max_duration=max(durations) if durations else 0,
            success_rate=(passed / len(self.metrics) * 100) if self.metrics else 0,
            browsers=browsers,
            shards=shards,
            execution_time=self._format_duration(sum(durations))
        )
    
    def _format_duration(self, seconds: float) -> str:
        """Formata duração em formato legível"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Gera relatório de performance"""
        suite_metrics = self.generate_suite_metrics()
        
        # Análise por browser
        browser_metrics = {}
        for browser in suite_metrics.browsers:
            browser_tests = [m for m in self.metrics if m.browser == browser]
            browser_durations = [m.duration for m in browser_tests]
            browser_passed = len([m for m in browser_tests if m.status == 'passed'])
            
            browser_metrics[browser] = {
                'total_tests': len(browser_tests),
                'passed_tests': browser_passed,
                'success_rate': (browser_passed / len(browser_tests) * 100) if browser_tests else 0,
                'avg_duration': statistics.mean(browser_durations) if browser_durations else 0,
                'median_duration': statistics.median(browser_durations) if browser_durations else 0,
                'min_duration': min(browser_durations) if browser_durations else 0,
                'max_duration': max(browser_durations) if browser_durations else 0
            }
        
        # Análise por shard
        shard_metrics = {}
        for shard in suite_metrics.shards:
            shard_tests = [m for m in self.metrics if m.shard == shard]
            shard_durations = [m.duration for m in shard_tests]
            shard_passed = len([m for m in shard_tests if m.status == 'passed'])
            
            shard_metrics[f"shard_{shard}"] = {
                'total_tests': len(shard_tests),
                'passed_tests': shard_passed,
                'success_rate': (shard_passed / len(shard_tests) * 100) if shard_tests else 0,
                'avg_duration': statistics.mean(shard_durations) if shard_durations else 0,
                'total_duration': sum(shard_durations)
            }
        
        # Testes mais lentos
        slowest_tests = sorted(self.metrics, key=lambda x: x.duration, reverse=True)[:10]
        
        # Testes com falha
        failed_tests = [m for m in self.metrics if m.status == 'failed']
        
        return {
            'timestamp': datetime.now().isoformat(),
            'suite_metrics': {
                'total_tests': suite_metrics.total_tests,
                'passed_tests': suite_metrics.passed_tests,
                'failed_tests': suite_metrics.failed_tests,
                'skipped_tests': suite_metrics.skipped_tests,
                'total_duration': suite_metrics.total_duration,
                'avg_duration': suite_metrics.avg_duration,
                'median_duration': suite_metrics.median_duration,
                'min_duration': suite_metrics.min_duration,
                'max_duration': suite_metrics.max_duration,
                'success_rate': suite_metrics.success_rate,
                'execution_time': suite_metrics.execution_time
            },
            'browser_metrics': browser_metrics,
            'shard_metrics': shard_metrics,
            'slowest_tests': [
                {
                    'test_name': t.test_name,
                    'duration': t.duration,
                    'browser': t.browser,
                    'shard': t.shard
                }
                for t in slowest_tests
            ],
            'failed_tests': [
                {
                    'test_name': t.test_name,
                    'duration': t.duration,
                    'browser': t.browser,
                    'shard': t.shard,
                    'error_message': t.error_message
                }
                for t in failed_tests
            ],
            'recommendations': self._generate_recommendations(suite_metrics, browser_metrics)
        }
    
    def _generate_recommendations(self, suite_metrics: SuiteMetrics, browser_metrics: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas nas métricas"""
        recommendations = []
        
        # Análise de sucesso
        if suite_metrics.success_rate < 95:
            recommendations.append(f"Taxa de sucesso baixa ({suite_metrics.success_rate:.1f}%). Investigar falhas.")
        
        # Análise de performance
        if suite_metrics.avg_duration > 30:
            recommendations.append(f"Tempo médio alto ({suite_metrics.avg_duration:.1f}s). Otimizar testes lentos.")
        
        if suite_metrics.max_duration > 120:
            recommendations.append(f"Teste muito lento detectado ({suite_metrics.max_duration:.1f}s). Revisar.")
        
        # Análise por browser
        for browser, metrics in browser_metrics.items():
            if metrics['success_rate'] < 90:
                recommendations.append(f"Browser {browser} com baixa taxa de sucesso ({metrics['success_rate']:.1f}%).")
            
            if metrics['avg_duration'] > suite_metrics.avg_duration * 1.5:
                recommendations.append(f"Browser {browser} mais lento que a média ({metrics['avg_duration']:.1f}s).")
        
        return recommendations
    
    def generate_html_report(self, report_data: Dict[str, Any], output_path: str) -> None:
        """Gera relatório HTML"""
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Métricas E2E - Omni Writer</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .content {{
            padding: 30px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        .table th, .table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .table th {{
            background-color: #f8f9fa;
            font-weight: 600;
            color: #333;
        }}
        .status-success {{ color: #28a745; }}
        .status-failure {{ color: #dc3545; }}
        .status-warning {{ color: #ffc107; }}
        .recommendations {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        .recommendations h3 {{
            color: #856404;
            margin-top: 0;
        }}
        .recommendations ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 5px;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Relatório de Métricas E2E</h1>
            <p>Omni Writer - {report_data['timestamp']}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📈 Métricas Gerais</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{report_data['suite_metrics']['total_tests']}</div>
                        <div class="metric-label">Total de Testes</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value status-success">{report_data['suite_metrics']['passed_tests']}</div>
                        <div class="metric-label">Testes Passaram</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value status-failure">{report_data['suite_metrics']['failed_tests']}</div>
                        <div class="metric-label">Testes Falharam</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report_data['suite_metrics']['success_rate']:.1f}%</div>
                        <div class="metric-label">Taxa de Sucesso</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report_data['suite_metrics']['execution_time']}</div>
                        <div class="metric-label">Tempo Total</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{report_data['suite_metrics']['avg_duration']:.1f}s</div>
                        <div class="metric-label">Tempo Médio</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🌐 Métricas por Browser</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Browser</th>
                            <th>Total</th>
                            <th>Passaram</th>
                            <th>Taxa Sucesso</th>
                            <th>Tempo Médio</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for browser, metrics in report_data['browser_metrics'].items():
            success_class = 'status-success' if metrics['success_rate'] >= 95 else 'status-failure'
            html_content += f"""
                        <tr>
                            <td><strong>{browser}</strong></td>
                            <td>{metrics['total_tests']}</td>
                            <td class="{success_class}">{metrics['passed_tests']}</td>
                            <td class="{success_class}">{metrics['success_rate']:.1f}%</td>
                            <td>{metrics['avg_duration']:.1f}s</td>
                        </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🐌 Testes Mais Lentos</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Teste</th>
                            <th>Duração</th>
                            <th>Browser</th>
                            <th>Shard</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for test in report_data['slowest_tests']:
            html_content += f"""
                        <tr>
                            <td>{test['test_name']}</td>
                            <td class="status-warning">{test['duration']:.1f}s</td>
                            <td>{test['browser']}</td>
                            <td>{test['shard']}</td>
                        </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
            </div>
        """
        
        if report_data['failed_tests']:
            html_content += """
            <div class="section">
                <h2>❌ Testes com Falha</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Teste</th>
                            <th>Duração</th>
                            <th>Browser</th>
                            <th>Shard</th>
                            <th>Erro</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for test in report_data['failed_tests']:
                html_content += f"""
                        <tr>
                            <td>{test['test_name']}</td>
                            <td>{test['duration']:.1f}s</td>
                            <td>{test['browser']}</td>
                            <td>{test['shard']}</td>
                            <td class="status-failure">{test['error_message'] or 'N/A'}</td>
                        </tr>
                """
            
            html_content += """
                    </tbody>
                </table>
            </div>
            """
        
        if report_data['recommendations']:
            html_content += """
            <div class="recommendations">
                <h3>💡 Recomendações</h3>
                <ul>
            """
            
            for rec in report_data['recommendations']:
                html_content += f"<li>{rec}</li>"
            
            html_content += """
                </ul>
            </div>
            """
        
        html_content += """
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Gerador de Métricas E2E')
    parser.add_argument('--results-dir', default='test-results', help='Diretório com resultados')
    parser.add_argument('--output', '-o', default='test-results/metrics.json', help='Arquivo de saída JSON')
    parser.add_argument('--html', help='Arquivo de saída HTML')
    
    args = parser.parse_args()
    
    generator = E2EMetricsGenerator(args.results_dir)
    
    print("📊 Carregando resultados dos testes...")
    generator.load_results()
    
    if not generator.metrics:
        print("⚠️ Nenhum resultado encontrado. Verifique o diretório de resultados.")
        return
    
    print(f"📈 Gerando métricas para {len(generator.metrics)} testes...")
    report_data = generator.generate_performance_report()
    
    # Salvar JSON
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"💾 Métricas salvas em: {args.output}")
    
    # Gerar HTML se solicitado
    if args.html:
        generator.generate_html_report(report_data, args.html)
        print(f"🌐 Relatório HTML salvo em: {args.html}")
    
    # Exibir resumo
    suite_metrics = report_data['suite_metrics']
    print(f"\n📊 Resumo:")
    print(f"   Total: {suite_metrics['total_tests']} testes")
    print(f"   Passaram: {suite_metrics['passed_tests']} ({suite_metrics['success_rate']:.1f}%)")
    print(f"   Falharam: {suite_metrics['failed_tests']}")
    print(f"   Tempo total: {suite_metrics['execution_time']}")
    print(f"   Tempo médio: {suite_metrics['avg_duration']:.1f}s")

if __name__ == '__main__':
    main() 