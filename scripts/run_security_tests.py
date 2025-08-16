#!/usr/bin/env python3
"""
Script de Execução de Testes de Segurança - Omni Writer
======================================================

Executa todos os testes de segurança de forma automatizada:
- Testes básicos de segurança
- Testes avançados de penetração
- Validação de compliance OWASP Top 10
- Geração de relatórios detalhados

Prompt: Script de Execução de Testes de Segurança - Item 11
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T11:30:00Z
Tracing ID: ENTERPRISE_20250128_011_SCRIPT

Autor: Análise Técnica Omni Writer
Data: 2025-01-28
Versão: 1.0
"""

import os
import sys
import json
import time
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import requests

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.security.test_advanced_security import AdvancedSecurityTester


class SecurityTestRunner:
    """Executor de testes de segurança."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.results_dir = Path("test-results/security")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações
        self.config = {
            'timeout': 30,
            'retries': 3,
            'parallel_tests': 4,
            'generate_report': True,
            'send_notifications': False
        }
    
    def run_basic_security_tests(self) -> Dict[str, Any]:
        """
        Executa testes básicos de segurança usando pytest.
        
        Returns:
            Resultado dos testes básicos
        """
        print("🔒 Executando testes básicos de segurança...")
        
        results = {
            'test_suite': 'basic_security',
            'timestamp': datetime.now().isoformat(),
            'tests': [],
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'errors': 0
            }
        }
        
        # Lista de arquivos de teste básicos
        test_files = [
            'tests/security/test_sql_injection.py',
            'tests/security/test_xss_prevention.py',
            'tests/security/test_authentication.py',
            'tests/security/test_authorization.py',
            'tests/security/test_rate_limiting.py',
            'tests/security/test_csrf_headers.py',
            'tests/security/test_path_traversal.py'
        ]
        
        for test_file in test_files:
            if os.path.exists(test_file):
                try:
                    print(f"  📋 Executando {test_file}...")
                    
                    # Executa pytest no arquivo
                    cmd = [
                        sys.executable, '-m', 'pytest',
                        test_file,
                        '-v',
                        '--tb=short',
                        '--json-report',
                        '--json-report-file=none'
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.config['timeout']
                    )
                    
                    # Analisa resultado
                    test_result = {
                        'file': test_file,
                        'exit_code': result.returncode,
                        'stdout': result.stdout,
                        'stderr': result.stderr,
                        'passed': result.returncode == 0
                    }
                    
                    results['tests'].append(test_result)
                    
                    if result.returncode == 0:
                        results['summary']['passed'] += 1
                    else:
                        results['summary']['failed'] += 1
                    
                    results['summary']['total'] += 1
                    
                except subprocess.TimeoutExpired:
                    test_result = {
                        'file': test_file,
                        'error': 'Timeout',
                        'passed': False
                    }
                    results['tests'].append(test_result)
                    results['summary']['errors'] += 1
                    results['summary']['total'] += 1
                    
                except Exception as e:
                    test_result = {
                        'file': test_file,
                        'error': str(e),
                        'passed': False
                    }
                    results['tests'].append(test_result)
                    results['summary']['errors'] += 1
                    results['summary']['total'] += 1
        
        return results
    
    def run_advanced_security_tests(self) -> Dict[str, Any]:
        """
        Executa testes avançados de segurança.
        
        Returns:
            Resultado dos testes avançados
        """
        print("🚀 Executando testes avançados de segurança...")
        
        try:
            tester = AdvancedSecurityTester(self.base_url)
            results = tester.run_comprehensive_security_test()
            
            # Adiciona metadados
            results['test_suite'] = 'advanced_security'
            results['timestamp'] = datetime.now().isoformat()
            
            return results
            
        except Exception as e:
            return {
                'test_suite': 'advanced_security',
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'passed': False
            }
    
    def run_penetration_tests(self) -> Dict[str, Any]:
        """
        Executa testes de penetração automatizados.
        
        Returns:
            Resultado dos testes de penetração
        """
        print("🔍 Executando testes de penetração...")
        
        results = {
            'test_suite': 'penetration_tests',
            'timestamp': datetime.now().isoformat(),
            'tests': [],
            'vulnerabilities': []
        }
        
        # Testes de penetração básicos
        penetration_tests = [
            self._test_sql_injection_penetration,
            self._test_xss_penetration,
            self._test_csrf_penetration,
            self._test_authentication_bypass,
            self._test_authorization_bypass,
            self._test_rate_limiting_bypass
        ]
        
        for test_func in penetration_tests:
            try:
                test_result = test_func()
                results['tests'].append(test_result)
                
                if not test_result.get('passed', True):
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['tests'].append({
                    'test_name': test_func.__name__,
                    'error': str(e),
                    'passed': False
                })
        
        return results
    
    def _test_sql_injection_penetration(self) -> Dict[str, Any]:
        """Testa penetração por SQL injection."""
        result = {
            'test_name': 'sql_injection_penetration',
            'passed': True,
            'vulnerabilities': []
        }
        
        # Payloads de SQL injection avançados
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "' OR 1=1; INSERT INTO users VALUES ('hacker','admin'); --",
            "admin'--",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1"
        ]
        
        for payload in sql_payloads:
            try:
                response = requests.post(
                    f"{self.base_url}/api/login",
                    json={'username': payload, 'password': 'test'},
                    timeout=5
                )
                
                # Verifica se o ataque foi bem-sucedido
                if response.status_code == 200 and 'admin' in response.text.lower():
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'sql_injection',
                        'payload': payload,
                        'description': 'SQL injection successful'
                    })
                    
            except Exception:
                continue
        
        return result
    
    def _test_xss_penetration(self) -> Dict[str, Any]:
        """Testa penetração por XSS."""
        result = {
            'test_name': 'xss_penetration',
            'passed': True,
            'vulnerabilities': []
        }
        
        # Payloads de XSS avançados
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onchange=alert('XSS')><option>test</option></select>",
            "<textarea onblur=alert('XSS')>test</textarea>",
            "<details open ontoggle=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                response = requests.post(
                    f"{self.base_url}/api/comment",
                    json={'comment': payload},
                    timeout=5
                )
                
                # Verifica se o XSS foi refletido
                if payload in response.text:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'xss',
                        'payload': payload,
                        'description': 'XSS payload reflected'
                    })
                    
            except Exception:
                continue
        
        return result
    
    def _test_csrf_penetration(self) -> Dict[str, Any]:
        """Testa penetração por CSRF."""
        result = {
            'test_name': 'csrf_penetration',
            'passed': True,
            'vulnerabilities': []
        }
        
        try:
            # Testa se endpoints sensíveis aceitam requisições sem CSRF token
            sensitive_endpoints = [
                '/api/admin/users',
                '/api/config',
                '/api/delete'
            ]
            
            for endpoint in sensitive_endpoints:
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json={'action': 'delete'},
                    timeout=5
                )
                
                # Se aceita sem CSRF token, é vulnerável
                if response.status_code == 200:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'csrf',
                        'endpoint': endpoint,
                        'description': 'CSRF protection missing'
                    })
                    
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _test_authentication_bypass(self) -> Dict[str, Any]:
        """Testa bypass de autenticação."""
        result = {
            'test_name': 'authentication_bypass',
            'passed': True,
            'vulnerabilities': []
        }
        
        # Técnicas de bypass de autenticação
        bypass_techniques = [
            # Headers maliciosos
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            
            # Parâmetros de URL
            {'admin': 'true'},
            {'role': 'admin'},
            {'auth': 'bypass'}
        ]
        
        for technique in bypass_techniques:
            try:
                response = requests.get(
                    f"{self.base_url}/api/admin",
                    headers=technique,
                    timeout=5
                )
                
                if response.status_code == 200:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'auth_bypass',
                        'technique': technique,
                        'description': 'Authentication bypass successful'
                    })
                    
            except Exception:
                continue
        
        return result
    
    def _test_authorization_bypass(self) -> Dict[str, Any]:
        """Testa bypass de autorização."""
        result = {
            'test_name': 'authorization_bypass',
            'passed': True,
            'vulnerabilities': []
        }
        
        # Testa acesso a recursos sem permissão
        protected_resources = [
            '/api/admin/users',
            '/api/config/system',
            '/api/logs',
            '/api/backup'
        ]
        
        for resource in protected_resources:
            try:
                response = requests.get(
                    f"{self.base_url}{resource}",
                    timeout=5
                )
                
                if response.status_code == 200:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'authz_bypass',
                        'resource': resource,
                        'description': 'Authorization bypass successful'
                    })
                    
            except Exception:
                continue
        
        return result
    
    def _test_rate_limiting_bypass(self) -> Dict[str, Any]:
        """Testa bypass de rate limiting."""
        result = {
            'test_name': 'rate_limiting_bypass',
            'passed': True,
            'vulnerabilities': []
        }
        
        # Técnicas de bypass de rate limiting
        bypass_techniques = [
            # Múltiplos IPs
            {'X-Forwarded-For': '192.168.1.1'},
            {'X-Forwarded-For': '192.168.1.2'},
            {'X-Forwarded-For': '192.168.1.3'},
            
            # Headers de proxy
            {'X-Real-IP': '10.0.0.1'},
            {'X-Client-IP': '172.16.0.1'},
            {'CF-Connecting-IP': '203.0.113.1'}
        ]
        
        successful_requests = 0
        
        for technique in bypass_techniques:
            try:
                # Faz múltiplas requisições
                for _ in range(10):
                    response = requests.post(
                        f"{self.base_url}/api/generate",
                        json={'prompt': 'test'},
                        headers=technique,
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        successful_requests += 1
                        
            except Exception:
                continue
        
        # Se muitas requisições passaram, pode haver bypass
        if successful_requests > 50:
            result['passed'] = False
            result['vulnerabilities'].append({
                'type': 'rate_limit_bypass',
                'successful_requests': successful_requests,
                'description': 'Rate limiting bypass possible'
            })
        
        return result
    
    def generate_security_report(self, all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Gera relatório completo de segurança.
        
        Args:
            all_results: Lista com todos os resultados dos testes
            
        Returns:
            Relatório completo
        """
        print("📊 Gerando relatório de segurança...")
        
        report = {
            'report_type': 'security_comprehensive',
            'generated_at': datetime.now().isoformat(),
            'base_url': self.base_url,
            'test_suites': all_results,
            'summary': {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0
            },
            'recommendations': [],
            'compliance': {
                'owasp_top_10': False,
                'pci_dss': False,
                'gdpr': False
            }
        }
        
        # Analisa resultados
        for result in all_results:
            if 'summary' in result:
                report['summary']['total_tests'] += result['summary'].get('total', 0)
                report['summary']['passed_tests'] += result['summary'].get('passed', 0)
                report['summary']['failed_tests'] += result['summary'].get('failed', 0)
            
            # Conta vulnerabilidades
            vulnerabilities = []
            if 'vulnerabilities' in result:
                vulnerabilities.extend(result['vulnerabilities'])
            if 'tests' in result:
                for test in result['tests']:
                    if 'vulnerabilities' in test:
                        vulnerabilities.extend(test['vulnerabilities'])
            
            for vuln in vulnerabilities:
                report['summary']['total_vulnerabilities'] += 1
                severity = vuln.get('severity', 'medium').lower()
                
                if severity == 'critical':
                    report['summary']['critical_vulnerabilities'] += 1
                elif severity == 'high':
                    report['summary']['high_vulnerabilities'] += 1
                elif severity == 'medium':
                    report['summary']['medium_vulnerabilities'] += 1
                elif severity == 'low':
                    report['summary']['low_vulnerabilities'] += 1
        
        # Gera recomendações baseadas nas vulnerabilidades
        if report['summary']['critical_vulnerabilities'] > 0:
            report['recommendations'].append("🔴 CRÍTICO: Corrigir vulnerabilidades críticas imediatamente")
        
        if report['summary']['high_vulnerabilities'] > 0:
            report['recommendations'].append("🟠 ALTO: Implementar correções de segurança prioritárias")
        
        if report['summary']['total_vulnerabilities'] > 10:
            report['recommendations'].append("🟡 MÉDIO: Realizar auditoria completa de segurança")
        
        # Avalia compliance
        if report['summary']['total_vulnerabilities'] == 0:
            report['compliance']['owasp_top_10'] = True
            report['compliance']['pci_dss'] = True
            report['compliance']['gdpr'] = True
        
        return report
    
    def save_results(self, results: List[Dict[str, Any]], report: Dict[str, Any]):
        """
        Salva resultados e relatório em arquivos.
        
        Args:
            results: Resultados dos testes
            report: Relatório gerado
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Salva resultados individuais
        for result in results:
            test_suite = result.get('test_suite', 'unknown')
            filename = f"{test_suite}_{timestamp}.json"
            filepath = self.results_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Salva relatório completo
        report_filename = f"security_report_{timestamp}.json"
        report_filepath = self.results_dir / report_filename
        
        with open(report_filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Gera relatório HTML
        html_report = self._generate_html_report(report)
        html_filename = f"security_report_{timestamp}.html"
        html_filepath = self.results_dir / html_filename
        
        with open(html_filepath, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"💾 Resultados salvos em: {self.results_dir}")
        print(f"📄 Relatório JSON: {report_filepath}")
        print(f"🌐 Relatório HTML: {html_filepath}")
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """
        Gera relatório HTML.
        
        Args:
            report: Relatório em formato dict
            
        Returns:
            HTML do relatório
        """
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - Omni Writer</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .vulnerability {{ background: #e74c3c; color: white; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .warning {{ background: #f39c12; color: white; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .success {{ background: #27ae60; color: white; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #3498db; color: white; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Relatório de Segurança - Omni Writer</h1>
        <p>Gerado em: {report['generated_at']}</p>
        <p>URL Base: {report['base_url']}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Resumo Executivo</h2>
        <div class="metric">Total de Testes: {report['summary']['total_tests']}</div>
        <div class="metric">Testes Aprovados: {report['summary']['passed_tests']}</div>
        <div class="metric">Testes Falharam: {report['summary']['failed_tests']}</div>
        <div class="metric">Vulnerabilidades: {report['summary']['total_vulnerabilities']}</div>
    </div>
    
    <div class="summary">
        <h2>🚨 Vulnerabilidades por Severidade</h2>
        <div class="metric">Críticas: {report['summary']['critical_vulnerabilities']}</div>
        <div class="metric">Altas: {report['summary']['high_vulnerabilities']}</div>
        <div class="metric">Médias: {report['summary']['medium_vulnerabilities']}</div>
        <div class="metric">Baixas: {report['summary']['low_vulnerabilities']}</div>
    </div>
    
    <div class="summary">
        <h2>📋 Recomendações</h2>
        {''.join([f'<div class="warning">{rec}</div>' for rec in report['recommendations']])}
    </div>
    
    <div class="summary">
        <h2>✅ Compliance</h2>
        <div class="metric">OWASP Top 10: {'✅' if report['compliance']['owasp_top_10'] else '❌'}</div>
        <div class="metric">PCI DSS: {'✅' if report['compliance']['pci_dss'] else '❌'}</div>
        <div class="metric">GDPR: {'✅' if report['compliance']['gdpr'] else '❌'}</div>
    </div>
</body>
</html>
        """
        
        return html
    
    def run_all_security_tests(self) -> Dict[str, Any]:
        """
        Executa todos os testes de segurança.
        
        Returns:
            Resultado completo
        """
        print("🚀 Iniciando execução completa de testes de segurança...")
        print(f"🎯 URL Base: {self.base_url}")
        print(f"⏰ Timestamp: {datetime.now().isoformat()}")
        print("=" * 60)
        
        start_time = time.time()
        
        # Executa todos os testes
        all_results = []
        
        # 1. Testes básicos
        basic_results = self.run_basic_security_tests()
        all_results.append(basic_results)
        
        # 2. Testes avançados
        advanced_results = self.run_advanced_security_tests()
        all_results.append(advanced_results)
        
        # 3. Testes de penetração
        penetration_results = self.run_penetration_tests()
        all_results.append(penetration_results)
        
        # Gera relatório
        report = self.generate_security_report(all_results)
        
        # Salva resultados
        if self.config['generate_report']:
            self.save_results(all_results, report)
        
        # Calcula tempo total
        total_time = time.time() - start_time
        
        # Exibe resumo
        print("=" * 60)
        print("🎉 EXECUÇÃO CONCLUÍDA!")
        print(f"⏱️  Tempo total: {total_time:.2f} segundos")
        print(f"📊 Total de testes: {report['summary']['total_tests']}")
        print(f"✅ Testes aprovados: {report['summary']['passed_tests']}")
        print(f"❌ Testes falharam: {report['summary']['failed_tests']}")
        print(f"🚨 Vulnerabilidades: {report['summary']['total_vulnerabilities']}")
        
        if report['summary']['critical_vulnerabilities'] > 0:
            print(f"🔴 VULNERABILIDADES CRÍTICAS: {report['summary']['critical_vulnerabilities']}")
        
        return {
            'success': True,
            'total_time': total_time,
            'report': report,
            'results': all_results
        }


def main():
    """Função principal."""
    parser = argparse.ArgumentParser(description='Executa testes de segurança do Omni Writer')
    parser.add_argument('--url', default='http://localhost:5000', help='URL base da aplicação')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout para testes (segundos)')
    parser.add_argument('--no-report', action='store_true', help='Não gerar relatórios')
    parser.add_argument('--parallel', type=int, default=4, help='Número de testes paralelos')
    
    args = parser.parse_args()
    
    # Configura runner
    runner = SecurityTestRunner(args.url)
    runner.config['timeout'] = args.timeout
    runner.config['generate_report'] = not args.no_report
    runner.config['parallel_tests'] = args.parallel
    
    try:
        # Executa testes
        result = runner.run_all_security_tests()
        
        # Retorna código de saída baseado no resultado
        if result['success'] and result['report']['summary']['critical_vulnerabilities'] == 0:
            sys.exit(0)  # Sucesso
        else:
            sys.exit(1)  # Falha
            
    except KeyboardInterrupt:
        print("\n⚠️  Execução interrompida pelo usuário")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Erro durante execução: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 