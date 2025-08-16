"""
Script de Auditoria de SDKs para Omni Writer.
Verifica sincronização entre frontend e backend, detecta divergências e gera alertas.

Prompt: Implementação de SDK Version Audit
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T11:15:00Z
Tracing ID: SDK_AUDITOR_20250128_001
"""
import os
import json
import hashlib
import logging
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import yaml
import subprocess
import sys

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sdk_auditor")

@dataclass
class SDKVersion:
    """Representa uma versão de SDK com metadados."""
    name: str
    version: str
    hash: str
    last_updated: datetime
    source: str
    dependencies: List[str]
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'name': self.name,
            'version': self.version,
            'hash': self.hash,
            'last_updated': self.last_updated.isoformat(),
            'source': self.source,
            'dependencies': self.dependencies
        }

@dataclass
class AuditResult:
    """Resultado da auditoria de SDK."""
    sdk_name: str
    status: str  # 'synced', 'outdated', 'missing', 'conflict'
    frontend_version: Optional[SDKVersion]
    backend_version: Optional[SDKVersion]
    differences: List[str]
    recommendations: List[str]
    severity: str  # 'low', 'medium', 'high', 'critical'
    
    def to_dict(self) -> Dict:
        """Converte para dicionário para serialização."""
        return {
            'sdk_name': self.sdk_name,
            'status': self.status,
            'frontend_version': self.frontend_version.to_dict() if self.frontend_version else None,
            'backend_version': self.backend_version.to_dict() if self.backend_version else None,
            'differences': self.differences,
            'recommendations': self.recommendations,
            'severity': self.severity,
            'timestamp': datetime.utcnow().isoformat()
        }

class SDKAuditor:
    """
    Auditor de SDKs para verificar sincronização entre frontend e backend.
    Baseado no código real do projeto Omni Writer.
    """
    
    def __init__(self, config_path: str = "scripts/sdk_auditor_config.json"):
        """
        Inicializa o auditor de SDKs.
        
        Args:
            config_path: Caminho para arquivo de configuração
        """
        self.config = self._load_config(config_path)
        self.results: List[AuditResult] = []
        self.trace_id = f"SDK_AUDIT_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"SDK Auditor inicializado | trace_id={self.trace_id}")
    
    def _load_config(self, config_path: str) -> Dict:
        """Carrega configuração do auditor."""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                # Configuração padrão baseada no projeto real
                return {
                    "sdk_paths": {
                        "frontend": "ui/",
                        "backend": "app/",
                        "shared": "shared/"
                    },
                    "sdk_files": {
                        "typescript": ["ui/hooks/use_api.ts", "ui/components/api/"],
                        "python": ["app/routes.py", "app/services/"],
                        "openapi": ["docs/openapi.v2.yaml"]
                    },
                    "hash_algorithms": ["md5", "sha256"],
                    "alert_thresholds": {
                        "version_diff_days": 7,
                        "hash_mismatch": "critical",
                        "missing_sdk": "high"
                    },
                    "notification_channels": ["slack", "email"]
                }
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            return {}
    
    def calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """
        Calcula hash de um arquivo.
        
        Args:
            file_path: Caminho do arquivo
            algorithm: Algoritmo de hash (md5, sha256)
            
        Returns:
            Hash do arquivo
        """
        try:
            if not os.path.exists(file_path):
                return ""
            
            hash_func = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except Exception as e:
            logger.error(f"Erro ao calcular hash de {file_path}: {e}")
            return ""
    
    def get_sdk_version(self, sdk_path: str, sdk_type: str) -> Optional[SDKVersion]:
        """
        Obtém versão de um SDK específico.
        
        Args:
            sdk_path: Caminho do SDK
            sdk_type: Tipo do SDK (typescript, python, openapi)
            
        Returns:
            Versão do SDK ou None se não encontrado
        """
        try:
            if not os.path.exists(sdk_path):
                return None
            
            # Calcula hash do arquivo/diretório
            if os.path.isfile(sdk_path):
                file_hash = self.calculate_file_hash(sdk_path)
                last_modified = datetime.fromtimestamp(os.path.getmtime(sdk_path))
            else:
                # Para diretórios, calcula hash de todos os arquivos
                file_hash = self._calculate_directory_hash(sdk_path)
                last_modified = datetime.fromtimestamp(os.path.getmtime(sdk_path))
            
            # Extrai versão baseada no tipo
            version = self._extract_version(sdk_path, sdk_type)
            
            # Obtém dependências
            dependencies = self._get_dependencies(sdk_path, sdk_type)
            
            return SDKVersion(
                name=os.path.basename(sdk_path),
                version=version,
                hash=file_hash,
                last_updated=last_modified,
                source=sdk_path,
                dependencies=dependencies
            )
            
        except Exception as e:
            logger.error(f"Erro ao obter versão do SDK {sdk_path}: {e}")
            return None
    
    def _calculate_directory_hash(self, dir_path: str) -> str:
        """Calcula hash de um diretório baseado em todos os arquivos."""
        try:
            hash_func = hashlib.sha256()
            
            for root, _, files in os.walk(dir_path):
                for file in sorted(files):
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        with open(file_path, 'rb') as f:
                            hash_func.update(f.read())
            
            return hash_func.hexdigest()
            
        except Exception as e:
            logger.error(f"Erro ao calcular hash do diretório {dir_path}: {e}")
            return ""
    
    def _extract_version(self, sdk_path: str, sdk_type: str) -> str:
        """Extrai versão do SDK baseado no tipo."""
        try:
            if sdk_type == "typescript":
                # Procura por package.json ou versão em comentários
                package_json = os.path.join(os.path.dirname(sdk_path), "package.json")
                if os.path.exists(package_json):
                    with open(package_json, 'r') as f:
                        data = json.load(f)
                        return data.get('version', '1.0.0')
                
            elif sdk_type == "python":
                # Procura por __version__ ou setup.py
                setup_py = os.path.join(os.path.dirname(sdk_path), "setup.py")
                if os.path.exists(setup_py):
                    # Extrai versão do setup.py
                    with open(setup_py, 'r') as f:
                        content = f.read()
                        if 'version=' in content:
                            import re
                            match = re.search(r"version=['\"]([^'\"]+)['\"]", content)
                            if match:
                                return match.group(1)
                
            elif sdk_type == "openapi":
                # Extrai versão do OpenAPI spec
                if os.path.exists(sdk_path):
                    with open(sdk_path, 'r') as f:
                        spec = yaml.safe_load(f)
                        return spec.get('info', {}).get('version', '1.0.0')
            
            # Fallback: usa timestamp
            return datetime.utcnow().strftime('%Y%m%d.%H%M%S')
            
        except Exception as e:
            logger.error(f"Erro ao extrair versão de {sdk_path}: {e}")
            return 'unknown'
    
    def _get_dependencies(self, sdk_path: str, sdk_type: str) -> List[str]:
        """Obtém dependências do SDK."""
        try:
            dependencies = []
            
            if sdk_type == "typescript":
                package_json = os.path.join(os.path.dirname(sdk_path), "package.json")
                if os.path.exists(package_json):
                    with open(package_json, 'r') as f:
                        data = json.load(f)
                        dependencies.extend(data.get('dependencies', {}).keys())
                        dependencies.extend(data.get('devDependencies', {}).keys())
                
            elif sdk_type == "python":
                requirements_txt = os.path.join(os.path.dirname(sdk_path), "requirements.txt")
                if os.path.exists(requirements_txt):
                    with open(requirements_txt, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                dependencies.append(line.split('==')[0].split('>=')[0].split('<=')[0])
            
            return dependencies
            
        except Exception as e:
            logger.error(f"Erro ao obter dependências de {sdk_path}: {e}")
            return []
    
    def compare_sdk_versions(self, frontend_version: Optional[SDKVersion], 
                           backend_version: Optional[SDKVersion]) -> AuditResult:
        """
        Compara versões de SDK entre frontend e backend.
        
        Args:
            frontend_version: Versão do frontend
            backend_version: Versão do backend
            
        Returns:
            Resultado da auditoria
        """
        sdk_name = frontend_version.name if frontend_version else backend_version.name if backend_version else "unknown"
        
        if not frontend_version and not backend_version:
            return AuditResult(
                sdk_name=sdk_name,
                status="missing",
                frontend_version=None,
                backend_version=None,
                differences=["SDK não encontrado em frontend e backend"],
                recommendations=["Verificar se o SDK foi removido intencionalmente"],
                severity="high"
            )
        
        if not frontend_version:
            return AuditResult(
                sdk_name=sdk_name,
                status="missing",
                frontend_version=None,
                backend_version=backend_version,
                differences=["SDK não encontrado no frontend"],
                recommendations=["Implementar SDK no frontend ou remover do backend"],
                severity="high"
            )
        
        if not backend_version:
            return AuditResult(
                sdk_name=sdk_name,
                status="missing",
                frontend_version=frontend_version,
                backend_version=None,
                differences=["SDK não encontrado no backend"],
                recommendations=["Implementar SDK no backend ou remover do frontend"],
                severity="high"
            )
        
        # Compara versões
        differences = []
        recommendations = []
        severity = "low"
        
        if frontend_version.version != backend_version.version:
            differences.append(f"Versão frontend ({frontend_version.version}) != backend ({backend_version.version})")
            recommendations.append("Sincronizar versões entre frontend e backend")
            severity = "medium"
        
        if frontend_version.hash != backend_version.hash:
            differences.append("Hash do conteúdo diferente entre frontend e backend")
            recommendations.append("Verificar se as implementações estão sincronizadas")
            severity = "critical"
        
        # Verifica dependências
        frontend_deps = set(frontend_version.dependencies)
        backend_deps = set(backend_version.dependencies)
        
        missing_in_backend = frontend_deps - backend_deps
        missing_in_frontend = backend_deps - frontend_deps
        
        if missing_in_backend:
            differences.append(f"Dependências no frontend não encontradas no backend: {missing_in_backend}")
            recommendations.append("Adicionar dependências faltantes no backend")
            severity = "medium"
        
        if missing_in_frontend:
            differences.append(f"Dependências no backend não encontradas no frontend: {missing_in_frontend}")
            recommendations.append("Adicionar dependências faltantes no frontend")
            severity = "medium"
        
        # Verifica data de atualização
        days_diff = abs((frontend_version.last_updated - backend_version.last_updated).days)
        if days_diff > self.config.get('alert_thresholds', {}).get('version_diff_days', 7):
            differences.append(f"Diferença de {days_diff} dias na última atualização")
            recommendations.append("Sincronizar atualizações entre frontend e backend")
            severity = "medium"
        
        status = "synced" if not differences else "conflict"
        
        return AuditResult(
            sdk_name=sdk_name,
            status=status,
            frontend_version=frontend_version,
            backend_version=backend_version,
            differences=differences,
            recommendations=recommendations,
            severity=severity
        )
    
    def audit_all_sdks(self) -> List[AuditResult]:
        """
        Executa auditoria completa de todos os SDKs.
        
        Returns:
            Lista de resultados da auditoria
        """
        logger.info(f"Iniciando auditoria completa de SDKs | trace_id={self.trace_id}")
        
        sdk_files = self.config.get('sdk_files', {})
        results = []
        
        for sdk_type, paths in sdk_files.items():
            for path in paths:
                try:
                    # Obtém versões
                    frontend_path = os.path.join(self.config.get('sdk_paths', {}).get('frontend', ''), path)
                    backend_path = os.path.join(self.config.get('sdk_paths', {}).get('backend', ''), path)
                    
                    frontend_version = self.get_sdk_version(frontend_path, sdk_type)
                    backend_version = self.get_sdk_version(backend_path, sdk_type)
                    
                    # Compara versões
                    result = self.compare_sdk_versions(frontend_version, backend_version)
                    results.append(result)
                    
                    logger.info(f"Auditoria concluída para {path} | status={result.status} | severity={result.severity}")
                    
                except Exception as e:
                    logger.error(f"Erro na auditoria de {path}: {e}")
                    results.append(AuditResult(
                        sdk_name=path,
                        status="error",
                        frontend_version=None,
                        backend_version=None,
                        differences=[f"Erro na auditoria: {str(e)}"],
                        recommendations=["Verificar configuração e permissões"],
                        severity="high"
                    ))
        
        self.results = results
        return results
    
    def generate_report(self, output_path: str = "logs/sdk_audit_report.json") -> str:
        """
        Gera relatório da auditoria.
        
        Args:
            output_path: Caminho para salvar o relatório
            
        Returns:
            Caminho do relatório gerado
        """
        try:
            # Cria diretório se não existir
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            report = {
                'trace_id': self.trace_id,
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'total_sdks': len(self.results),
                    'synced': len([r for r in self.results if r.status == 'synced']),
                    'conflicts': len([r for r in self.results if r.status == 'conflict']),
                    'missing': len([r for r in self.results if r.status == 'missing']),
                    'errors': len([r for r in self.results if r.status == 'error'])
                },
                'results': [result.to_dict() for result in self.results],
                'recommendations': self._generate_recommendations()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Relatório gerado: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""
    
    def _generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas nos resultados."""
        recommendations = []
        
        critical_issues = [r for r in self.results if r.severity == 'critical']
        if critical_issues:
            recommendations.append(f"Resolver {len(critical_issues)} problemas críticos de sincronização")
        
        missing_sdks = [r for r in self.results if r.status == 'missing']
        if missing_sdks:
            recommendations.append(f"Implementar {len(missing_sdks)} SDKs faltantes")
        
        version_conflicts = [r for r in self.results if r.status == 'conflict']
        if version_conflicts:
            recommendations.append(f"Sincronizar versões de {len(version_conflicts)} SDKs")
        
        if not recommendations:
            recommendations.append("Todos os SDKs estão sincronizados")
        
        return recommendations
    
    def send_alerts(self) -> bool:
        """
        Envia alertas para canais configurados.
        
        Returns:
            True se alertas foram enviados com sucesso
        """
        try:
            channels = self.config.get('notification_channels', [])
            critical_results = [r for r in self.results if r.severity in ['high', 'critical']]
            
            if not critical_results:
                logger.info("Nenhum alerta crítico para enviar")
                return True
            
            alert_message = self._format_alert_message(critical_results)
            
            for channel in channels:
                if channel == 'slack':
                    self._send_slack_alert(alert_message)
                elif channel == 'email':
                    self._send_email_alert(alert_message)
            
            logger.info(f"Alertas enviados para {len(channels)} canais")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar alertas: {e}")
            return False
    
    def _format_alert_message(self, critical_results: List[AuditResult]) -> str:
        """Formata mensagem de alerta."""
        message = f"🚨 ALERTA SDK AUDITOR - {len(critical_results)} problemas críticos detectados\n\n"
        
        for result in critical_results:
            message += f"• {result.sdk_name}: {result.status} ({result.severity})\n"
            for diff in result.differences[:2]:  # Limita a 2 diferenças
                message += f"  - {diff}\n"
            message += "\n"
        
        return message
    
    def _send_slack_alert(self, message: str) -> bool:
        """Envia alerta para Slack."""
        # Implementação baseada no código real de notificações
        try:
            webhook_url = os.getenv('SLACK_WEBHOOK_URL')
            if webhook_url:
                payload = {'text': message}
                response = requests.post(webhook_url, json=payload, timeout=10)
                return response.status_code == 200
            return False
        except Exception as e:
            logger.error(f"Erro ao enviar alerta Slack: {e}")
            return False
    
    def _send_email_alert(self, message: str) -> bool:
        """Envia alerta por email."""
        # Implementação baseada no código real de notificações
        try:
            # Mock para demonstração
            logger.info(f"Email alert seria enviado: {message[:100]}...")
            return True
        except Exception as e:
            logger.error(f"Erro ao enviar alerta email: {e}")
            return False

def main():
    """Função principal do script."""
    try:
        # Inicializa auditor
        auditor = SDKAuditor()
        
        # Executa auditoria
        results = auditor.audit_all_sdks()
        
        # Gera relatório
        report_path = auditor.generate_report()
        
        # Envia alertas se necessário
        auditor.send_alerts()
        
        # Resumo
        synced = len([r for r in results if r.status == 'synced'])
        total = len(results)
        
        print(f"✅ Auditoria concluída: {synced}/{total} SDKs sincronizados")
        print(f"📊 Relatório: {report_path}")
        
        if synced < total:
            print("⚠️  Problemas detectados. Verifique o relatório para detalhes.")
            return 1
        else:
            print("🎉 Todos os SDKs estão sincronizados!")
            return 0
            
    except Exception as e:
        logger.error(f"Erro na execução do auditor: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 