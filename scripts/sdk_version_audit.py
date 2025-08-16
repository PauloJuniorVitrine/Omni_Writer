#!/usr/bin/env python3
"""
SDK Version Audit System - Omni Writer
=====================================

Sistema de auditoria de versões de SDK para monitorar compatibilidade
e detectar breaking changes automaticamente.

Tracing ID: SDK_AUDIT_20250127_001
Ruleset: enterprise_control_layer.yaml
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import semver
import requests
from dataclasses import dataclass, asdict

@dataclass
class SDKVersion:
    """Representa uma versão de SDK com metadados."""
    name: str
    current_version: str
    latest_version: str
    last_check: datetime
    breaking_changes: List[str]
    compatibility_score: float
    status: str  # 'compatible', 'deprecated', 'breaking', 'unknown'

@dataclass
class AuditResult:
    """Resultado da auditoria de SDK."""
    timestamp: datetime
    total_sdks: int
    compatible_sdks: int
    breaking_changes: int
    deprecated_sdks: int
    recommendations: List[str]
    risk_score: float

class SDKVersionAuditor:
    """Auditor de versões de SDK com detecção de breaking changes."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.audit_log_path = self.project_root / "logs" / "sdk_audit.log"
        self.results_path = self.project_root / "monitoring" / "sdk_audit_results.json"
        self.tracing_id = f"SDK_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configurar logging estruturado
        self._setup_logging()
        
    def _setup_logging(self):
        """Configura logging estruturado para auditoria."""
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] [SDK_AUDIT] %(message)s',
            handlers=[
                logging.FileHandler(self.audit_log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _log_audit_event(self, event: str, details: Dict = None):
        """Registra evento de auditoria com metadados."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": self.tracing_id,
            "event": event,
            "details": details or {}
        }
        self.logger.info(f"SDK Audit Event: {json.dumps(log_entry)}")
        
    def detect_sdks(self) -> List[str]:
        """Detecta SDKs utilizados no projeto."""
        self._log_audit_event("detecting_sdks")
        
        sdks = []
        
        # Verificar requirements.txt
        requirements_path = self.project_root / "requirements.txt"
        if requirements_path.exists():
            with open(requirements_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extrair nome do pacote
                        package_name = re.split(r'[<>=!]', line)[0].strip()
                        sdks.append(package_name)
        
        # Verificar package.json (se existir)
        package_json_path = self.project_root / "package.json"
        if package_json_path.exists():
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
                dependencies = package_data.get('dependencies', {})
                dev_dependencies = package_data.get('devDependencies', {})
                
                for dep in list(dependencies.keys()) + list(dev_dependencies.keys()):
                    if dep not in sdks:
                        sdks.append(dep)
        
        self._log_audit_event("sdks_detected", {"count": len(sdks), "sdks": sdks})
        return sdks
    
    def get_current_version(self, sdk_name: str) -> Optional[str]:
        """Obtém versão atual de um SDK."""
        try:
            # Para Python
            if sdk_name in sys.modules:
                module = sys.modules[sdk_name]
                if hasattr(module, '__version__'):
                    return module.__version__
            
            # Tentar via pip
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'show', sdk_name],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Version:'):
                        return line.split(':', 1)[1].strip()
            
            # Para Node.js
            if Path("package-lock.json").exists():
                with open("package-lock.json", 'r') as f:
                    lock_data = json.load(f)
                    if 'dependencies' in lock_data:
                        for dep_name, dep_info in lock_data['dependencies'].items():
                            if dep_name == sdk_name:
                                return dep_info.get('version', 'unknown')
                                
        except Exception as e:
            self.logger.warning(f"Erro ao obter versão atual de {sdk_name}: {e}")
            
        return None
    
    def get_latest_version(self, sdk_name: str) -> Optional[str]:
        """Obtém versão mais recente de um SDK."""
        try:
            # Para Python (PyPI)
            response = requests.get(f"https://pypi.org/pypi/{sdk_name}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data['info']['version']
            
            # Para Node.js (npm)
            response = requests.get(f"https://registry.npmjs.org/{sdk_name}/latest", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data['version']
                
        except Exception as e:
            self.logger.warning(f"Erro ao obter versão mais recente de {sdk_name}: {e}")
            
        return None
    
    def detect_breaking_changes(self, sdk_name: str, current_version: str, latest_version: str) -> List[str]:
        """Detecta possíveis breaking changes entre versões."""
        breaking_changes = []
        
        try:
            # Análise semântica de versão
            if current_version and latest_version:
                current_semver = semver.VersionInfo.parse(current_version)
                latest_semver = semver.VersionInfo.parse(latest_version)
                
                # Major version bump indica breaking change
                if latest_semver.major > current_semver.major:
                    breaking_changes.append(f"Major version bump: {current_version} -> {latest_version}")
                
                # Verificar changelog se disponível
                changelog_urls = [
                    f"https://pypi.org/pypi/{sdk_name}/{latest_version}/json",
                    f"https://registry.npmjs.org/{sdk_name}/{latest_version}"
                ]
                
                for url in changelog_urls:
                    try:
                        response = requests.get(url, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            # Procurar por keywords de breaking changes
                            changelog_text = json.dumps(data).lower()
                            breaking_keywords = ['breaking', 'deprecated', 'removed', 'changed']
                            
                            for keyword in breaking_keywords:
                                if keyword in changelog_text:
                                    breaking_changes.append(f"Breaking change detected: {keyword}")
                                    break
                    except:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"Erro ao detectar breaking changes para {sdk_name}: {e}")
            
        return breaking_changes
    
    def calculate_compatibility_score(self, sdk_name: str, current_version: str, latest_version: str, breaking_changes: List[str]) -> float:
        """Calcula score de compatibilidade (0-100)."""
        if not current_version or not latest_version:
            return 0.0
            
        try:
            current_semver = semver.VersionInfo.parse(current_version)
            latest_semver = semver.VersionInfo.parse(latest_version)
            
            # Base score baseado na diferença de versão
            major_diff = latest_semver.major - current_semver.major
            minor_diff = latest_semver.minor - current_semver.minor
            patch_diff = latest_semver.patch - current_semver.patch
            
            # Penalidades
            major_penalty = major_diff * 30  # Major version é crítico
            minor_penalty = minor_diff * 10   # Minor version é importante
            patch_penalty = patch_diff * 2    # Patch é menor impacto
            
            breaking_penalty = len(breaking_changes) * 20
            
            score = 100 - major_penalty - minor_penalty - patch_penalty - breaking_penalty
            return max(0.0, min(100.0, score))
            
        except Exception as e:
            self.logger.warning(f"Erro ao calcular score de compatibilidade para {sdk_name}: {e}")
            return 50.0  # Score neutro em caso de erro
    
    def audit_sdk(self, sdk_name: str) -> SDKVersion:
        """Audita um SDK específico."""
        self._log_audit_event("auditing_sdk", {"sdk_name": sdk_name})
        
        current_version = self.get_current_version(sdk_name)
        latest_version = self.get_latest_version(sdk_name)
        breaking_changes = self.detect_breaking_changes(sdk_name, current_version, latest_version)
        compatibility_score = self.calculate_compatibility_score(sdk_name, current_version, latest_version, breaking_changes)
        
        # Determinar status
        if compatibility_score >= 80:
            status = "compatible"
        elif compatibility_score >= 60:
            status = "deprecated"
        elif breaking_changes:
            status = "breaking"
        else:
            status = "unknown"
        
        sdk_version = SDKVersion(
            name=sdk_name,
            current_version=current_version or "unknown",
            latest_version=latest_version or "unknown",
            last_check=datetime.now(),
            breaking_changes=breaking_changes,
            compatibility_score=compatibility_score,
            status=status
        )
        
        self._log_audit_event("sdk_audited", {
            "sdk_name": sdk_name,
            "status": status,
            "compatibility_score": compatibility_score,
            "breaking_changes_count": len(breaking_changes)
        })
        
        return sdk_version
    
    def generate_recommendations(self, sdk_versions: List[SDKVersion]) -> List[str]:
        """Gera recomendações baseadas na auditoria."""
        recommendations = []
        
        breaking_sdks = [sdk for sdk in sdk_versions if sdk.status == "breaking"]
        deprecated_sdks = [sdk for sdk in sdk_versions if sdk.status == "deprecated"]
        
        if breaking_sdks:
            recommendations.append(f"⚠️ {len(breaking_sdks)} SDK(s) com breaking changes detectados. Revisar antes de atualizar.")
            
        if deprecated_sdks:
            recommendations.append(f"📋 {len(deprecated_sdks)} SDK(s) marcados como deprecated. Considerar migração.")
        
        # Recomendações específicas
        for sdk in sdk_versions:
            if sdk.compatibility_score < 50:
                recommendations.append(f"🚨 {sdk.name}: Score de compatibilidade baixo ({sdk.compatibility_score:.1f}). Revisar urgente.")
            elif sdk.compatibility_score < 80:
                recommendations.append(f"⚠️ {sdk.name}: Considerar atualização (score: {sdk.compatibility_score:.1f})")
        
        return recommendations
    
    def calculate_risk_score(self, sdk_versions: List[SDKVersion]) -> float:
        """Calcula score de risco geral do projeto."""
        if not sdk_versions:
            return 0.0
            
        total_risk = 0.0
        weights = {
            "breaking": 1.0,
            "deprecated": 0.7,
            "unknown": 0.5,
            "compatible": 0.1
        }
        
        for sdk in sdk_versions:
            weight = weights.get(sdk.status, 0.5)
            risk_factor = (100 - sdk.compatibility_score) / 100
            total_risk += weight * risk_factor
        
        return min(100.0, (total_risk / len(sdk_versions)) * 100)
    
    def run_audit(self) -> AuditResult:
        """Executa auditoria completa de SDKs."""
        self._log_audit_event("starting_full_audit")
        
        # Detectar SDKs
        sdk_names = self.detect_sdks()
        
        # Auditar cada SDK
        sdk_versions = []
        for sdk_name in sdk_names:
            sdk_version = self.audit_sdk(sdk_name)
            sdk_versions.append(sdk_version)
        
        # Gerar recomendações
        recommendations = self.generate_recommendations(sdk_versions)
        
        # Calcular métricas
        total_sdks = len(sdk_versions)
        compatible_sdks = len([sdk for sdk in sdk_versions if sdk.status == "compatible"])
        breaking_changes = len([sdk for sdk in sdk_versions if sdk.status == "breaking"])
        deprecated_sdks = len([sdk for sdk in sdk_versions if sdk.status == "deprecated"])
        risk_score = self.calculate_risk_score(sdk_versions)
        
        # Criar resultado
        result = AuditResult(
            timestamp=datetime.now(),
            total_sdks=total_sdks,
            compatible_sdks=compatible_sdks,
            breaking_changes=breaking_changes,
            deprecated_sdks=deprecated_sdks,
            recommendations=recommendations,
            risk_score=risk_score
        )
        
        # Salvar resultados
        self._save_results(sdk_versions, result)
        
        self._log_audit_event("audit_completed", {
            "total_sdks": total_sdks,
            "compatible_sdks": compatible_sdks,
            "breaking_changes": breaking_changes,
            "risk_score": risk_score
        })
        
        return result
    
    def _save_results(self, sdk_versions: List[SDKVersion], audit_result: AuditResult):
        """Salva resultados da auditoria."""
        results_data = {
            "audit_result": asdict(audit_result),
            "sdk_versions": [asdict(sdk) for sdk in sdk_versions],
            "metadata": {
                "tracing_id": self.tracing_id,
                "generated_at": datetime.now().isoformat(),
                "ruleset": "enterprise_control_layer.yaml"
            }
        }
        
        # Converter datetime para string
        results_data["audit_result"]["timestamp"] = results_data["audit_result"]["timestamp"].isoformat()
        for sdk_data in results_data["sdk_versions"]:
            sdk_data["last_check"] = sdk_data["last_check"].isoformat()
        
        # Salvar em JSON
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self._log_audit_event("results_saved", {"path": str(self.results_path)})
    
    def generate_report(self) -> str:
        """Gera relatório em markdown da auditoria."""
        if not self.results_path.exists():
            return "❌ Nenhum resultado de auditoria encontrado."
        
        with open(self.results_path, 'r') as f:
            data = json.load(f)
        
        audit_result = data["audit_result"]
        sdk_versions = data["sdk_versions"]
        
        report = f"""# 🔍 SDK Version Audit Report

**Tracing ID:** {data['metadata']['tracing_id']}  
**Generated:** {data['metadata']['generated_at']}  
**Ruleset:** {data['metadata']['ruleset']}

## 📊 Summary

- **Total SDKs:** {audit_result['total_sdks']}
- **Compatible:** {audit_result['compatible_sdks']}
- **Breaking Changes:** {audit_result['breaking_changes']}
- **Deprecated:** {audit_result['deprecated_sdks']}
- **Risk Score:** {audit_result['risk_score']:.1f}/100

## 🚨 Recommendations

"""
        
        for rec in audit_result['recommendations']:
            report += f"- {rec}\n"
        
        report += "\n## 📋 SDK Details\n\n"
        report += "| SDK | Current | Latest | Status | Score | Breaking Changes |\n"
        report += "|-----|---------|--------|--------|-------|------------------|\n"
        
        for sdk in sdk_versions:
            breaking_count = len(sdk['breaking_changes'])
            report += f"| {sdk['name']} | {sdk['current_version']} | {sdk['latest_version']} | {sdk['status']} | {sdk['compatibility_score']:.1f} | {breaking_count} |\n"
        
        return report

def main():
    """Função principal para execução da auditoria."""
    project_root = os.getcwd()
    auditor = SDKVersionAuditor(project_root)
    
    print("🔍 Iniciando auditoria de versões de SDK...")
    result = auditor.run_audit()
    
    print(f"\n📊 Resultados da Auditoria:")
    print(f"   Total SDKs: {result.total_sdks}")
    print(f"   Compatíveis: {result.compatible_sdks}")
    print(f"   Breaking Changes: {result.breaking_changes}")
    print(f"   Score de Risco: {result.risk_score:.1f}/100")
    
    print(f"\n🚨 Recomendações:")
    for rec in result.recommendations:
        print(f"   {rec}")
    
    # Gerar relatório
    report = auditor.generate_report()
    report_path = Path(project_root) / "docs" / f"sdk_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\n📄 Relatório salvo em: {report_path}")
    print(f"📊 Resultados JSON: {auditor.results_path}")

if __name__ == "__main__":
    main() 