"""
Módulo de Versionamento Semântico - Omni Writer
Implementa versionamento semântico (SemVer 2.0.0) e estratégia de breaking changes

Tracing ID: VERSIONING_20250127_001
"""

import re
import json
import yaml
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pathlib import Path

class VersionType(Enum):
    """Tipos de versão"""
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"

class BreakingChangeType(Enum):
    """Tipos de breaking changes"""
    ENDPOINT_REMOVED = "endpoint_removed"
    PARAMETER_REMOVED = "parameter_removed"
    RESPONSE_CHANGED = "response_changed"
    AUTHENTICATION_CHANGED = "authentication_changed"
    SCHEMA_CHANGED = "schema_changed"

@dataclass
class Version:
    """Representa uma versão semântica"""
    major: int
    minor: int
    patch: int
    prerelease: Optional[str] = None
    build: Optional[str] = None
    
    def __str__(self) -> str:
        version = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version += f"-{self.prerelease}"
        if self.build:
            version += f"+{self.build}"
        return version
    
    @classmethod
    def parse(cls, version_string: str) -> 'Version':
        """Parse string de versão"""
        pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'
        match = re.match(pattern, version_string)
        
        if not match:
            raise ValueError(f"Versão inválida: {version_string}")
        
        major, minor, patch, prerelease, build = match.groups()
        return cls(
            major=int(major),
            minor=int(minor),
            patch=int(patch),
            prerelease=prerelease,
            build=build
        )
    
    def bump(self, version_type: VersionType) -> 'Version':
        """Incrementa versão"""
        if version_type == VersionType.MAJOR:
            return Version(self.major + 1, 0, 0)
        elif version_type == VersionType.MINOR:
            return Version(self.major, self.minor + 1, 0)
        elif version_type == VersionType.PATCH:
            return Version(self.major, self.minor, self.patch + 1)
        else:
            raise ValueError(f"Tipo de versão inválido: {version_type}")

@dataclass
class BreakingChange:
    """Representa uma breaking change"""
    type: BreakingChangeType
    description: str
    affected_endpoints: List[str]
    migration_guide: Optional[str] = None
    deprecated_since: Optional[str] = None
    sunset_date: Optional[str] = None
    severity: str = "high"  # low, medium, high, critical
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return asdict(self)

@dataclass
class VersionInfo:
    """Informações de uma versão"""
    version: str
    status: str  # stable, beta, deprecated
    release_date: str
    deprecated: bool = False
    sunset_date: Optional[str] = None
    breaking_changes: List[BreakingChange] = None
    features: List[str] = None
    bugfixes: List[str] = None
    security_fixes: List[str] = None
    
    def __post_init__(self):
        if self.breaking_changes is None:
            self.breaking_changes = []
        if self.features is None:
            self.features = []
        if self.bugfixes is None:
            self.bugfixes = []
        if self.security_fixes is None:
            self.security_fixes = []

class SemanticVersioning:
    """Gerenciador de versionamento semântico"""
    
    def __init__(self, config_file: str = "versioning_config.yaml"):
        self.config_file = Path(config_file)
        self.current_version = Version(2, 0, 0)
        self.version_history: List[VersionInfo] = []
        self.breaking_changes: List[BreakingChange] = []
        self.load_config()
    
    def load_config(self):
        """Carrega configuração de versionamento"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                
                self.current_version = Version.parse(config.get('current_version', '2.0.0'))
                self.version_history = [
                    VersionInfo(**v) for v in config.get('version_history', [])
                ]
                self.breaking_changes = [
                    BreakingChange(**bc) for bc in config.get('breaking_changes', [])
                ]
                
            except Exception as e:
                print(f"Erro ao carregar configuração: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Cria configuração padrão"""
        self.version_history = [
            VersionInfo(
                version="1.0.0",
                status="deprecated",
                release_date="2024-01-01",
                deprecated=True,
                sunset_date="2025-06-01",
                breaking_changes=[],
                features=["API inicial"],
                bugfixes=[],
                security_fixes=[]
            ),
            VersionInfo(
                version="2.0.0",
                status="stable",
                release_date=datetime.now().strftime("%Y-%m-%d"),
                deprecated=False,
                sunset_date=None,
                breaking_changes=[],
                features=["Versionamento semântico", "Breaking changes"],
                bugfixes=[],
                security_fixes=[]
            )
        ]
        self.save_config()
    
    def save_config(self):
        """Salva configuração"""
        try:
            config = {
                'current_version': str(self.current_version),
                'version_history': [asdict(v) for v in self.version_history],
                'breaking_changes': [bc.to_dict() for bc in self.breaking_changes]
            }
            
            self.config_file.parent.mkdir(exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
                
        except Exception as e:
            print(f"Erro ao salvar configuração: {e}")
    
    def add_breaking_change(self, breaking_change: BreakingChange):
        """Adiciona breaking change"""
        self.breaking_changes.append(breaking_change)
        self.save_config()
    
    def bump_version(self, version_type: VersionType, prerelease: Optional[str] = None) -> str:
        """Incrementa versão"""
        new_version = self.current_version.bump(version_type)
        if prerelease:
            new_version.prerelease = prerelease
        
        self.current_version = new_version
        
        # Adiciona à história
        version_info = VersionInfo(
            version=str(new_version),
            status="beta" if prerelease else "stable",
            release_date=datetime.now().strftime("%Y-%m-%d"),
            deprecated=False,
            sunset_date=None,
            breaking_changes=[],
            features=[],
            bugfixes=[],
            security_fixes=[]
        )
        
        self.version_history.append(version_info)
        self.save_config()
        
        return str(new_version)
    
    def deprecate_version(self, version: str, sunset_date: Optional[str] = None):
        """Marca versão como deprecated"""
        for v in self.version_history:
            if v.version == version:
                v.deprecated = True
                v.status = "deprecated"
                if sunset_date:
                    v.sunset_date = sunset_date
                else:
                    # Sunset padrão: 6 meses
                    release_date = datetime.strptime(v.release_date, "%Y-%m-%d")
                    sunset = release_date + timedelta(days=180)
                    v.sunset_date = sunset.strftime("%Y-%m-%d")
                break
        
        self.save_config()
    
    def get_version_info(self, version: str) -> Optional[VersionInfo]:
        """Obtém informações de uma versão"""
        for v in self.version_history:
            if v.version == version:
                return v
        return None
    
    def get_deprecated_versions(self) -> List[VersionInfo]:
        """Obtém versões deprecated"""
        return [v for v in self.version_history if v.deprecated]
    
    def get_breaking_changes_since(self, version: str) -> List[BreakingChange]:
        """Obtém breaking changes desde uma versão"""
        try:
            target_version = Version.parse(version)
            changes = []
            
            for bc in self.breaking_changes:
                # Aqui você pode implementar lógica mais sofisticada
                # para determinar quando a breaking change foi introduzida
                changes.append(bc)
            
            return changes
            
        except ValueError:
            return []
    
    def generate_changelog(self, from_version: str, to_version: str) -> str:
        """Gera changelog entre versões"""
        try:
            from_v = Version.parse(from_version)
            to_v = Version.parse(to_version)
            
            changelog = f"# Changelog: {from_version} → {to_version}\n\n"
            
            # Encontra versões no intervalo
            versions_in_range = []
            for v in self.version_history:
                try:
                    v_parsed = Version.parse(v.version)
                    if from_v <= v_parsed <= to_v:
                        versions_in_range.append(v)
                except ValueError:
                    continue
            
            # Ordena por versão
            versions_in_range.sort(key=lambda x: Version.parse(x.version))
            
            for version_info in versions_in_range:
                changelog += f"## {version_info.version} ({version_info.release_date})\n\n"
                
                if version_info.features:
                    changelog += "### ✨ Novas Funcionalidades\n"
                    for feature in version_info.features:
                        changelog += f"- {feature}\n"
                    changelog += "\n"
                
                if version_info.bugfixes:
                    changelog += "### 🐛 Correções\n"
                    for bugfix in version_info.bugfixes:
                        changelog += f"- {bugfix}\n"
                    changelog += "\n"
                
                if version_info.security_fixes:
                    changelog += "### 🔒 Correções de Segurança\n"
                    for security_fix in version_info.security_fixes:
                        changelog += f"- {security_fix}\n"
                    changelog += "\n"
                
                if version_info.breaking_changes:
                    changelog += "### ⚠️ Breaking Changes\n"
                    for bc in version_info.breaking_changes:
                        changelog += f"- **{bc.type.value}**: {bc.description}\n"
                        if bc.migration_guide:
                            changelog += f"  - Guia de migração: {bc.migration_guide}\n"
                    changelog += "\n"
            
            return changelog
            
        except ValueError as e:
            return f"Erro ao gerar changelog: {e}"
    
    def validate_api_compatibility(self, old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> List[str]:
        """Valida compatibilidade entre especificações OpenAPI"""
        issues = []
        
        old_paths = old_spec.get('paths', {})
        new_paths = new_spec.get('paths', {})
        
        # Verifica endpoints removidos
        for path in old_paths:
            if path not in new_paths:
                issues.append(f"Endpoint removido: {path}")
                continue
            
            old_methods = old_paths[path]
            new_methods = new_paths[path]
            
            for method in old_methods:
                if method not in new_methods:
                    issues.append(f"Método removido: {method} {path}")
                    continue
                
                # Verifica parâmetros
                old_params = old_methods[method].get('parameters', [])
                new_params = new_methods[method].get('parameters', [])
                
                old_param_names = {p['name'] for p in old_params}
                new_param_names = {p['name'] for p in new_params}
                
                removed_params = old_param_names - new_param_names
                for param in removed_params:
                    issues.append(f"Parâmetro removido: {param} em {method} {path}")
        
        return issues
    
    def create_migration_guide(self, from_version: str, to_version: str) -> str:
        """Cria guia de migração entre versões"""
        breaking_changes = self.get_breaking_changes_since(from_version)
        
        if not breaking_changes:
            return f"# Guia de Migração: {from_version} → {to_version}\n\nNenhuma breaking change encontrada."
        
        guide = f"# Guia de Migração: {from_version} → {to_version}\n\n"
        guide += "## Breaking Changes\n\n"
        
        for bc in breaking_changes:
            guide += f"### {bc.type.value.replace('_', ' ').title()}\n\n"
            guide += f"**Descrição:** {bc.description}\n\n"
            
            if bc.affected_endpoints:
                guide += "**Endpoints Afetados:**\n"
                for endpoint in bc.affected_endpoints:
                    guide += f"- `{endpoint}`\n"
                guide += "\n"
            
            if bc.migration_guide:
                guide += f"**Como Migrar:**\n{bc.migration_guide}\n\n"
            
            if bc.deprecated_since:
                guide += f"**Deprecated desde:** {bc.deprecated_since}\n\n"
            
            if bc.sunset_date:
                guide += f"**Data de Sunset:** {bc.sunset_date}\n\n"
            
            guide += "---\n\n"
        
        return guide

# Instância global
versioning = SemanticVersioning()

# Funções de conveniência
def get_current_version() -> str:
    """Obtém versão atual"""
    return str(versioning.current_version)

def bump_major_version(prerelease: Optional[str] = None) -> str:
    """Incrementa versão major"""
    return versioning.bump_version(VersionType.MAJOR, prerelease)

def bump_minor_version(prerelease: Optional[str] = None) -> str:
    """Incrementa versão minor"""
    return versioning.bump_version(VersionType.MINOR, prerelease)

def bump_patch_version(prerelease: Optional[str] = None) -> str:
    """Incrementa versão patch"""
    return versioning.bump_version(VersionType.PATCH, prerelease)

def add_breaking_change(
    change_type: BreakingChangeType,
    description: str,
    affected_endpoints: List[str],
    migration_guide: Optional[str] = None,
    severity: str = "high"
) -> BreakingChange:
    """Adiciona breaking change"""
    breaking_change = BreakingChange(
        type=change_type,
        description=description,
        affected_endpoints=affected_endpoints,
        migration_guide=migration_guide,
        severity=severity
    )
    versioning.add_breaking_change(breaking_change)
    return breaking_change

def generate_changelog(from_version: str, to_version: str) -> str:
    """Gera changelog entre versões"""
    return versioning.generate_changelog(from_version, to_version)

def create_migration_guide(from_version: str, to_version: str) -> str:
    """Cria guia de migração entre versões"""
    return versioning.create_migration_guide(from_version, to_version) 