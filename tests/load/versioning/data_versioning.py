"""
Data Versioning System - Omni Writer
====================================

Sistema de versionamento de dados para testes de carga.
Permite controle de versão de payloads, parâmetros e configurações.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 12
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:00:00Z
"""

import os
import json
import hashlib
import time
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import logging
import git
from dataclasses import dataclass, asdict
import yaml
import pickle
from copy import deepcopy

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('data_versioning')

@dataclass
class DataVersion:
    """Estrutura para versionamento de dados."""
    version_id: str
    timestamp: datetime
    description: str
    author: str
    data_hash: str
    parent_version: Optional[str] = None
    tags: List[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class PayloadVersion:
    """Versionamento específico de payloads."""
    payload_id: str
    version: str
    endpoint: str
    payload_data: Dict[str, Any]
    validation_rules: Dict[str, Any]
    created_at: datetime
    is_active: bool = True

class DataVersioningSystem:
    """
    Sistema de versionamento de dados para testes de carga.
    Permite controle de versão de payloads, parâmetros e configurações.
    """
    
    def __init__(self, 
                 base_dir: str = "tests/load/versioning",
                 git_repo_path: str = "."):
        """
        Inicializa o sistema de versionamento.
        
        Args:
            base_dir: Diretório base para versionamento
            git_repo_path: Caminho para repositório Git
        """
        self.base_dir = Path(base_dir)
        self.git_repo_path = Path(git_repo_path)
        
        # Diretórios específicos
        self.payloads_dir = self.base_dir / "payloads"
        self.configs_dir = self.base_dir / "configs"
        self.backups_dir = self.base_dir / "backups"
        self.metadata_dir = self.base_dir / "metadata"
        
        # Cria diretórios
        for dir_path in [self.payloads_dir, self.configs_dir, self.backups_dir, self.metadata_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Arquivo de controle de versões
        self.versions_file = self.base_dir / "versions.json"
        self.payloads_file = self.base_dir / "payloads.json"
        
        # Histórico de versões
        self.versions: List[DataVersion] = []
        self.payloads: Dict[str, PayloadVersion] = {}
        
        # Configurações
        self.versioning_config = {
            "auto_backup": True,
            "max_versions": 100,
            "backup_retention_days": 30,
            "git_integration": True,
            "hash_algorithm": "sha256"
        }
        
        # Inicializa Git se disponível
        self.git_repo = None
        if self.versioning_config["git_integration"]:
            try:
                self.git_repo = git.Repo(self.git_repo_path)
                logger.info("Integração Git ativada")
            except Exception as e:
                logger.warning(f"Git não disponível: {e}")
        
        # Carrega dados existentes
        self.load_existing_data()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Diretório base: {self.base_dir}")

    def load_existing_data(self) -> None:
        """
        Carrega dados de versionamento existentes.
        """
        try:
            # Carrega versões
            if self.versions_file.exists():
                with open(self.versions_file, 'r', encoding='utf-8') as f:
                    versions_data = json.load(f)
                    self.versions = [DataVersion(**v) for v in versions_data]
                logger.info(f"Carregadas {len(self.versions)} versões existentes")
            
            # Carrega payloads
            if self.payloads_file.exists():
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    payloads_data = json.load(f)
                    self.payloads = {k: PayloadVersion(**v) for k, v in payloads_data.items()}
                logger.info(f"Carregados {len(self.payloads)} payloads existentes")
                
        except Exception as e:
            logger.error(f"Erro ao carregar dados existentes: {e}")

    def save_data(self) -> None:
        """
        Salva dados de versionamento.
        """
        try:
            # Salva versões
            versions_data = [asdict(v) for v in self.versions]
            with open(self.versions_file, 'w', encoding='utf-8') as f:
                json.dump(versions_data, f, indent=2, default=str)
            
            # Salva payloads
            payloads_data = {k: asdict(v) for k, v in self.payloads.items()}
            with open(self.payloads_file, 'w', encoding='utf-8') as f:
                json.dump(payloads_data, f, indent=2, default=str)
                
            logger.info("Dados salvos com sucesso")
            
        except Exception as e:
            logger.error(f"Erro ao salvar dados: {e}")

    def generate_version_id(self, data: Dict[str, Any]) -> str:
        """
        Gera ID único de versão baseado no hash dos dados.
        """
        data_str = json.dumps(data, sort_keys=True, default=str)
        data_hash = hashlib.sha256(data_str.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"v{timestamp}_{data_hash}"

    def calculate_data_hash(self, data: Dict[str, Any]) -> str:
        """
        Calcula hash dos dados usando algoritmo configurado.
        """
        data_str = json.dumps(data, sort_keys=True, default=str)
        if self.versioning_config["hash_algorithm"] == "sha256":
            return hashlib.sha256(data_str.encode()).hexdigest()
        else:
            return hashlib.md5(data_str.encode()).hexdigest()

    def create_payload_version(self, 
                             endpoint: str, 
                             payload_data: Dict[str, Any],
                             description: str = "",
                             author: str = "system",
                             tags: List[str] = None) -> PayloadVersion:
        """
        Cria nova versão de payload.
        """
        try:
            # Gera ID único
            payload_id = f"{endpoint}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Cria versão
            payload_version = PayloadVersion(
                payload_id=payload_id,
                version=self.generate_version_id(payload_data),
                endpoint=endpoint,
                payload_data=deepcopy(payload_data),
                validation_rules=self._generate_validation_rules(payload_data),
                created_at=datetime.now()
            )
            
            # Adiciona ao sistema
            self.payloads[payload_id] = payload_version
            
            # Cria versão de dados
            data_version = DataVersion(
                version_id=payload_version.version,
                timestamp=payload_version.created_at,
                description=f"Payload version for {endpoint}: {description}",
                author=author,
                data_hash=self.calculate_data_hash(payload_data),
                tags=tags or [],
                metadata={
                    "type": "payload",
                    "endpoint": endpoint,
                    "payload_id": payload_id
                }
            )
            
            self.versions.append(data_version)
            
            # Salva dados
            self.save_data()
            
            # Backup automático
            if self.versioning_config["auto_backup"]:
                self.create_backup(payload_version)
            
            # Commit Git se disponível
            if self.git_repo:
                self._git_commit(f"Add payload version {payload_version.version}")
            
            logger.info(f"Payload version criada: {payload_version.version}")
            return payload_version
            
        except Exception as e:
            logger.error(f"Erro ao criar payload version: {e}")
            raise

    def _generate_validation_rules(self, payload_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera regras de validação baseadas no payload.
        """
        rules = {
            "required_fields": [],
            "field_types": {},
            "field_constraints": {}
        }
        
        for field, value in payload_data.items():
            rules["required_fields"].append(field)
            rules["field_types"][field] = type(value).__name__
            
            # Adiciona constraints baseadas no tipo
            if isinstance(value, str):
                rules["field_constraints"][field] = {
                    "min_length": 1,
                    "max_length": 1000
                }
            elif isinstance(value, (int, float)):
                rules["field_constraints"][field] = {
                    "min_value": 0,
                    "max_value": 999999
                }
            elif isinstance(value, list):
                rules["field_constraints"][field] = {
                    "min_items": 1,
                    "max_items": 100
                }
        
        return rules

    def version_config(self, 
                      config_name: str,
                      config_data: Dict[str, Any],
                      description: str = "",
                      author: str = "system") -> DataVersion:
        """
        Versiona configuração de teste.
        """
        try:
            # Gera versão
            version_id = self.generate_version_id(config_data)
            
            # Cria versão
            data_version = DataVersion(
                version_id=version_id,
                timestamp=datetime.now(),
                description=f"Config version for {config_name}: {description}",
                author=author,
                data_hash=self.calculate_data_hash(config_data),
                tags=["config", config_name],
                metadata={
                    "type": "config",
                    "config_name": config_name
                }
            )
            
            # Salva arquivo de configuração
            config_file = self.configs_dir / f"{config_name}_{version_id}.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
            
            # Adiciona ao histórico
            self.versions.append(data_version)
            
            # Salva dados
            self.save_data()
            
            logger.info(f"Config version criada: {version_id}")
            return data_version
            
        except Exception as e:
            logger.error(f"Erro ao versionar config: {e}")
            raise

    def create_backup(self, data_object: Any) -> str:
        """
        Cria backup dos dados versionados.
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backups_dir / f"backup_{timestamp}.pkl"
            
            with open(backup_file, 'wb') as f:
                pickle.dump(data_object, f)
            
            logger.info(f"Backup criado: {backup_file}")
            return str(backup_file)
            
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            return ""

    def restore_from_backup(self, backup_file: str) -> Any:
        """
        Restaura dados de backup.
        """
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                raise FileNotFoundError(f"Backup não encontrado: {backup_file}")
            
            with open(backup_path, 'rb') as f:
                data = pickle.load(f)
            
            logger.info(f"Dados restaurados de: {backup_file}")
            return data
            
        except Exception as e:
            logger.error(f"Erro ao restaurar backup: {e}")
            raise

    def get_payload_version(self, payload_id: str) -> Optional[PayloadVersion]:
        """
        Obtém versão específica de payload.
        """
        return self.payloads.get(payload_id)

    def get_active_payloads(self, endpoint: str = None) -> List[PayloadVersion]:
        """
        Obtém payloads ativos, opcionalmente filtrados por endpoint.
        """
        active_payloads = [p for p in self.payloads.values() if p.is_active]
        
        if endpoint:
            active_payloads = [p for p in active_payloads if p.endpoint == endpoint]
        
        return active_payloads

    def deactivate_payload(self, payload_id: str) -> bool:
        """
        Desativa payload específico.
        """
        if payload_id in self.payloads:
            self.payloads[payload_id].is_active = False
            self.save_data()
            logger.info(f"Payload desativado: {payload_id}")
            return True
        return False

    def rollback_payload(self, payload_id: str, target_version: str) -> bool:
        """
        Faz rollback de payload para versão específica.
        """
        try:
            if payload_id not in self.payloads:
                return False
            
            # Busca versão alvo
            target_payload = None
            for payload in self.payloads.values():
                if payload.version == target_version and payload.endpoint == self.payloads[payload_id].endpoint:
                    target_payload = payload
                    break
            
            if not target_payload:
                logger.error(f"Versão alvo não encontrada: {target_version}")
                return False
            
            # Cria nova versão com dados da versão alvo
            new_payload = PayloadVersion(
                payload_id=f"{payload_id}_rollback_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                version=self.generate_version_id(target_payload.payload_data),
                endpoint=target_payload.endpoint,
                payload_data=deepcopy(target_payload.payload_data),
                validation_rules=target_payload.validation_rules,
                created_at=datetime.now()
            )
            
            # Desativa versão atual
            self.payloads[payload_id].is_active = False
            
            # Adiciona nova versão
            self.payloads[new_payload.payload_id] = new_payload
            
            # Salva dados
            self.save_data()
            
            logger.info(f"Rollback realizado: {payload_id} -> {new_payload.version}")
            return True
            
        except Exception as e:
            logger.error(f"Erro no rollback: {e}")
            return False

    def cleanup_old_versions(self) -> int:
        """
        Remove versões antigas baseado na configuração.
        """
        try:
            max_versions = self.versioning_config["max_versions"]
            retention_days = self.versioning_config["backup_retention_days"]
            
            # Remove versões excedentes
            if len(self.versions) > max_versions:
                # Ordena por timestamp e remove as mais antigas
                self.versions.sort(key=lambda v: v.timestamp)
                removed_count = len(self.versions) - max_versions
                self.versions = self.versions[removed_count:]
                
                logger.info(f"Removidas {removed_count} versões antigas")
            
            # Remove backups antigos
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            backup_files = list(self.backups_dir.glob("backup_*.pkl"))
            
            removed_backups = 0
            for backup_file in backup_files:
                try:
                    file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                    if file_time < cutoff_date:
                        backup_file.unlink()
                        removed_backups += 1
                except Exception as e:
                    logger.warning(f"Erro ao remover backup {backup_file}: {e}")
            
            if removed_backups > 0:
                logger.info(f"Removidos {removed_backups} backups antigos")
            
            return removed_count + removed_backups
            
        except Exception as e:
            logger.error(f"Erro na limpeza: {e}")
            return 0

    def _git_commit(self, message: str) -> bool:
        """
        Faz commit no Git se disponível.
        """
        try:
            if not self.git_repo:
                return False
            
            # Adiciona arquivos modificados
            self.git_repo.index.add([str(self.versions_file), str(self.payloads_file)])
            
            # Commit
            self.git_repo.index.commit(message)
            
            logger.info(f"Git commit: {message}")
            return True
            
        except Exception as e:
            logger.warning(f"Erro no Git commit: {e}")
            return False

    def export_version_history(self, output_file: str = None) -> str:
        """
        Exporta histórico de versões.
        """
        try:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.base_dir / f"version_history_{timestamp}.json"
            
            history_data = {
                "export_timestamp": datetime.now().isoformat(),
                "total_versions": len(self.versions),
                "total_payloads": len(self.payloads),
                "versions": [asdict(v) for v in self.versions],
                "payloads": {k: asdict(v) for k, v in self.payloads.items()}
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, default=str)
            
            logger.info(f"Histórico exportado: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Erro ao exportar histórico: {e}")
            return ""

    def generate_version_report(self) -> str:
        """
        Gera relatório de versionamento.
        """
        try:
            report_file = self.base_dir / f"version_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Versionamento - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Total de versões:** {len(self.versions)}\n")
                f.write(f"- **Total de payloads:** {len(self.payloads)}\n")
                f.write(f"- **Payloads ativos:** {len(self.get_active_payloads())}\n")
                f.write(f"- **Última versão:** {self.versions[-1].version_id if self.versions else 'N/A'}\n\n")
                
                f.write("## Versões por Tipo\n\n")
                
                # Agrupa por tipo
                versions_by_type = {}
                for version in self.versions:
                    v_type = version.metadata.get('type', 'unknown') if version.metadata else 'unknown'
                    if v_type not in versions_by_type:
                        versions_by_type[v_type] = []
                    versions_by_type[v_type].append(version)
                
                for v_type, versions in versions_by_type.items():
                    f.write(f"### {v_type.title()}\n")
                    f.write(f"- **Quantidade:** {len(versions)}\n")
                    f.write(f"- **Última:** {versions[-1].version_id}\n\n")
                
                f.write("## Payloads por Endpoint\n\n")
                
                # Agrupa payloads por endpoint
                payloads_by_endpoint = {}
                for payload in self.payloads.values():
                    if payload.endpoint not in payloads_by_endpoint:
                        payloads_by_endpoint[payload.endpoint] = []
                    payloads_by_endpoint[payload.endpoint].append(payload)
                
                for endpoint, payloads in payloads_by_endpoint.items():
                    f.write(f"### {endpoint}\n")
                    f.write(f"- **Total:** {len(payloads)}\n")
                    f.write(f"- **Ativos:** {len([p for p in payloads if p.is_active])}\n")
                    f.write(f"- **Última versão:** {payloads[-1].version}\n\n")
                
                f.write("## Configurações\n\n")
                f.write(f"- **Backup automático:** {self.versioning_config['auto_backup']}\n")
                f.write(f"- **Máximo de versões:** {self.versioning_config['max_versions']}\n")
                f.write(f"- **Retenção de backup:** {self.versioning_config['backup_retention_days']} dias\n")
                f.write(f"- **Integração Git:** {self.versioning_config['git_integration']}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""


def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Data Versioning System...")
    
    system = DataVersioningSystem()
    
    # Exemplo de uso
    try:
        # Cria versão de payload
        payload_data = {
            "api_key": "sk-test-versioning",
            "model_type": "openai",
            "prompts": [{"text": "Teste de versionamento", "index": 0}]
        }
        
        payload_version = system.create_payload_version(
            endpoint="/generate",
            payload_data=payload_data,
            description="Payload para teste de versionamento",
            author="test_user",
            tags=["test", "versioning"]
        )
        
        # Cria versão de configuração
        config_data = {
            "users": 50,
            "spawn_rate": 5,
            "duration": "5m",
            "host": "http://localhost:5000"
        }
        
        config_version = system.version_config(
            config_name="load_test_config",
            config_data=config_data,
            description="Configuração para teste de carga",
            author="test_user"
        )
        
        # Gera relatório
        report_file = system.generate_version_report()
        
        logger.info("Sistema de versionamento testado com sucesso!")
        logger.info(f"Payload version: {payload_version.version}")
        logger.info(f"Config version: {config_version.version_id}")
        logger.info(f"Relatório: {report_file}")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    main() 