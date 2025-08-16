#!/usr/bin/env python3
"""
🔄 Sistema de Rollback de Documentação
======================================

Objetivo: Sistema de backup e rollback automático para documentação
Autor: AI Assistant
Data: 2025-01-27
Tracing ID: DOC_ROLLBACK_20250127_001

Compliance: PCI-DSS 6.3, LGPD Art. 37
"""

import os
import json
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor
import zipfile
import tempfile

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/doc_rollback.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class BackupSnapshot:
    """Snapshot de backup de documentação"""
    snapshot_id: str
    timestamp: datetime
    description: str
    file_count: int
    total_size: int
    hash_value: str
    metadata: Dict = None
    status: str = "created"

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

@dataclass
class RollbackOperation:
    """Operação de rollback"""
    operation_id: str
    snapshot_id: str
    timestamp: datetime
    reason: str
    files_affected: int
    status: str = "pending"
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

class DocumentRollbackSystem:
    """
    Sistema de rollback de documentação
    """
    
    def __init__(self, backup_dir: str = "backups", max_backups: int = 10):
        self.backup_dir = backup_dir
        self.max_backups = max_backups
        self.snapshots: List[BackupSnapshot] = []
        self.rollback_history: List[RollbackOperation] = []
        self.lock = threading.Lock()
        
        # Criar diretórios
        os.makedirs(backup_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        # Carregar histórico existente
        self.load_history()
        
        logger.info(f"[DOC_ROLLBACK] Sistema inicializado - Backup dir: {backup_dir}")

    def create_snapshot(self, directories: List[str] = None, description: str = "Backup automático") -> BackupSnapshot:
        """Cria um snapshot de backup"""
        try:
            if directories is None:
                directories = ["docs", "scripts"]
            
            snapshot_id = f"snapshot_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            timestamp = datetime.now(timezone.utc)
            
            logger.info(f"[DOC_ROLLBACK] Criando snapshot: {snapshot_id}")
            
            # Criar diretório do snapshot
            snapshot_dir = os.path.join(self.backup_dir, snapshot_id)
            os.makedirs(snapshot_dir, exist_ok=True)
            
            # Coletar arquivos
            files_to_backup = []
            total_size = 0
            
            for directory in directories:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if self._should_backup_file(file_path):
                                files_to_backup.append(file_path)
                                total_size += os.path.getsize(file_path)
            
            # Copiar arquivos
            copied_files = []
            for file_path in files_to_backup:
                try:
                    # Manter estrutura de diretórios
                    relative_path = os.path.relpath(file_path)
                    backup_path = os.path.join(snapshot_dir, relative_path)
                    
                    # Criar diretório se necessário
                    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                    
                    # Copiar arquivo
                    shutil.copy2(file_path, backup_path)
                    copied_files.append(relative_path)
                    
                except Exception as e:
                    logger.error(f"[DOC_ROLLBACK] Erro ao copiar {file_path}: {e}")
            
            # Calcular hash do snapshot
            snapshot_hash = self._calculate_snapshot_hash(snapshot_dir)
            
            # Criar metadata
            metadata = {
                "directories": directories,
                "copied_files": copied_files,
                "backup_format": "files",
                "compression": False
            }
            
            # Criar snapshot
            snapshot = BackupSnapshot(
                snapshot_id=snapshot_id,
                timestamp=timestamp,
                description=description,
                file_count=len(copied_files),
                total_size=total_size,
                hash_value=snapshot_hash,
                metadata=metadata
            )
            
            # Salvar snapshot
            self._save_snapshot(snapshot)
            
            # Adicionar à lista
            with self.lock:
                self.snapshots.append(snapshot)
                self._cleanup_old_backups()
            
            logger.info(f"[DOC_ROLLBACK] Snapshot criado: {snapshot_id} ({len(copied_files)} arquivos)")
            return snapshot
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao criar snapshot: {e}")
            return None

    def _should_backup_file(self, file_path: str) -> bool:
        """Verifica se arquivo deve ser incluído no backup"""
        # Extensões de documentação
        doc_extensions = ['.md', '.txt', '.rst', '.yaml', '.json', '.py']
        
        # Verificar extensão
        if not any(file_path.endswith(ext) for ext in doc_extensions):
            return False
        
        # Excluir arquivos temporários
        temp_patterns = ['__pycache__', '.tmp', '.temp', '.log']
        if any(pattern in file_path for pattern in temp_patterns):
            return False
        
        # Excluir arquivos muito grandes (>10MB)
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return False
        except:
            return False
        
        return True

    def _calculate_snapshot_hash(self, snapshot_dir: str) -> str:
        """Calcula hash do snapshot"""
        try:
            hash_objects = []
            
            for root, dirs, files in os.walk(snapshot_dir):
                for file in sorted(files):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            file_hash = hashlib.sha256(content).hexdigest()
                            hash_objects.append(file_hash)
                    except Exception as e:
                        logger.warning(f"[DOC_ROLLBACK] Erro ao calcular hash de {file_path}: {e}")
            
            # Hash final
            if hash_objects:
                combined_hash = hashlib.sha256(''.join(hash_objects).encode()).hexdigest()
                return combined_hash
            else:
                return hashlib.sha256(b"empty").hexdigest()
                
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao calcular hash do snapshot: {e}")
            return ""

    def _save_snapshot(self, snapshot: BackupSnapshot) -> None:
        """Salva metadados do snapshot"""
        try:
            snapshot_file = os.path.join(self.backup_dir, f"{snapshot.snapshot_id}.json")
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(snapshot), f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao salvar snapshot: {e}")

    def _cleanup_old_backups(self) -> None:
        """Remove backups antigos se exceder limite"""
        try:
            if len(self.snapshots) > self.max_backups:
                # Ordenar por timestamp (mais antigos primeiro)
                self.snapshots.sort(key=lambda x: x.timestamp)
                
                # Remover backups antigos
                to_remove = self.snapshots[:-self.max_backups]
                
                for snapshot in to_remove:
                    self._remove_snapshot(snapshot)
                
                logger.info(f"[DOC_ROLLBACK] Removidos {len(to_remove)} backups antigos")
                
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao limpar backups antigos: {e}")

    def _remove_snapshot(self, snapshot: BackupSnapshot) -> None:
        """Remove um snapshot específico"""
        try:
            # Remover diretório
            snapshot_dir = os.path.join(self.backup_dir, snapshot.snapshot_id)
            if os.path.exists(snapshot_dir):
                shutil.rmtree(snapshot_dir)
            
            # Remover arquivo de metadados
            snapshot_file = os.path.join(self.backup_dir, f"{snapshot.snapshot_id}.json")
            if os.path.exists(snapshot_file):
                os.remove(snapshot_file)
            
            # Remover da lista
            self.snapshots = [s for s in self.snapshots if s.snapshot_id != snapshot.snapshot_id]
            
            logger.info(f"[DOC_ROLLBACK] Snapshot removido: {snapshot.snapshot_id}")
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao remover snapshot {snapshot.snapshot_id}: {e}")

    def list_snapshots(self) -> List[BackupSnapshot]:
        """Lista todos os snapshots disponíveis"""
        return sorted(self.snapshots, key=lambda x: x.timestamp, reverse=True)

    def get_snapshot(self, snapshot_id: str) -> Optional[BackupSnapshot]:
        """Obtém um snapshot específico"""
        for snapshot in self.snapshots:
            if snapshot.snapshot_id == snapshot_id:
                return snapshot
        return None

    def validate_snapshot(self, snapshot_id: str) -> Tuple[bool, List[str]]:
        """Valida integridade de um snapshot"""
        try:
            snapshot = self.get_snapshot(snapshot_id)
            if not snapshot:
                return False, ["Snapshot não encontrado"]
            
            snapshot_dir = os.path.join(self.backup_dir, snapshot_id)
            if not os.path.exists(snapshot_dir):
                return False, ["Diretório do snapshot não encontrado"]
            
            # Verificar hash
            current_hash = self._calculate_snapshot_hash(snapshot_dir)
            if current_hash != snapshot.hash_value:
                return False, ["Hash do snapshot não confere"]
            
            # Verificar arquivos
            issues = []
            expected_files = snapshot.metadata.get("copied_files", [])
            
            for expected_file in expected_files:
                file_path = os.path.join(snapshot_dir, expected_file)
                if not os.path.exists(file_path):
                    issues.append(f"Arquivo não encontrado: {expected_file}")
            
            # Verificar arquivos extras
            actual_files = []
            for root, dirs, files in os.walk(snapshot_dir):
                for file in files:
                    relative_path = os.path.relpath(os.path.join(root, file), snapshot_dir)
                    actual_files.append(relative_path)
            
            extra_files = set(actual_files) - set(expected_files)
            if extra_files:
                issues.append(f"Arquivos extras encontrados: {list(extra_files)}")
            
            return len(issues) == 0, issues
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao validar snapshot {snapshot_id}: {e}")
            return False, [f"Erro de validação: {e}"]

    def rollback_to_snapshot(self, snapshot_id: str, reason: str = "Rollback manual") -> RollbackOperation:
        """Executa rollback para um snapshot específico"""
        try:
            # Verificar se snapshot existe
            snapshot = self.get_snapshot(snapshot_id)
            if not snapshot:
                raise ValueError(f"Snapshot não encontrado: {snapshot_id}")
            
            # Validar snapshot
            is_valid, issues = self.validate_snapshot(snapshot_id)
            if not is_valid:
                raise ValueError(f"Snapshot inválido: {issues}")
            
            # Criar operação de rollback
            operation_id = f"rollback_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            operation = RollbackOperation(
                operation_id=operation_id,
                snapshot_id=snapshot_id,
                timestamp=datetime.now(timezone.utc),
                reason=reason,
                files_affected=snapshot.file_count,
                status="in_progress"
            )
            
            logger.info(f"[DOC_ROLLBACK] Iniciando rollback: {operation_id} -> {snapshot_id}")
            
            # Criar backup do estado atual antes do rollback
            current_snapshot = self.create_snapshot(description=f"Backup antes do rollback {operation_id}")
            
            # Executar rollback
            try:
                self._execute_rollback(snapshot_id, operation)
                operation.status = "completed"
                logger.info(f"[DOC_ROLLBACK] Rollback concluído: {operation_id}")
                
            except Exception as e:
                operation.status = "failed"
                operation.metadata["error"] = str(e)
                logger.error(f"[DOC_ROLLBACK] Rollback falhou: {operation_id} - {e}")
                
                # Tentar restaurar estado anterior
                if current_snapshot:
                    logger.info(f"[DOC_ROLLBACK] Restaurando estado anterior: {current_snapshot.snapshot_id}")
                    self._execute_rollback(current_snapshot.snapshot_id, operation)
            
            # Salvar operação
            self._save_rollback_operation(operation)
            
            # Adicionar ao histórico
            with self.lock:
                self.rollback_history.append(operation)
            
            return operation
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao executar rollback: {e}")
            return None

    def _execute_rollback(self, snapshot_id: str, operation: RollbackOperation) -> None:
        """Executa o rollback efetivo"""
        try:
            snapshot_dir = os.path.join(self.backup_dir, snapshot_id)
            snapshot = self.get_snapshot(snapshot_id)
            
            if not snapshot:
                raise ValueError(f"Snapshot não encontrado: {snapshot_id}")
            
            # Lista de arquivos a restaurar
            files_to_restore = snapshot.metadata.get("copied_files", [])
            
            # Restaurar arquivos
            restored_count = 0
            for file_path in files_to_restore:
                try:
                    backup_path = os.path.join(snapshot_dir, file_path)
                    if os.path.exists(backup_path):
                        # Criar diretório se necessário
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        
                        # Restaurar arquivo
                        shutil.copy2(backup_path, file_path)
                        restored_count += 1
                        
                except Exception as e:
                    logger.error(f"[DOC_ROLLBACK] Erro ao restaurar {file_path}: {e}")
            
            # Atualizar metadata da operação
            operation.metadata["restored_files"] = restored_count
            operation.metadata["total_files"] = len(files_to_restore)
            
            logger.info(f"[DOC_ROLLBACK] Restaurados {restored_count}/{len(files_to_restore)} arquivos")
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro na execução do rollback: {e}")
            raise

    def _save_rollback_operation(self, operation: RollbackOperation) -> None:
        """Salva operação de rollback"""
        try:
            operations_file = os.path.join(self.backup_dir, "rollback_operations.json")
            
            # Carregar operações existentes
            operations = []
            if os.path.exists(operations_file):
                with open(operations_file, 'r', encoding='utf-8') as f:
                    operations = json.load(f)
            
            # Adicionar nova operação
            operations.append(asdict(operation))
            
            # Salvar
            with open(operations_file, 'w', encoding='utf-8') as f:
                json.dump(operations, f, indent=2, ensure_ascii=False, default=str)
                
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao salvar operação: {e}")

    def load_history(self) -> None:
        """Carrega histórico de snapshots e operações"""
        try:
            # Carregar snapshots
            for file in os.listdir(self.backup_dir):
                if file.endswith('.json') and file.startswith('snapshot_'):
                    try:
                        snapshot_file = os.path.join(self.backup_dir, file)
                        with open(snapshot_file, 'r', encoding='utf-8') as f:
                            snapshot_data = json.load(f)
                            snapshot = BackupSnapshot(**snapshot_data)
                            self.snapshots.append(snapshot)
                    except Exception as e:
                        logger.warning(f"[DOC_ROLLBACK] Erro ao carregar snapshot {file}: {e}")
            
            # Carregar operações de rollback
            operations_file = os.path.join(self.backup_dir, "rollback_operations.json")
            if os.path.exists(operations_file):
                try:
                    with open(operations_file, 'r', encoding='utf-8') as f:
                        operations_data = json.load(f)
                        for op_data in operations_data:
                            operation = RollbackOperation(**op_data)
                            self.rollback_history.append(operation)
                except Exception as e:
                    logger.warning(f"[DOC_ROLLBACK] Erro ao carregar operações: {e}")
            
            logger.info(f"[DOC_ROLLBACK] Histórico carregado: {len(self.snapshots)} snapshots, {len(self.rollback_history)} operações")
            
        except Exception as e:
            logger.error(f"[DOC_ROLLBACK] Erro ao carregar histórico: {e}")

    def get_statistics(self) -> Dict:
        """Retorna estatísticas do sistema"""
        return {
            "total_snapshots": len(self.snapshots),
            "total_rollbacks": len(self.rollback_history),
            "backup_directory": self.backup_dir,
            "max_backups": self.max_backups,
            "total_backup_size_mb": sum(s.total_size for s in self.snapshots) / (1024 * 1024),
            "last_snapshot": self.snapshots[-1].snapshot_id if self.snapshots else None,
            "last_rollback": self.rollback_history[-1].operation_id if self.rollback_history else None
        }


def main():
    """Função principal"""
    print("🔄 Iniciando Sistema de Rollback de Documentação...")
    
    # Inicializar sistema
    rollback_system = DocumentRollbackSystem()
    
    # Criar snapshot inicial
    print("📸 Criando snapshot inicial...")
    snapshot = rollback_system.create_snapshot(description="Snapshot inicial do sistema")
    
    if snapshot:
        print(f"✅ Snapshot criado: {snapshot.snapshot_id}")
        print(f"   - Arquivos: {snapshot.file_count}")
        print(f"   - Tamanho: {snapshot.total_size / (1024*1024):.2f} MB")
        print(f"   - Hash: {snapshot.hash_value[:16]}...")
        
        # Mostrar estatísticas
        stats = rollback_system.get_statistics()
        print(f"\n📊 Estatísticas:")
        print(f"   - Snapshots: {stats['total_snapshots']}")
        print(f"   - Rollbacks: {stats['total_rollbacks']}")
        print(f"   - Tamanho total: {stats['total_backup_size_mb']:.2f} MB")
    else:
        print("❌ Erro ao criar snapshot")


if __name__ == "__main__":
    main() 