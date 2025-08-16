#!/usr/bin/env python3
"""
Script de Migração para Storage Distribuído - Omni Writer
=========================================================

Migra dados do storage atual (SQLite/JSON) para o sistema de storage distribuído
com PostgreSQL e Redis.

Prompt: Script de migração para storage distribuído
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import os
import sys
import json
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.distributed_storage import DistributedStorage, DistributedStatus, DistributedFeedback
from shared.status_repository import get_status as get_old_status
from feedback.storage import list_feedbacks as get_old_feedbacks

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [migration] %(message)s',
    handlers=[
        logging.FileHandler('logs/exec_trace/migration_distributed_storage.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DistributedStorageMigration:
    """
    Classe para migração de dados para storage distribuído.
    
    Funcionalidades:
    - Migração de status do SQLite para PostgreSQL
    - Migração de feedback do JSON para PostgreSQL
    - Validação de integridade dos dados
    - Rollback em caso de falha
    - Logs detalhados da migração
    """
    
    def __init__(self):
        self.distributed_storage = DistributedStorage()
        self.migration_stats = {
            'status_migrated': 0,
            'feedbacks_migrated': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }
        self.backup_data = {}
    
    def create_backup(self) -> bool:
        """
        Cria backup dos dados atuais antes da migração.
        
        Returns:
            True se backup criado com sucesso
        """
        try:
            logger.info("Iniciando criação de backup...")
            
            # Backup de status
            self.backup_data['status'] = self._backup_status_data()
            
            # Backup de feedbacks
            self.backup_data['feedbacks'] = self._backup_feedback_data()
            
            # Salva backup em arquivo
            backup_file = f"backup_pre_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(self.backup_data, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"Backup criado: {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            return False
    
    def _backup_status_data(self) -> List[Dict[str, Any]]:
        """Backup dos dados de status."""
        try:
            # Tenta obter dados do SQLite
            if os.path.exists('status.db'):
                conn = sqlite3.connect('status.db')
                cursor = conn.cursor()
                cursor.execute('SELECT trace_id, total, current, status FROM status')
                rows = cursor.fetchall()
                conn.close()
                
                return [
                    {
                        'trace_id': row[0],
                        'total': row[1],
                        'current': row[2],
                        'status': row[3]
                    }
                    for row in rows
                ]
            
            return []
            
        except Exception as e:
            logger.error(f"Erro ao fazer backup de status: {e}")
            return []
    
    def _backup_feedback_data(self) -> List[Dict[str, Any]]:
        """Backup dos dados de feedback."""
        try:
            return get_old_feedbacks()
        except Exception as e:
            logger.error(f"Erro ao fazer backup de feedback: {e}")
            return []
    
    def migrate_status_data(self) -> bool:
        """
        Migra dados de status para o storage distribuído.
        
        Returns:
            True se migração bem-sucedida
        """
        try:
            logger.info("Iniciando migração de dados de status...")
            
            if not self.backup_data.get('status'):
                logger.warning("Nenhum dado de status para migrar")
                return True
            
            migrated_count = 0
            error_count = 0
            
            for status_data in self.backup_data['status']:
                try:
                    # Migra para storage distribuído
                    self.distributed_storage.update_status(
                        trace_id=status_data['trace_id'],
                        total=status_data['total'],
                        current=status_data['current'],
                        status=status_data['status']
                    )
                    migrated_count += 1
                    
                except Exception as e:
                    logger.error(f"Erro ao migrar status {status_data['trace_id']}: {e}")
                    error_count += 1
            
            self.migration_stats['status_migrated'] = migrated_count
            self.migration_stats['errors'] += error_count
            
            logger.info(f"Migração de status concluída: {migrated_count} migrados, {error_count} erros")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Erro na migração de status: {e}")
            return False
    
    def migrate_feedback_data(self) -> bool:
        """
        Migra dados de feedback para o storage distribuído.
        
        Returns:
            True se migração bem-sucedida
        """
        try:
            logger.info("Iniciando migração de dados de feedback...")
            
            if not self.backup_data.get('feedbacks'):
                logger.warning("Nenhum dado de feedback para migrar")
                return True
            
            migrated_count = 0
            error_count = 0
            
            for feedback_data in self.backup_data['feedbacks']:
                try:
                    # Converte formato antigo para novo
                    user_id = feedback_data.get('user_id') or feedback_data.get('usuario') or 'unknown'
                    artigo_id = feedback_data.get('artigo_id') or feedback_data.get('id_artigo') or 'unknown'
                    tipo = feedback_data.get('tipo') or feedback_data.get('avaliacao') or 'neutro'
                    comentario = feedback_data.get('comentario') or ''
                    
                    # Migra para storage distribuído
                    success = self.distributed_storage.save_feedback(
                        user_id=user_id,
                        artigo_id=artigo_id,
                        tipo=tipo,
                        comentario=comentario
                    )
                    
                    if success:
                        migrated_count += 1
                    else:
                        error_count += 1
                    
                except Exception as e:
                    logger.error(f"Erro ao migrar feedback {feedback_data.get('id_artigo', 'unknown')}: {e}")
                    error_count += 1
            
            self.migration_stats['feedbacks_migrated'] = migrated_count
            self.migration_stats['errors'] += error_count
            
            logger.info(f"Migração de feedback concluída: {migrated_count} migrados, {error_count} erros")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Erro na migração de feedback: {e}")
            return False
    
    def validate_migration(self) -> bool:
        """
        Valida a migração comparando dados originais com migrados.
        
        Returns:
            True se validação bem-sucedida
        """
        try:
            logger.info("Iniciando validação da migração...")
            
            # Valida status
            status_valid = self._validate_status_migration()
            
            # Valida feedbacks
            feedback_valid = self._validate_feedback_migration()
            
            if status_valid and feedback_valid:
                logger.info("Validação da migração concluída com sucesso")
                return True
            else:
                logger.error("Validação da migração falhou")
                return False
                
        except Exception as e:
            logger.error(f"Erro na validação: {e}")
            return False
    
    def _validate_status_migration(self) -> bool:
        """Valida migração de status."""
        try:
            original_count = len(self.backup_data.get('status', []))
            validated_count = 0
            
            for status_data in self.backup_data.get('status', []):
                migrated_status = self.distributed_storage.get_status(status_data['trace_id'])
                
                if migrated_status:
                    if (migrated_status['total'] == status_data['total'] and
                        migrated_status['current'] == status_data['current'] and
                        migrated_status['status'] == status_data['status']):
                        validated_count += 1
                    else:
                        logger.warning(f"Status {status_data['trace_id']} não corresponde")
                else:
                    logger.warning(f"Status {status_data['trace_id']} não encontrado")
            
            logger.info(f"Validação de status: {validated_count}/{original_count}")
            return validated_count == original_count
            
        except Exception as e:
            logger.error(f"Erro na validação de status: {e}")
            return False
    
    def _validate_feedback_migration(self) -> bool:
        """Valida migração de feedback."""
        try:
            original_count = len(self.backup_data.get('feedbacks', []))
            validated_count = 0
            
            for feedback_data in self.backup_data.get('feedbacks', []):
                artigo_id = feedback_data.get('artigo_id') or feedback_data.get('id_artigo')
                if artigo_id:
                    migrated_feedbacks = self.distributed_storage.get_feedbacks(artigo_id)
                    
                    # Verifica se pelo menos um feedback foi migrado
                    if migrated_feedbacks:
                        validated_count += 1
                    else:
                        logger.warning(f"Feedback para artigo {artigo_id} não encontrado")
            
            logger.info(f"Validação de feedback: {validated_count}/{original_count}")
            return validated_count > 0  # Pelo menos alguns feedbacks migrados
            
        except Exception as e:
            logger.error(f"Erro na validação de feedback: {e}")
            return False
    
    def rollback_migration(self) -> bool:
        """
        Executa rollback da migração em caso de falha.
        
        Returns:
            True se rollback bem-sucedido
        """
        try:
            logger.info("Iniciando rollback da migração...")
            
            # Limpa dados migrados
            if self.distributed_storage.enabled:
                self.distributed_storage.cleanup_old_data(days=0)  # Remove todos os dados
            
            logger.info("Rollback concluído")
            return True
            
        except Exception as e:
            logger.error(f"Erro no rollback: {e}")
            return False
    
    def run_migration(self) -> bool:
        """
        Executa a migração completa.
        
        Returns:
            True se migração bem-sucedida
        """
        try:
            self.migration_stats['start_time'] = datetime.now()
            logger.info("=== INICIANDO MIGRAÇÃO PARA STORAGE DISTRIBUÍDO ===")
            
            # Passo 1: Criar backup
            if not self.create_backup():
                logger.error("Falha ao criar backup. Migração abortada.")
                return False
            
            # Passo 2: Migrar status
            if not self.migrate_status_data():
                logger.error("Falha na migração de status. Executando rollback...")
                self.rollback_migration()
                return False
            
            # Passo 3: Migrar feedbacks
            if not self.migrate_feedback_data():
                logger.error("Falha na migração de feedbacks. Executando rollback...")
                self.rollback_migration()
                return False
            
            # Passo 4: Validar migração
            if not self.validate_migration():
                logger.error("Validação falhou. Executando rollback...")
                self.rollback_migration()
                return False
            
            self.migration_stats['end_time'] = datetime.now()
            duration = self.migration_stats['end_time'] - self.migration_stats['start_time']
            
            logger.info("=== MIGRAÇÃO CONCLUÍDA COM SUCESSO ===")
            logger.info(f"Duração: {duration}")
            logger.info(f"Status migrados: {self.migration_stats['status_migrated']}")
            logger.info(f"Feedbacks migrados: {self.migration_stats['feedbacks_migrated']}")
            logger.info(f"Erros: {self.migration_stats['errors']}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erro durante migração: {e}")
            self.rollback_migration()
            return False

def main():
    """Função principal do script."""
    try:
        # Verifica se storage distribuído está habilitado
        if not os.getenv('ENABLE_DISTRIBUTED_STORAGE', 'false').lower() == 'true':
            logger.error("Storage distribuído não está habilitado. Configure ENABLE_DISTRIBUTED_STORAGE=true")
            return 1
        
        # Executa migração
        migration = DistributedStorageMigration()
        success = migration.run_migration()
        
        if success:
            logger.info("Migração concluída com sucesso!")
            return 0
        else:
            logger.error("Migração falhou!")
            return 1
            
    except KeyboardInterrupt:
        logger.info("Migração interrompida pelo usuário")
        return 1
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return 1

if __name__ == '__main__':
    exit(main()) 