"""
Tasks de manutenção para sistema distribuído.
Implementa limpeza automática, rotação de tokens e backup.
"""
import os
import logging
import time
import shutil
from datetime import datetime, timedelta
from typing import Dict, List
from celery import current_task
from celery.utils.log import get_task_logger
import redis
import json

# Configuração de logging
logger = get_task_logger(__name__)

@current_task.task(bind=True, name='app.tasks.maintenance_tasks.cleanup_old_files')
def cleanup_old_files(self, days_old: int = 7) -> Dict:
    """
    Task de baixa prioridade para limpeza de arquivos antigos.
    
    Args:
        days_old: Idade mínima dos arquivos para remoção
        
    Returns:
        Resultado da limpeza
    """
    start_time = time.time()
    
    try:
        # Diretórios para limpeza
        cleanup_dirs = [
            'output',
            'artigos_gerados',
            'logs',
            'temp'
        ]
        
        cutoff_date = datetime.now() - timedelta(days=days_old)
        removed_files = []
        removed_dirs = []
        total_size_freed = 0
        
        for dir_path in cleanup_dirs:
            if not os.path.exists(dir_path):
                continue
                
            for root, dirs, files in os.walk(dir_path, topdown=False):
                # Remove arquivos antigos
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if file_mtime < cutoff_date:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            removed_files.append(file_path)
                            total_size_freed += file_size
                            logger.info(f"Arquivo removido: {file_path}")
                    except Exception as e:
                        logger.warning(f"Erro ao remover arquivo {file_path}: {e}")
                
                # Remove diretórios vazios
                for dir_name in dirs:
                    dir_path_full = os.path.join(root, dir_name)
                    try:
                        if not os.listdir(dir_path_full):
                            os.rmdir(dir_path_full)
                            removed_dirs.append(dir_path_full)
                            logger.info(f"Diretório vazio removido: {dir_path_full}")
                    except Exception as e:
                        logger.warning(f"Erro ao remover diretório {dir_path_full}: {e}")
        
        return {
            'status': 'success',
            'removed_files': len(removed_files),
            'removed_dirs': len(removed_dirs),
            'size_freed_mb': round(total_size_freed / (1024 * 1024), 2),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na limpeza de arquivos: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=300 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.maintenance_tasks.rotate_api_tokens')
def rotate_api_tokens(self) -> Dict:
    """
    Task para rotação automática de tokens de API.
    
    Returns:
        Resultado da rotação
    """
    start_time = time.time()
    
    try:
        # Configuração do Redis
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url)
        
        # Chaves de tokens no Redis
        token_keys = redis_client.keys('api_token:*')
        rotated_tokens = []
        expired_tokens = []
        
        for key in token_keys:
            try:
                token_data = redis_client.get(key)
                if token_data:
                    token_info = json.loads(token_data)
                    
                    # Verifica se o token expirou (30 dias)
                    created_at = datetime.fromisoformat(token_info.get('created_at', ''))
                    if datetime.now() - created_at > timedelta(days=30):
                        # Remove token expirado
                        redis_client.delete(key)
                        expired_tokens.append(key.decode())
                        logger.info(f"Token expirado removido: {key.decode()}")
                    else:
                        # Renova token próximo do vencimento (25 dias)
                        if datetime.now() - created_at > timedelta(days=25):
                            # Aqui você implementaria a lógica de renovação
                            # Por enquanto, apenas marca como renovado
                            token_info['last_rotated'] = datetime.now().isoformat()
                            redis_client.setex(key, 86400 * 7, json.dumps(token_info))  # 7 dias
                            rotated_tokens.append(key.decode())
                            logger.info(f"Token renovado: {key.decode()}")
                            
            except Exception as e:
                logger.warning(f"Erro ao processar token {key}: {e}")
        
        return {
            'status': 'success',
            'rotated_tokens': len(rotated_tokens),
            'expired_tokens': len(expired_tokens),
            'total_tokens': len(token_keys),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na rotação de tokens: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=600 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.maintenance_tasks.backup_database')
def backup_database(self, backup_dir: str = 'backups') -> Dict:
    """
    Task para backup do banco de dados.
    
    Args:
        backup_dir: Diretório para armazenar backups
        
    Returns:
        Resultado do backup
    """
    start_time = time.time()
    
    try:
        # Cria diretório de backup se não existir
        os.makedirs(backup_dir, exist_ok=True)
        
        # Lista de bancos para backup
        db_files = [
            'blog.db',
            'blogs.db',
            'omni_writer.db',
            'status.db'
        ]
        
        backup_files = []
        total_size = 0
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        for db_file in db_files:
            if os.path.exists(db_file):
                backup_name = f"{db_file}.{timestamp}.backup"
                backup_path = os.path.join(backup_dir, backup_name)
                
                # Copia arquivo do banco
                shutil.copy2(db_file, backup_path)
                
                file_size = os.path.getsize(backup_path)
                backup_files.append(backup_path)
                total_size += file_size
                
                logger.info(f"Backup criado: {backup_path} ({file_size} bytes)")
        
        # Remove backups antigos (mantém apenas os últimos 7 dias)
        cutoff_date = datetime.now() - timedelta(days=7)
        removed_backups = []
        
        for file in os.listdir(backup_dir):
            if file.endswith('.backup'):
                file_path = os.path.join(backup_dir, file)
                file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if file_mtime < cutoff_date:
                    os.remove(file_path)
                    removed_backups.append(file_path)
                    logger.info(f"Backup antigo removido: {file_path}")
        
        return {
            'status': 'success',
            'backup_files': len(backup_files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'removed_old_backups': len(removed_backups),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro no backup do banco: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=300 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.maintenance_tasks.cleanup_cache')
def cleanup_cache(self, max_age_hours: int = 24) -> Dict:
    """
    Task para limpeza do cache Redis.
    
    Args:
        max_age_hours: Idade máxima dos itens em cache
        
    Returns:
        Resultado da limpeza do cache
    """
    start_time = time.time()
    
    try:
        # Configuração do Redis
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url)
        
        # Chaves de cache para limpeza
        cache_patterns = [
            'cache:*',
            'celery:*',
            'temp:*'
        ]
        
        removed_keys = 0
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        for pattern in cache_patterns:
            keys = redis_client.keys(pattern)
            
            for key in keys:
                try:
                    # Verifica TTL da chave
                    ttl = redis_client.ttl(key)
                    if ttl > 0 and ttl < (max_age_hours * 3600):
                        redis_client.delete(key)
                        removed_keys += 1
                        logger.debug(f"Chave de cache removida: {key.decode()}")
                except Exception as e:
                    logger.warning(f"Erro ao processar chave {key}: {e}")
        
        return {
            'status': 'success',
            'removed_keys': removed_keys,
            'max_age_hours': max_age_hours,
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na limpeza do cache: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=180 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.maintenance_tasks.validate_system_integrity')
def validate_system_integrity(self) -> Dict:
    """
    Task para validação da integridade do sistema.
    
    Returns:
        Resultado da validação
    """
    start_time = time.time()
    
    try:
        # Verificações de integridade
        checks = {
            'database_connection': False,
            'redis_connection': False,
            'file_permissions': False,
            'disk_space': False
        }
        
        # Verifica conexão com Redis
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            redis_client = redis.from_url(redis_url)
            redis_client.ping()
            checks['redis_connection'] = True
        except Exception as e:
            logger.error(f"Erro na conexão Redis: {e}")
        
        # Verifica permissões de arquivo
        try:
            test_file = 'test_permissions.tmp'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            checks['file_permissions'] = True
        except Exception as e:
            logger.error(f"Erro nas permissões de arquivo: {e}")
        
        # Verifica espaço em disco
        try:
            import shutil
            total, used, free = shutil.disk_usage('.')
            free_gb = free / (1024**3)
            checks['disk_space'] = free_gb > 1.0  # Pelo menos 1GB livre
        except Exception as e:
            logger.error(f"Erro na verificação de disco: {e}")
        
        # Verifica conexão com banco (SQLite)
        try:
            import sqlite3
            if os.path.exists('blog.db'):
                conn = sqlite3.connect('blog.db')
                conn.close()
                checks['database_connection'] = True
        except Exception as e:
            logger.error(f"Erro na conexão com banco: {e}")
        
        # Calcula score de integridade
        integrity_score = sum(checks.values()) / len(checks) * 100
        
        return {
            'status': 'success',
            'checks': checks,
            'integrity_score': round(integrity_score, 2),
            'all_passed': all(checks.values()),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na validação de integridade: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=300 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        } 