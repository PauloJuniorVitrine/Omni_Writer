"""
Token Rotation System - Omni Writer
===================================

Sistema de rotação automática de tokens com agendamento, logs de auditoria
e validação de expiração para segurança robusta.

Prompt: Implementação de rotação automática de tokens
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:00:00Z
"""

import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import secrets
from shared.token_repository import ApiToken, Session, log_auth_attempt

# Configuração de logging estruturado
rotation_logger = logging.getLogger("token_rotation")
rotation_logger.setLevel(logging.INFO)
if not rotation_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/token_rotation.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [token_rotation] %(message)s'
    )
    handler.setFormatter(formatter)
    rotation_logger.addHandler(handler)

# Configurações de rotação
ROTATION_INTERVAL_DAYS = int(os.getenv('TOKEN_ROTATION_DAYS', '7'))
FORCE_EXPIRATION_DAYS = int(os.getenv('TOKEN_FORCE_EXPIRATION_DAYS', '30'))
ROTATION_HOUR = int(os.getenv('TOKEN_ROTATION_HOUR', '2'))  # 2 AM UTC
ROTATION_MINUTE = int(os.getenv('TOKEN_ROTATION_MINUTE', '0'))

class TokenRotationService:
    """
    Serviço de rotação automática de tokens com agendamento e auditoria.
    
    Funcionalidades:
    - Rotação automática periódica (7 dias por padrão)
    - Expiração forçada de tokens antigos (>30 dias)
    - Logs de auditoria estruturados
    - Agendamento via cron
    """
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.session_factory = Session
        
    def start_scheduler(self):
        """Inicia o agendador de rotação automática."""
        try:
            # Rotação automática diária às 2 AM UTC
            self.scheduler.add_job(
                func=self.rotate_expired_tokens,
                trigger=CronTrigger(hour=ROTATION_HOUR, minute=ROTATION_MINUTE),
                id='token_rotation_daily',
                name='Rotação automática de tokens expirados',
                replace_existing=True
            )
            
            # Limpeza de tokens antigos semanalmente
            self.scheduler.add_job(
                func=self.force_expire_old_tokens,
                trigger=CronTrigger(day_of_week='sun', hour=3, minute=0),
                id='token_cleanup_weekly',
                name='Limpeza de tokens antigos',
                replace_existing=True
            )
            
            self.scheduler.start()
            rotation_logger.info(
                f"Scheduler iniciado - Rotação: {ROTATION_HOUR}:{ROTATION_MINUTE:02d} UTC, "
                f"Limpeza: Domingo 03:00 UTC"
            )
            
        except Exception as e:
            rotation_logger.error(f"Erro ao iniciar scheduler: {str(e)}")
            raise
    
    def stop_scheduler(self):
        """Para o agendador de rotação."""
        try:
            self.scheduler.shutdown()
            rotation_logger.info("Scheduler parado")
        except Exception as e:
            rotation_logger.error(f"Erro ao parar scheduler: {str(e)}")
    
    def rotate_expired_tokens(self):
        """
        Rotaciona tokens expirados automaticamente.
        
        Processo:
        1. Identifica tokens expirados
        2. Cria novos tokens para usuários ativos
        3. Desativa tokens antigos
        4. Registra auditoria
        """
        try:
            session = self.session_factory()
            now = datetime.utcnow()
            
            # Identifica tokens expirados
            expired_tokens = session.query(ApiToken).filter(
                ApiToken.expires_at <= now,
                ApiToken.active == True
            ).all()
            
            rotation_count = 0
            for token in expired_tokens:
                try:
                    # Cria novo token para o usuário
                    new_token = self._create_new_token(token.user_id)
                    
                    # Desativa token antigo
                    token.active = False
                    
                    rotation_count += 1
                    
                    # Log de auditoria
                    rotation_logger.info(
                        f"Token rotacionado - User: {token.user_id}, "
                        f"Old: {token.token[:8]}..., New: {new_token[:8]}..., "
                        f"Expired: {token.expires_at.isoformat()}"
                    )
                    
                except Exception as e:
                    rotation_logger.error(
                        f"Erro ao rotacionar token {token.token[:8]}... "
                        f"para usuário {token.user_id}: {str(e)}"
                    )
            
            session.commit()
            session.close()
            
            rotation_logger.info(
                f"Rotação concluída - {rotation_count} tokens rotacionados"
            )
            
        except Exception as e:
            rotation_logger.error(f"Erro na rotação automática: {str(e)}")
            if 'session' in locals():
                session.rollback()
                session.close()
    
    def force_expire_old_tokens(self):
        """
        Força expiração de tokens muito antigos (>30 dias).
        
        Segurança: Remove tokens que podem ter sido comprometidos
        ou não utilizados por muito tempo.
        """
        try:
            session = self.session_factory()
            cutoff_date = datetime.utcnow() - timedelta(days=FORCE_EXPIRATION_DAYS)
            
            # Identifica tokens muito antigos
            old_tokens = session.query(ApiToken).filter(
                ApiToken.expires_at <= cutoff_date,
                ApiToken.active == True
            ).all()
            
            expired_count = 0
            for token in old_tokens:
                token.active = False
                expired_count += 1
                
                # Log de auditoria
                rotation_logger.info(
                    f"Token forçadamente expirado - User: {token.user_id}, "
                    f"Token: {token.token[:8]}..., "
                    f"Expired: {token.expires_at.isoformat()}, "
                    f"Age: {(datetime.utcnow() - token.expires_at).days} days"
                )
            
            session.commit()
            session.close()
            
            rotation_logger.info(
                f"Expiração forçada concluída - {expired_count} tokens expirados"
            )
            
        except Exception as e:
            rotation_logger.error(f"Erro na expiração forçada: {str(e)}")
            if 'session' in locals():
                session.rollback()
                session.close()
    
    def _create_new_token(self, user_id: str) -> str:
        """Cria novo token para usuário."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=ROTATION_INTERVAL_DAYS)
        
        session = self.session_factory()
        new_token_obj = ApiToken(
            token=token,
            user_id=user_id,
            expires_at=expires_at,
            active=True
        )
        session.add(new_token_obj)
        session.commit()
        session.close()
        
        # Log de criação
        log_auth_attempt(token, user_id, True)
        
        return token
    
    def get_rotation_stats(self) -> dict:
        """Retorna estatísticas de rotação para monitoramento."""
        try:
            session = self.session_factory()
            now = datetime.utcnow()
            
            # Tokens ativos
            active_tokens = session.query(ApiToken).filter(
                ApiToken.active == True
            ).count()
            
            # Tokens expirados
            expired_tokens = session.query(ApiToken).filter(
                ApiToken.expires_at <= now,
                ApiToken.active == True
            ).count()
            
            # Tokens muito antigos
            cutoff_date = now - timedelta(days=FORCE_EXPIRATION_DAYS)
            old_tokens = session.query(ApiToken).filter(
                ApiToken.expires_at <= cutoff_date,
                ApiToken.active == True
            ).count()
            
            session.close()
            
            return {
                "active_tokens": active_tokens,
                "expired_tokens": expired_tokens,
                "old_tokens": old_tokens,
                "rotation_interval_days": ROTATION_INTERVAL_DAYS,
                "force_expiration_days": FORCE_EXPIRATION_DAYS,
                "last_check": now.isoformat()
            }
            
        except Exception as e:
            rotation_logger.error(f"Erro ao obter estatísticas: {str(e)}")
            return {"error": str(e)}

# Instância global do serviço
token_rotation_service = TokenRotationService()

def init_token_rotation():
    """Inicializa o sistema de rotação de tokens."""
    try:
        token_rotation_service.start_scheduler()
        rotation_logger.info("Sistema de rotação de tokens inicializado")
        
        # Log inicial de estatísticas
        stats = token_rotation_service.get_rotation_stats()
        rotation_logger.info(f"Estatísticas iniciais: {stats}")
        
    except Exception as e:
        rotation_logger.error(f"Erro ao inicializar rotação: {str(e)}")
        raise

def stop_token_rotation():
    """Para o sistema de rotação de tokens."""
    try:
        token_rotation_service.stop_scheduler()
        rotation_logger.info("Sistema de rotação de tokens parado")
    except Exception as e:
        rotation_logger.error(f"Erro ao parar rotação: {str(e)}") 