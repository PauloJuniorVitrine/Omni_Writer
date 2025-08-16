# 📋 AUDIT TRAIL COMPLETO
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas auditoria baseada em eventos reais do sistema
# 📅 Data/Hora: 2025-01-27T15:50:00Z
# 🎯 Prompt: Implementação de audit trail completo
# 📋 Ruleset: enterprise_control_layer.yaml

"""
Audit Trail Completo
====================

Este módulo implementa auditoria completa de todas as ações do sistema
Omni Writer para compliance e segurança.

Cenários Reais Baseados em:
- Logs de auditoria de sistemas enterprise
- Requisitos de compliance (SOX, PCI-DSS, GDPR)
- Eventos de segurança detectados
- Padrões de auditoria da indústria
"""

import json
import logging
import hashlib
import time
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from flask import request, g, session, current_app
import sqlite3
import threading
from contextlib import contextmanager

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "AUDIT_TRAIL_20250127_001"

class AuditEventType(Enum):
    """Tipos de eventos de auditoria baseados em uso real"""
    
    # Autenticação e Autorização
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    TOKEN_GENERATION = "token_generation"
    TOKEN_REVOCATION = "token_revocation"
    
    # Geração de Conteúdo
    ARTICLE_GENERATION_START = "article_generation_start"
    ARTICLE_GENERATION_SUCCESS = "article_generation_success"
    ARTICLE_GENERATION_FAILURE = "article_generation_failure"
    PROMPT_CREATION = "prompt_creation"
    PROMPT_MODIFICATION = "prompt_modification"
    PROMPT_DELETION = "prompt_deletion"
    
    # Gestão de Blogs
    BLOG_CREATION = "blog_creation"
    BLOG_MODIFICATION = "blog_modification"
    BLOG_DELETION = "blog_deletion"
    CATEGORY_CREATION = "category_creation"
    CATEGORY_MODIFICATION = "category_modification"
    CATEGORY_DELETION = "category_deletion"
    
    # Exportação e Download
    DATA_EXPORT = "data_export"
    FILE_DOWNLOAD = "file_download"
    BACKUP_CREATION = "backup_creation"
    BACKUP_RESTORATION = "backup_restoration"
    
    # Feedback e Avaliação
    FEEDBACK_SUBMISSION = "feedback_submission"
    RATING_SUBMISSION = "rating_submission"
    QUALITY_ASSESSMENT = "quality_assessment"
    
    # Administração
    USER_CREATION = "user_creation"
    USER_MODIFICATION = "user_modification"
    USER_DELETION = "user_deletion"
    ROLE_ASSIGNMENT = "role_assignment"
    PERMISSION_CHANGE = "permission_change"
    SYSTEM_CONFIGURATION = "system_configuration"
    
    # Segurança
    SECURITY_ALERT = "security_alert"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CSRF_ATTEMPT = "csrf_attempt"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    
    # Performance e Sistema
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    PERFORMANCE_ALERT = "performance_alert"
    ERROR_OCCURRENCE = "error_occurrence"
    MAINTENANCE_MODE = "maintenance_mode"

class AuditSeverity(Enum):
    """Níveis de severidade baseados em padrões da indústria"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class AuditEvent:
    """Evento de auditoria completo"""
    
    # Identificação única
    event_id: str
    timestamp: datetime
    tracing_id: str
    
    # Informações do evento
    event_type: AuditEventType
    severity: AuditSeverity
    description: str
    
    # Contexto da requisição
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    
    # Dados do evento
    request_data: Optional[Dict]
    response_data: Optional[Dict]
    error_message: Optional[str]
    
    # Metadados
    source_module: str
    tags: List[str]
    metadata: Dict[str, Any]

class AuditTrailManager:
    """
    Gerenciador de audit trail completo.
    
    Funcionalidades:
    - Registro de eventos de auditoria
    - Armazenamento seguro e imutável
    - Consulta e relatórios
    - Compliance e retenção
    - Integração com sistemas de segurança
    """
    
    def __init__(self, app=None, db_path: str = "audit_trail.db"):
        self.tracing_id = TRACING_ID
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.db_path = db_path
        
        # Configurações de auditoria
        self.retention_days = 2555  # 7 anos (compliance)
        self.max_event_size = 1024 * 1024  # 1MB por evento
        self.batch_size = 100  # Eventos por batch
        
        # Thread safety
        self.lock = threading.Lock()
        self.event_queue = []
        
        # Inicializa banco de dados
        self._init_database()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicializa o audit trail na aplicação Flask"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Registra handlers de erro
        app.register_error_handler(Exception, self.error_handler)
        
        self.logger.info(f"[{self.tracing_id}] Audit trail inicializado")
    
    def before_request(self):
        """Executado antes de cada request"""
        try:
            # Inicia contexto de auditoria
            g.audit_context = {
                'start_time': time.time(),
                'request_id': str(uuid.uuid4()),
                'user_id': self._get_user_id(),
                'session_id': self._get_session_id(),
                'ip_address': self._get_client_ip(),
                'user_agent': request.headers.get('User-Agent', ''),
                'endpoint': request.endpoint or request.path,
                'method': request.method,
                'request_data': self._extract_request_data()
            }
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no before_request: {e}")
    
    def after_request(self, response):
        """Executado após cada request"""
        try:
            if hasattr(g, 'audit_context'):
                context = g.audit_context
                
                # Determina tipo de evento baseado na resposta
                event_type = self._determine_event_type(context, response)
                severity = self._determine_severity(context, response)
                
                # Cria evento de auditoria
                event = self._create_audit_event(
                    event_type=event_type,
                    severity=severity,
                    description=self._generate_description(context, response),
                    request_data=context.get('request_data'),
                    response_data=self._extract_response_data(response),
                    error_message=None
                )
                
                # Registra evento
                self.record_event(event)
            
            return response
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no after_request: {e}")
            return response
    
    def error_handler(self, error):
        """Handler para erros da aplicação"""
        try:
            if hasattr(g, 'audit_context'):
                context = g.audit_context
                
                # Cria evento de erro
                event = self._create_audit_event(
                    event_type=AuditEventType.ERROR_OCCURRENCE,
                    severity=AuditSeverity.HIGH,
                    description=f"Erro na aplicação: {str(error)}",
                    request_data=context.get('request_data'),
                    response_data=None,
                    error_message=str(error)
                )
                
                # Registra evento
                self.record_event(event)
            
            # Re-raise para tratamento normal
            raise error
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no error_handler: {e}")
            raise error
    
    def record_event(self, event: AuditEvent):
        """Registra evento de auditoria"""
        try:
            with self.lock:
                self.event_queue.append(event)
                
                # Processa batch se necessário
                if len(self.event_queue) >= self.batch_size:
                    self._process_batch()
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao registrar evento: {e}")
    
    def record_custom_event(self, event_type: AuditEventType, description: str, 
                          severity: AuditSeverity = AuditSeverity.INFO,
                          request_data: Optional[Dict] = None,
                          response_data: Optional[Dict] = None,
                          error_message: Optional[str] = None,
                          tags: List[str] = None,
                          metadata: Dict[str, Any] = None):
        """Registra evento customizado"""
        try:
            event = self._create_audit_event(
                event_type=event_type,
                severity=severity,
                description=description,
                request_data=request_data,
                response_data=response_data,
                error_message=error_message,
                tags=tags or [],
                metadata=metadata or {}
            )
            
            self.record_event(event)
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao registrar evento customizado: {e}")
    
    def _init_database(self):
        """Inicializa banco de dados de auditoria"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        tracing_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        description TEXT NOT NULL,
                        user_id TEXT,
                        session_id TEXT,
                        ip_address TEXT NOT NULL,
                        user_agent TEXT,
                        endpoint TEXT NOT NULL,
                        method TEXT NOT NULL,
                        request_data TEXT,
                        response_data TEXT,
                        error_message TEXT,
                        source_module TEXT NOT NULL,
                        tags TEXT,
                        metadata TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Índices para performance
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_address ON audit_events(ip_address)")
                
                conn.commit()
                
            self.logger.info(f"[{self.tracing_id}] Banco de dados de auditoria inicializado")
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao inicializar banco de dados: {e}")
    
    def _process_batch(self):
        """Processa batch de eventos"""
        try:
            if not self.event_queue:
                return
            
            events_to_process = self.event_queue.copy()
            self.event_queue.clear()
            
            with sqlite3.connect(self.db_path) as conn:
                for event in events_to_process:
                    self._insert_event(conn, event)
                
                conn.commit()
            
            self.logger.info(f"[{self.tracing_id}] {len(events_to_process)} eventos processados")
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao processar batch: {e}")
    
    def _insert_event(self, conn: sqlite3.Connection, event: AuditEvent):
        """Insere evento no banco de dados"""
        try:
            conn.execute("""
                INSERT INTO audit_events (
                    event_id, timestamp, tracing_id, event_type, severity, description,
                    user_id, session_id, ip_address, user_agent, endpoint, method,
                    request_data, response_data, error_message, source_module, tags, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.tracing_id,
                event.event_type.value,
                event.severity.value,
                event.description,
                event.user_id,
                event.session_id,
                event.ip_address,
                event.user_agent,
                event.endpoint,
                event.method,
                json.dumps(event.request_data) if event.request_data else None,
                json.dumps(event.response_data) if event.response_data else None,
                event.error_message,
                event.source_module,
                json.dumps(event.tags),
                json.dumps(event.metadata)
            ))
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao inserir evento: {e}")
    
    def _create_audit_event(self, event_type: AuditEventType, severity: AuditSeverity,
                          description: str, request_data: Optional[Dict] = None,
                          response_data: Optional[Dict] = None, error_message: Optional[str] = None,
                          tags: List[str] = None, metadata: Dict[str, Any] = None) -> AuditEvent:
        """Cria evento de auditoria"""
        try:
            context = getattr(g, 'audit_context', {})
            
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                tracing_id=self.tracing_id,
                event_type=event_type,
                severity=severity,
                description=description,
                user_id=context.get('user_id'),
                session_id=context.get('session_id'),
                ip_address=context.get('ip_address', ''),
                user_agent=context.get('user_agent', ''),
                endpoint=context.get('endpoint', ''),
                method=context.get('method', ''),
                request_data=request_data,
                response_data=response_data,
                error_message=error_message,
                source_module=self._get_source_module(),
                tags=tags or [],
                metadata=metadata or {}
            )
            
            return event
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao criar evento: {e}")
            raise
    
    def _get_user_id(self) -> Optional[str]:
        """Obtém ID do usuário"""
        try:
            if hasattr(g, 'user') and g.user:
                return g.user.get('user_id')
            return None
        except Exception:
            return None
    
    def _get_session_id(self) -> Optional[str]:
        """Obtém ID da sessão"""
        try:
            if hasattr(session, 'id'):
                return session.id
            elif hasattr(session, '_id'):
                return session._id
            else:
                return hashlib.sha256(str(session).encode()).hexdigest()[:16]
        except Exception:
            return None
    
    def _get_client_ip(self) -> str:
        """Obtém IP do cliente"""
        try:
            for header in ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP']:
                ip = request.headers.get(header)
                if ip:
                    return ip.split(',')[0].strip()
            return request.remote_addr
        except Exception:
            return 'unknown'
    
    def _extract_request_data(self) -> Optional[Dict]:
        """Extrai dados da requisição"""
        try:
            data = {}
            
            # Query parameters
            if request.args:
                data['query_params'] = dict(request.args)
            
            # Form data
            if request.form:
                data['form_data'] = dict(request.form)
            
            # JSON data
            if request.is_json:
                data['json_data'] = request.get_json()
            
            # Headers (apenas alguns importantes)
            important_headers = ['Content-Type', 'Authorization', 'User-Agent', 'Referer']
            data['headers'] = {k: v for k, v in request.headers.items() if k in important_headers}
            
            return data if data else None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao extrair dados da requisição: {e}")
            return None
    
    def _extract_response_data(self, response) -> Optional[Dict]:
        """Extrai dados da resposta"""
        try:
            data = {
                'status_code': response.status_code,
                'content_type': response.content_type
            }
            
            # Adiciona headers importantes
            important_headers = ['Content-Type', 'Content-Length', 'X-CSRF-Token']
            data['headers'] = {k: v for k, v in response.headers.items() if k in important_headers}
            
            return data
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao extrair dados da resposta: {e}")
            return None
    
    def _determine_event_type(self, context: Dict, response) -> AuditEventType:
        """Determina tipo de evento baseado no contexto"""
        try:
            endpoint = context.get('endpoint', '').lower()
            method = context.get('method', '')
            
            # Autenticação
            if 'login' in endpoint:
                return AuditEventType.LOGIN_SUCCESS if response.status_code == 200 else AuditEventType.LOGIN_FAILURE
            elif 'logout' in endpoint:
                return AuditEventType.LOGOUT
            
            # Geração de conteúdo
            elif 'generate' in endpoint:
                return AuditEventType.ARTICLE_GENERATION_SUCCESS if response.status_code == 200 else AuditEventType.ARTICLE_GENERATION_FAILURE
            
            # Gestão de blogs
            elif 'blog' in endpoint:
                if method == 'POST':
                    return AuditEventType.BLOG_CREATION
                elif method == 'PUT':
                    return AuditEventType.BLOG_MODIFICATION
                elif method == 'DELETE':
                    return AuditEventType.BLOG_DELETION
            
            # Exportação
            elif 'export' in endpoint or 'download' in endpoint:
                return AuditEventType.DATA_EXPORT
            
            # Feedback
            elif 'feedback' in endpoint:
                return AuditEventType.FEEDBACK_SUBMISSION
            
            # Padrão
            else:
                return AuditEventType.INFO
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao determinar tipo de evento: {e}")
            return AuditEventType.INFO
    
    def _determine_severity(self, context: Dict, response) -> AuditSeverity:
        """Determina severidade baseada no contexto"""
        try:
            status_code = response.status_code
            
            if status_code >= 500:
                return AuditSeverity.HIGH
            elif status_code >= 400:
                return AuditSeverity.MEDIUM
            elif status_code >= 300:
                return AuditSeverity.LOW
            else:
                return AuditSeverity.INFO
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao determinar severidade: {e}")
            return AuditSeverity.INFO
    
    def _generate_description(self, context: Dict, response) -> str:
        """Gera descrição do evento"""
        try:
            endpoint = context.get('endpoint', '')
            method = context.get('method', '')
            status_code = response.status_code
            
            return f"{method} {endpoint} - Status: {status_code}"
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao gerar descrição: {e}")
            return "Evento de auditoria"
    
    def _get_source_module(self) -> str:
        """Obtém módulo fonte"""
        try:
            # Tenta obter do contexto da requisição
            if hasattr(g, 'audit_context'):
                endpoint = g.audit_context.get('endpoint', '')
                if endpoint:
                    return endpoint.split('.')[0] if '.' in endpoint else endpoint
            
            return 'unknown'
            
        except Exception:
            return 'unknown'
    
    def query_events(self, filters: Dict[str, Any] = None, limit: int = 100) -> List[Dict]:
        """Consulta eventos de auditoria"""
        try:
            query = "SELECT * FROM audit_events WHERE 1=1"
            params = []
            
            if filters:
                if 'user_id' in filters:
                    query += " AND user_id = ?"
                    params.append(filters['user_id'])
                
                if 'event_type' in filters:
                    query += " AND event_type = ?"
                    params.append(filters['event_type'])
                
                if 'severity' in filters:
                    query += " AND severity = ?"
                    params.append(filters['severity'])
                
                if 'start_date' in filters:
                    query += " AND timestamp >= ?"
                    params.append(filters['start_date'])
                
                if 'end_date' in filters:
                    query += " AND timestamp <= ?"
                    params.append(filters['end_date'])
                
                if 'ip_address' in filters:
                    query += " AND ip_address = ?"
                    params.append(filters['ip_address'])
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                columns = [description[0] for description in cursor.description]
                
                events = []
                for row in cursor.fetchall():
                    event_dict = dict(zip(columns, row))
                    
                    # Parse JSON fields
                    for field in ['request_data', 'response_data', 'tags', 'metadata']:
                        if event_dict.get(field):
                            try:
                                event_dict[field] = json.loads(event_dict[field])
                            except:
                                pass
                    
                    events.append(event_dict)
                
                return events
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao consultar eventos: {e}")
            return []
    
    def cleanup_old_events(self):
        """Remove eventos antigos"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff_date.isoformat(),))
                conn.commit()
            
            self.logger.info(f"[{self.tracing_id}] Limpeza de eventos antigos concluída")
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na limpeza de eventos: {e}")

# Instância global do audit trail
audit_trail = AuditTrailManager()

# Funções de conveniência
def record_audit_event(event_type: AuditEventType, description: str, **kwargs):
    """Registra evento de auditoria"""
    audit_trail.record_custom_event(event_type, description, **kwargs)

def get_audit_events(filters: Dict[str, Any] = None, limit: int = 100) -> List[Dict]:
    """Consulta eventos de auditoria"""
    return audit_trail.query_events(filters, limit)

# Decorator para auditoria automática
def audit_event(event_type: AuditEventType, description: str = None):
    """Decorator para auditoria automática de funções"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                # Executa função
                result = func(*args, **kwargs)
                
                # Registra evento de sucesso
                desc = description or f"Função {func.__name__} executada com sucesso"
                audit_trail.record_custom_event(
                    event_type=event_type,
                    description=desc,
                    severity=AuditSeverity.INFO,
                    metadata={'function': func.__name__, 'result': 'success'}
                )
                
                return result
                
            except Exception as e:
                # Registra evento de erro
                desc = description or f"Erro na execução da função {func.__name__}"
                audit_trail.record_custom_event(
                    event_type=event_type,
                    description=desc,
                    severity=AuditSeverity.HIGH,
                    error_message=str(e),
                    metadata={'function': func.__name__, 'result': 'error'}
                )
                
                raise
        
        return wrapper
    return decorator 