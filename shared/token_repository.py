import os
from sqlalchemy import create_engine, Column, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import secrets
import logging
from flask import request
from collections import defaultdict

Base = declarative_base()

class ApiToken(Base):
    __tablename__ = 'api_tokens'
    token = Column(String, primary_key=True)
    user_id = Column(String)
    expires_at = Column(DateTime)
    active = Column(Boolean, default=True)

DB_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)

auth_logger = logging.getLogger("omni_auth")
auth_logger.setLevel(logging.INFO)
if not auth_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/auth_attempts.log")
    handler.setFormatter(logging.Formatter('%(message)s'))
    auth_logger.addHandler(handler)

# Rate limiting adaptativo (memória, para produção usar Redis)
FAILED_ATTEMPTS = defaultdict(list)  # key: ip or token, value: [timestamps]
BLOCKED = {}  # key: ip or token, value: unblock_time
MAX_ATTEMPTS = 5
BLOCK_TIME = 600  # segundos (10 min)

def is_blocked(key):
    now = datetime.utcnow()
    unblock_time = BLOCKED.get(key)
    if unblock_time and now < unblock_time:
        return True
    if unblock_time and now >= unblock_time:
        del BLOCKED[key]
    return False

def register_failed_attempt(key):
    now = datetime.utcnow()
    FAILED_ATTEMPTS[key] = [t for t in FAILED_ATTEMPTS[key] if (now - t).total_seconds() < BLOCK_TIME]
    FAILED_ATTEMPTS[key].append(now)
    if len(FAILED_ATTEMPTS[key]) >= MAX_ATTEMPTS:
        BLOCKED[key] = now + timedelta(seconds=BLOCK_TIME)
        FAILED_ATTEMPTS[key] = []

def log_auth_attempt(token, user_id, success):
    ip = request.remote_addr if request else None
    log_data = {
        "timestamp_utc": datetime.utcnow().isoformat(),
        "ip": ip,
        "user_agent": request.headers.get('User-Agent') if request else None,
        "token": token,
        "user_id": user_id,
        "success": success
    }
    auth_logger.info(str(log_data))
    # Rate limiting adaptativo
    key = token or ip
    if not success:
        register_failed_attempt(key)
    # Limpa tentativas antigas em sucesso
    elif key in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = []

def init_db():
    Base.metadata.create_all(engine)

def create_token(user_id: str, days_valid: int = 7) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=days_valid)
    session = Session()
    obj = ApiToken(token=token, user_id=user_id, expires_at=expires_at, active=True)
    session.add(obj)
    session.commit()
    session.close()
    log_auth_attempt(token, user_id, True)
    return token

def validate_token(token: str) -> bool:
    ip = request.remote_addr if request else None
    key = token or ip
    if is_blocked(key):
        log_auth_attempt(token, None, False)
        return False
    session = Session()
    obj = session.query(ApiToken).get(token)
    session.close()
    user_id = obj.user_id if obj else None
    valid = obj and obj.active and obj.expires_at > datetime.utcnow()
    log_auth_attempt(token, user_id, bool(valid))
    return bool(valid)

def rotate_token(user_id: str) -> str:
    session = Session()
    session.query(ApiToken).filter_by(user_id=user_id).update({"active": False})
    session.commit()
    session.close()
    return create_token(user_id)

def revoke_token(token: str):
    session = Session()
    obj = session.query(ApiToken).get(token)
    if obj:
        obj.active = False
        session.commit()
    session.close() 