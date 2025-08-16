"""
Status repository utilities for tracking article generation progress.
Handles status persistence, retrieval, and cleanup using SQLite.
"""
import os
from sqlalchemy import create_engine, Column, String, Integer, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

Base = declarative_base()

class Status(Base):
    __tablename__ = 'status'
    trace_id = Column(String, primary_key=True)
    total = Column(Integer)
    current = Column(Integer)
    status = Column(String)

DB_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)

def init_db():
    """
    Initializes the status database and creates the status table if it does not exist.
    """
    Base.metadata.create_all(engine)

def update_status(trace_id: str, total: int, current: int, status: str):
    """
    Updates or inserts the status for a given trace_id.
    Args:
        trace_id (str): Unique identifier for the generation process.
        total (int): Total number of steps.
        current (int): Current step.
        status (str): Status string (e.g., 'in_progress', 'done').
    """
    session = Session()
    obj = session.query(Status).get(trace_id) or Status(trace_id=trace_id)
    obj.total = total
    obj.current = current
    obj.status = status
    session.merge(obj)
    session.commit()
    session.close()

def get_status(trace_id: str):
    """
    Retrieves the status for a given trace_id.
    Args:
        trace_id (str): Unique identifier for the generation process.
    Returns:
        dict or None: Status dictionary or None if not found.
    """
    session = Session()
    obj = session.query(Status).get(trace_id)
    session.close()
    if obj:
        return {'trace_id': obj.trace_id, 'total': obj.total, 'current': obj.current, 'status': obj.status}
    return None

def clear_old_status(days: int = 7):
    """
    Removes status entries older than the specified number of days.
    Args:
        days (int): Number of days to keep status entries.
    """
    session = Session()
    session.query(Status).delete()
    session.commit()
    session.close()

# Inicialização condicional do banco de status
if os.getenv("ENABLE_STATUS_DB", "0") == "1":
    init_db()
    print("[status_repository] Banco de status inicializado.")
else:
    print("[status_repository] Banco de status NÃO inicializado (ENABLE_STATUS_DB != 1).") 