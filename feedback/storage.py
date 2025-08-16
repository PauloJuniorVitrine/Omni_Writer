import os
import json
from typing import List, Optional
from feedback.models import FeedbackEntry
from tempfile import NamedTemporaryFile
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

FEEDBACK_FILE = os.path.join(os.path.dirname(__file__), 'feedback_data.json')

Base = declarative_base()

class Feedback(Base):
    __tablename__ = 'feedback'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String)
    artigo_id = Column(String)
    tipo = Column(String)
    comentario = Column(String)
    criado_em = Column(DateTime, default=datetime.utcnow)

DB_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)

def init_db():
    Base.metadata.create_all(engine)

def save_feedback(*args, **kwargs):
    """
    Salva feedback. Aceita:
    - FeedbackEntry (arquivo JSON, modo legado)
    - user_id, artigo_id, tipo, comentario (SQLAlchemy)
    """
    from feedback.models import FeedbackEntry
    if len(args) == 1 and isinstance(args[0], FeedbackEntry):
        # Modo arquivo JSON (compatível com testes)
        entry = args[0]
        feedback = entry.to_dict()
        # Carrega feedbacks existentes
        if not os.path.exists(FEEDBACK_FILE):
            data = []
        else:
            with open(FEEDBACK_FILE, encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = []
        # Evita duplicidade
        for fb in data:
            if fb['id_artigo'] == feedback['id_artigo'] and fb['prompt'] == feedback['prompt'] and fb['avaliacao'] == feedback['avaliacao'] and fb.get('comentario') == feedback.get('comentario'):
                return 'duplicate'
        data.append(feedback)
        try:
            with NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(FEEDBACK_FILE)) as tf:
                json.dump(data, tf, ensure_ascii=False, indent=2)
            os.replace(tf.name, FEEDBACK_FILE)
        except OSError as e:
            raise
        return 'ok'
    elif len(args) == 4:
        # Modo SQLAlchemy
        user_id, artigo_id, tipo, comentario = args
        session = Session()
        fb = Feedback(user_id=user_id, artigo_id=artigo_id, tipo=tipo, comentario=comentario)
        session.add(fb)
        session.commit()
        session.close()
        return 'ok'
    else:
        raise TypeError('save_feedback: argumentos inválidos')

def get_feedbacks(artigo_id=None):
    session = Session()
    query = session.query(Feedback)
    if artigo_id:
        query = query.filter_by(artigo_id=artigo_id)
    result = [
        {'id': fb.id, 'user_id': fb.user_id, 'artigo_id': fb.artigo_id, 'tipo': fb.tipo, 'comentario': fb.comentario, 'criado_em': fb.criado_em}
        for fb in query.all()
    ]
    session.close()
    return result 

def list_feedbacks():
    """
    Lista todos os feedbacks do arquivo feedback_data.json.
    """
    if not os.path.exists(FEEDBACK_FILE):
        return []
    with open(FEEDBACK_FILE, encoding='utf-8') as f:
        try:
            data = json.load(f)
            return data
        except Exception:
            return []

def get_feedback_by_article(id_artigo):
    """
    Retorna todos os feedbacks para um id_artigo específico.
    """
    return [fb for fb in list_feedbacks() if fb.get('id_artigo') == id_artigo] 