import os
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from feedback.storage import Feedback, Base
from datetime import datetime

FEEDBACK_FILE = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
POSTGRES_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')

# Carregar feedbacks do JSON
if not os.path.exists(FEEDBACK_FILE):
    print('Arquivo de feedback não encontrado.')
    exit(0)
with open(FEEDBACK_FILE, 'r', encoding='utf-8') as f:
    feedbacks = json.load(f)

# Conexão PostgreSQL
engine = create_engine(POSTGRES_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

total = 0
for fb in feedbacks:
    obj = Feedback(
        user_id=fb.get('user_id') or fb.get('usuario') or '',
        artigo_id=fb.get('artigo_id') or fb.get('id_artigo') or '',
        tipo=fb.get('tipo') or fb.get('avaliacao') or '',
        comentario=fb.get('comentario') or '',
        criado_em=fb.get('criado_em') and datetime.fromisoformat(fb['criado_em']) if fb.get('criado_em') else datetime.utcnow()
    )
    session.add(obj)
    total += 1
session.commit()
session.close()

print(f"Migrados {total} registros de feedback para PostgreSQL.") 