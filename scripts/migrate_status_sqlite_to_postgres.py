import os
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from shared.status_repository import Status, Base

# Configs
SQLITE_PATH = os.getenv('STATUS_DB_PATH', os.path.join(os.getcwd(), 'status.db'))
POSTGRES_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')

# Conexão SQLite
conn = sqlite3.connect(SQLITE_PATH)
cursor = conn.cursor()
cursor.execute('SELECT trace_id, total, current, status FROM status')
rows = cursor.fetchall()
conn.close()

# Conexão PostgreSQL
engine = create_engine(POSTGRES_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Migração
total = 0
for row in rows:
    trace_id, total_val, current, status_val = row
    obj = Status(trace_id=trace_id, total=total_val, current=current, status=status_val)
    session.merge(obj)
    total += 1
session.commit()
session.close()

print(f"Migrados {total} registros de status para PostgreSQL.") 