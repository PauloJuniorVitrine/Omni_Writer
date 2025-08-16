import os
import zipfile
from datetime import datetime

BACKUP_DIRS = [
    os.getenv('ARTIGOS_DIR', 'artigos_gerados'),
    os.getenv('OUTPUT_BASE_DIR', 'output'),
]
BACKUP_FILES = [
    os.getenv('STATUS_DB_PATH', 'status.db'),
]
BACKUP_NAME = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

def backup():
    with zipfile.ZipFile(BACKUP_NAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for d in BACKUP_DIRS:
            if os.path.exists(d):
                for root, _, files in os.walk(d):
                    for f in files:
                        path = os.path.join(root, f)
                        zipf.write(path)
        for f in BACKUP_FILES:
            if os.path.exists(f):
                zipf.write(f)
    print(f"Backup gerado: {BACKUP_NAME}")

if __name__ == "__main__":
    backup() 