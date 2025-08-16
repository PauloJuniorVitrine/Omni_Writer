import sys
import zipfile
import os

def restore(backup_zip):
    with zipfile.ZipFile(backup_zip, 'r') as zipf:
        zipf.extractall()
    print(f"Backup restaurado de: {backup_zip}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python restore.py <backup.zip>")
        sys.exit(1)
    restore(sys.argv[1]) 