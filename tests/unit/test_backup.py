import os
import zipfile
import tempfile
import shutil
from unittest import mock
import scripts.backup as backup_mod

def test_backup_cria_zip(tmp_path, monkeypatch):
    # Cria arquivos e diretórios simulados
    d1 = tmp_path / "artigos_gerados"
    d1.mkdir()
    f1 = d1 / "a.txt"
    f1.write_text("abc")
    d2 = tmp_path / "output"
    d2.mkdir()
    f2 = d2 / "b.txt"
    f2.write_text("def")
    db = tmp_path / "status.db"
    db.write_text("dbdata")
    monkeypatch.setenv("ARTIGOS_DIR", str(d1))
    monkeypatch.setenv("OUTPUT_BASE_DIR", str(d2))
    monkeypatch.setenv("STATUS_DB_PATH", str(db))
    # Força nome fixo para facilitar teste
    monkeypatch.setattr(backup_mod, "BACKUP_NAME", str(tmp_path / "test_backup.zip"))
    backup_mod.BACKUP_DIRS[:] = [str(d1), str(d2)]
    backup_mod.BACKUP_FILES[:] = [str(db)]
    backup_mod.backup()
    assert os.path.exists(str(tmp_path / "test_backup.zip"))
    with zipfile.ZipFile(str(tmp_path / "test_backup.zip")) as z:
        files = z.namelist()
        assert any("a.txt" in f for f in files)
        assert any("b.txt" in f for f in files)
        assert any("status.db" in f for f in files) 