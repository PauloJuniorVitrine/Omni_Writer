def test_pytest_minimal():
    assert True

import os
import time
import pytest
from unittest import mock
from infraestructure import storage
from omni_writer.domain.models import ArticleOutput
import zipfile


def test_get_content_hash():
    h1 = storage.get_content_hash("abc")
    h2 = storage.get_content_hash("abc")
    h3 = storage.get_content_hash("def")
    assert h1 == h2
    assert h1 != h3


def test_load_and_save_hash(tmp_path):
    hash_file = tmp_path / "hashes.json"
    with mock.patch("infraestructure.storage.HASHES_FILE", str(hash_file)):
        storage.save_hash({"a", "b"})
        hashes = storage.load_hashes()
        assert "a" in hashes and "b" in hashes


def test_save_article_unique(tmp_path, caplog):
    art = ArticleOutput(content="conteudo unico", filename="a.txt")
    with mock.patch("infraestructure.storage.HASHES_FILE", str(tmp_path / "hashes.json")):
        with caplog.at_level("INFO"):
            storage.save_article(art, output_dir=str(tmp_path))
        files = list(tmp_path.glob("*.txt"))
        assert any(f.name == "a.txt" for f in files)


def test_save_article_duplicate(tmp_path, caplog):
    art = ArticleOutput(content="conteudo duplicado", filename="b.txt")
    with mock.patch("infraestructure.storage.HASHES_FILE", str(tmp_path / "hashes.json")):
        storage.save_article(art, output_dir=str(tmp_path))
        with caplog.at_level("INFO"):
            storage.save_article(art, output_dir=str(tmp_path))
        files = list(tmp_path.glob("*.txt"))
        assert len(files) == 1


def test_save_article_ioerror(tmp_path, caplog):
    art = ArticleOutput(content="erro io", filename="fail.txt")
    with mock.patch("infraestructure.storage.HASHES_FILE", str(tmp_path / "hashes.json")):
        with mock.patch("builtins.open", side_effect=IOError("fail")):
            with pytest.raises(Exception):
                storage.save_article(art, output_dir=str(tmp_path))


def test_make_zip(tmp_path):
    file1 = tmp_path / "a.txt"
    file1.write_text("abc")
    zip_path = tmp_path / "out.zip"
    storage.make_zip(articles_dir=str(tmp_path), zip_path=str(zip_path))
    assert os.path.exists(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        assert "a.txt" in z.namelist()


def test_make_zip_empty(tmp_path):
    zip_path = tmp_path / "empty.zip"
    storage.make_zip(articles_dir=str(tmp_path), zip_path=str(zip_path))
    assert os.path.exists(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        assert len(z.namelist()) == 0


def test_make_zip_multi(tmp_path):
    inst = {"nome": "inst1", "prompts": ["p1", "p2"]}
    inst_dir = tmp_path / "inst1"
    inst_dir.mkdir()
    for i in range(2):
        prompt_dir = inst_dir / f"prompt_{i+1}"
        prompt_dir.mkdir()
        (prompt_dir / f"artigo_{i+1}.txt").write_text(f"conteudo {i}")
    zip_path = tmp_path / "multi.zip"
    storage.make_zip_multi([inst], output_base=str(tmp_path), zip_path=str(zip_path))
    assert os.path.exists(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        files = z.namelist()
        assert any("artigo_1.txt" in f for f in files)
        assert any("artigo_2.txt" in f for f in files)


def test_make_zip_multi_empty(tmp_path):
    inst = {"nome": "inst2", "prompts": ["p1"]}
    inst_dir = tmp_path / "inst2"
    inst_dir.mkdir()
    # Não cria prompt_dir
    zip_path = tmp_path / "multi_empty.zip"
    storage.make_zip_multi([inst], output_base=str(tmp_path), zip_path=str(zip_path))
    assert os.path.exists(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        assert len(z.namelist()) == 0


def test_limpar_arquivos_antigos(tmp_path):
    old_file = tmp_path / "old.txt"
    old_file.write_text("velho")
    # Usar timestamp antigo, mas válido para Windows
    old_time = time.time() - (2 * 86400)
    os.utime(old_file, (old_time, old_time))
    storage.limpar_arquivos_antigos(str(tmp_path), dias=0)
    assert not old_file.exists()


def test_limpar_arquivos_antigos_novos(tmp_path):
    new_file = tmp_path / "new.txt"
    new_file.write_text("novo")
    storage.limpar_arquivos_antigos(str(tmp_path), dias=9999)
    assert new_file.exists()


def test_make_zip_exception(tmp_path, caplog):
    # Força erro ao criar ZIP
    with pytest.raises(Exception):
        storage.make_zip(articles_dir='/caminho/invalido', zip_path=str(tmp_path / 'fail.zip'))
    # Verifica se o log de erro foi registrado
    assert any(
        r.levelname == 'ERROR' and 'make_zip' in getattr(r, 'event', '')
        for r in caplog.records
    ) 