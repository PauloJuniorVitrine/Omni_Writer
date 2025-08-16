import pytest
import os
import tempfile
import shutil
from unittest import mock
from omni_writer.domain.data_models import ArticleOutput
import infraestructure.storage as storage

@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)

@pytest.fixture(autouse=True)
def clean_hashes_file():
    if os.path.exists(storage.HASHES_FILE):
        os.remove(storage.HASHES_FILE)
    yield
    if os.path.exists(storage.HASHES_FILE):
        os.remove(storage.HASHES_FILE)

# Teste de hash
@pytest.mark.parametrize("content", ["abc", "", "1234567890"])
def test_get_content_hash(content):
    h = storage.get_content_hash(content)
    assert isinstance(h, str)
    assert len(h) == 64

# Teste de save/load hash
@pytest.mark.parametrize("hashes", [{"a", "b"}, set(), {"x"}])
def test_save_and_load_hash(hashes):
    storage.save_hash(hashes)
    loaded = storage.load_hashes()
    assert set(loaded) == set(hashes)

# Teste de save_article (novo e duplicado)
def test_save_article_new_and_duplicate(temp_dir):
    art = ArticleOutput(content="conteudo unico", filename="a.txt")
    storage.save_article(art, output_dir=temp_dir)
    # Duplicado não deve salvar novamente
    with mock.patch.object(storage.logger, "info") as logger_info:
        storage.save_article(art, output_dir=temp_dir)
        logger_info.assert_any_call(mock.ANY, extra=mock.ANY)
    files = os.listdir(temp_dir)
    assert "a.txt" in files

# Teste de exceção em save_article (branch crítico)
def test_save_article_exception(temp_dir):
    art = ArticleOutput(content="conteudo", filename="a.txt")
    # Simular erro de I/O ao salvar arquivo
    with mock.patch("builtins.open", side_effect=OSError("Erro de I/O")):
        with pytest.raises(OSError):
            storage.save_article(art, output_dir=temp_dir)

# Teste de make_zip
def test_make_zip(temp_dir):
    art = ArticleOutput(content="abc", filename="a.txt")
    storage.save_article(art, output_dir=temp_dir)
    zip_path = os.path.join(temp_dir, "test.zip")
    storage.make_zip(articles_dir=temp_dir, zip_path=zip_path)
    assert os.path.exists(zip_path)

# Teste de make_zip_multi
def test_make_zip_multi(temp_dir):
    inst = [{"nome": "inst1", "prompts": ["p1"]}]
    inst_dir = os.path.join(temp_dir, "inst1", "prompt_1")
    os.makedirs(inst_dir)
    with open(os.path.join(inst_dir, "a.txt"), "w") as f:
        f.write("abc")
    zip_path = os.path.join(temp_dir, "multi.zip")
    storage.make_zip_multi(instances=inst, output_base=temp_dir, zip_path=zip_path)
    assert os.path.exists(zip_path)

# Teste de limpar_arquivos_antigos
def test_limpar_arquivos_antigos(temp_dir):
    file_path = os.path.join(temp_dir, "old.txt")
    with open(file_path, "w") as f:
        f.write("abc")
    os.utime(file_path, (0, 0))  # Tornar antigo
    storage.limpar_arquivos_antigos(temp_dir, dias=0)
    assert not os.path.exists(file_path)

# Teste de init_blog_db e get_blog_session
def test_init_blog_db_and_get_blog_session():
    engine = storage.init_blog_db()
    session = storage.get_blog_session()
    assert engine is not None
    assert session is not None

# Teste de get_generation_status
def test_get_generation_status():
    with mock.patch("shared.status_repository.get_status", return_value={"status": "ok"}):
        st = storage.get_generation_status("abc")
        assert st["status"] == "ok" 