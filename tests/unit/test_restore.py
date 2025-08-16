import os
import zipfile
import pytest
import scripts.restore as restore_mod

def test_restore_extrai_zip(tmp_path):
    # Cria um ZIP de teste
    zip_path = tmp_path / "test.zip"
    file_inside = "foo.txt"
    with zipfile.ZipFile(zip_path, 'w') as z:
        z.writestr(file_inside, "conteudo")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        restore_mod.restore(str(zip_path))
        assert os.path.exists(tmp_path / file_inside)
    finally:
        os.chdir(cwd)

def test_restore_arquivo_inexistente(tmp_path):
    with pytest.raises(FileNotFoundError):
        restore_mod.restore(str(tmp_path / "nao_existe.zip")) 