"""
/tests/integration/test_limpeza_storage_integration.spec.py
Fluxo: Limpeza e Manutenção
Camadas tocadas: Storage → Sistema de arquivos
Tipos de lógica: Remoção automática, efeitos colaterais, manutenção
Dependências externas: Sistema de arquivos
"""

import os
import time
import pytest
from infraestructure.storage import limpar_arquivos_antigos

@pytest.mark.integration
def test_limpeza_arquivos_antigos(tmp_path):
    """
    Teste de integração da limpeza automática de arquivos antigos:
    - Cria arquivos e diretórios antigos artificialmente
    - Executa função de limpeza
    - Valida remoção dos arquivos e pastas antigos
    """
    # Cria estrutura de arquivos antigos
    dir_antigo = tmp_path / "antigo_dir"
    dir_antigo.mkdir()
    file_antigo = dir_antigo / "velho.txt"
    file_antigo.write_text("conteudo velho")
    # Define mtime para 10 dias atrás
    old_time = time.time() - (10 * 86400)
    os.utime(file_antigo, (old_time, old_time))
    os.utime(dir_antigo, (old_time, old_time))
    # Cria arquivo novo
    file_novo = tmp_path / "novo.txt"
    file_novo.write_text("conteudo novo")
    # Executa limpeza para arquivos com mais de 7 dias
    limpar_arquivos_antigos(str(tmp_path), dias=7)
    # Valida remoção do arquivo e diretório antigos
    assert not file_antigo.exists(), "Arquivo antigo não foi removido"
    assert not dir_antigo.exists(), "Diretório antigo não foi removido"
    # Valida que arquivo novo permanece
    assert file_novo.exists(), "Arquivo novo foi removido indevidamente" 