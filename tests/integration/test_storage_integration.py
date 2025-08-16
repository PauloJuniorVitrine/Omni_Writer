"""
Testes de Integração — Storage

Cenários cobertos:
- Concorrência: múltiplos processos acessando funções de storage simultaneamente.
- Grandes volumes: criação, leitura e limpeza de centenas/milhares de arquivos.
- Performance: tempo de execução de operações de ZIP, limpeza, etc.
- Integração real: interação com sistema de arquivos, permissões, locks.

Observação: Não misture testes unitários e de integração neste arquivo.
"""

import os
import tempfile
import shutil
import pytest
from infraestructure import storage
import multiprocessing
import time

# Exemplos de funções de teste serão adicionados incrementalmente conforme o plano. 

def worker_save_article(output_dir, idx):
    from domain.models import ArticleOutput
    art = ArticleOutput(content=f"conteudo {idx}", filename=f"a{idx}.txt")
    storage.save_article(art, output_dir=output_dir)

def test_concorrencia_escrita_simultanea():
    """Testa se múltiplos processos conseguem salvar artigos simultaneamente sem corromper arquivos."""
    with tempfile.TemporaryDirectory() as tmpdir:
        procs = []
        for i in range(10):
            p = multiprocessing.Process(target=worker_save_article, args=(tmpdir, i))
            procs.append(p)
            p.start()
        for p in procs:
            p.join()
        files = os.listdir(tmpdir)
        assert len(files) == 10
        for i in range(10):
            assert f"a{i}.txt" in files

def test_grande_volume_criacao_limpeza():
    """Testa criação e limpeza de centenas de arquivos."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(300):
            with open(os.path.join(tmpdir, f"f{i}.txt"), "w") as f:
                f.write("x" * 100)
        assert len(os.listdir(tmpdir)) == 300
        storage.limpar_arquivos_antigos(tmpdir, dias=0)
        assert len(os.listdir(tmpdir)) == 0

def test_performance_make_zip():
    """Testa tempo de execução de make_zip com muitos arquivos."""
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(200):
            with open(os.path.join(tmpdir, f"f{i}.txt"), "w") as f:
                f.write("x" * 100)
        zip_path = os.path.join(tmpdir, "out.zip")
        start = time.time()
        storage.make_zip(articles_dir=tmpdir, zip_path=zip_path)
        elapsed = time.time() - start
        assert os.path.exists(zip_path)
        assert elapsed < 10  # Limite arbitrário de 10s para performance 