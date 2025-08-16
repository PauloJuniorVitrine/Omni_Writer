import sys
import os
import shutil
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import pytest
from unittest.mock import patch
from omni_writer.domain.models import ArticleOutput
from shared.status_repository import init_db

@pytest.fixture(autouse=True)
def mock_geracao_artigos():
    with patch('app.controller.generate_article') as mock_controller, \
         patch('infraestructure.openai_gateway.generate_article_openai') as mock_gateway:
        mock_controller.return_value = ArticleOutput(content='Artigo gerado de teste.', filename='artigo_teste.txt')
        mock_gateway.return_value = ArticleOutput(content='Artigo gerado de teste.', filename='artigo_teste.txt')
        yield 

@pytest.fixture(autouse=True)
def clean_data():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    blogs_file = os.path.join(base_dir, 'shared', 'blogs.json')
    prompts_dir = os.path.join(base_dir, 'shared', 'prompts')
    if os.path.exists(blogs_file):
        os.remove(blogs_file)
    if os.path.exists(prompts_dir):
        shutil.rmtree(prompts_dir)
    os.makedirs(prompts_dir, exist_ok=True)
    yield 

DB_PATH = "status.db"
OUTPUT_BASE_DIR = 'artigos_gerados'  # Valor padrão conforme estrutura do projeto
ARTIGOS_ZIP = 'artigos_gerados/omni_artigos.zip'  # Valor padrão conforme estrutura do projeto

@pytest.fixture(autouse=True)
def limpar_ambiente():
    """
    Limpa arquivos e diretórios críticos antes e depois de cada teste de integração.
    """
    def remove_com_retry(path, tentativas=5, delay=0.3):
        import time
        for _ in range(tentativas):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                    return
                elif os.path.isfile(path):
                    os.remove(path)
                    return
            except PermissionError:
                time.sleep(delay)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)
        except PermissionError:
            pass

    init_db()
    remove_com_retry(DB_PATH)
    remove_com_retry(OUTPUT_BASE_DIR)
    remove_com_retry(ARTIGOS_ZIP)
    yield
    remove_com_retry(DB_PATH)
    remove_com_retry(OUTPUT_BASE_DIR)
    remove_com_retry(ARTIGOS_ZIP)