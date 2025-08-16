"""
Storage utilities for article generation.
Handles saving articles, ZIP packaging, hash management, and cleanup routines.
"""
import os
import hashlib
import json as pyjson
from zipfile import ZipFile
from omni_writer.domain.models import ArticleOutput, Base, Blog, Prompt
from shared.config import ARTIGOS_DIR, ARTIGOS_ZIP, OUTPUT_BASE_DIR
from shared.logger import get_logger
from shared.messages import get_message
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from shared.status_repository import get_status

logger = get_logger(__name__)

HASHES_FILE = 'artigos_hashes.json'

DB_PATH = os.getenv('BLOG_DB_PATH', 'blogs.db')
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)

def load_hashes():
    """
    Loads the set of content hashes from the hash file.
    Returns:
        set: Set of SHA-256 hashes.
    """
    if os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, 'r', encoding='utf-8') as f:
            return set(pyjson.load(f))
    return set()

def save_hash(hash_set):
    """
    Saves the set of content hashes to the hash file.
    Args:
        hash_set (set): Set of SHA-256 hashes.
    """
    with open(HASHES_FILE, 'w', encoding='utf-8') as f:
        pyjson.dump(list(hash_set), f)

def get_content_hash(content: str) -> str:
    """
    Calculates the SHA-256 hash of the given content string.
    Args:
        content (str): Content to hash.
    Returns:
        str: SHA-256 hash.
    """
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def save_article(article: ArticleOutput, output_dir: str = ARTIGOS_DIR, trace_id: str = None):
    """
    Saves an article to the specified directory, ensuring uniqueness by content hash.
    If the article already exists (same content), it will not be saved again.
    Updates the hash repository and registra logs internacionalizados.
    Args:
        article (ArticleOutput): Artigo a ser salvo.
        output_dir (str): Diretório de destino.
        trace_id (str, opcional): ID de rastreamento para logs.
    """
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, article.filename)
    content_hash = get_content_hash(article.content)
    hashes = load_hashes()
    if content_hash in hashes:
        logger.info(get_message('artigo_duplicado_ignorado', arquivo=file_path), extra={'event': 'save_article', 'status': 'ignored', 'source': 'storage', 'details': f'Artigo duplicado ignorado: {file_path}', 'trace_id': trace_id})
        return
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(article.content)
        hashes.add(content_hash)
        save_hash(hashes)
        logger.info(get_message('artigo_salvo', arquivo=file_path), extra={'event': 'save_article', 'status': 'success', 'source': 'storage', 'details': f'Artigo salvo: {file_path}', 'trace_id': trace_id})
    except Exception as e:
        logger.error(get_message('erro_salvar_artigo', erro=str(e)), extra={'event': 'save_article', 'status': 'error', 'source': 'storage', 'details': str(e), 'trace_id': trace_id})
        raise

def make_zip(articles_dir: str = ARTIGOS_DIR, zip_path: str = ARTIGOS_ZIP, trace_id: str = None):
    """
    Creates a ZIP file containing all .txt articles in the specified directory.
    Args:
        articles_dir (str): Directory containing articles.
        zip_path (str): Path to the output ZIP file.
        trace_id (str, optional): Trace identifier for logs.
    """
    try:
        with ZipFile(zip_path, 'w') as zipf:
            for filename in os.listdir(articles_dir):
                if filename.endswith('.txt'):
                    zipf.write(os.path.join(articles_dir, filename), filename)
        logger.info('', extra={'event': 'make_zip', 'status': 'success', 'source': 'storage', 'details': f'ZIP gerado: {zip_path}', 'trace_id': trace_id})
    except Exception as e:
        logger.error('', extra={'event': 'make_zip', 'status': 'error', 'source': 'storage', 'details': str(e), 'trace_id': trace_id})
        raise

def make_zip_multi(instances: list, output_base: str = OUTPUT_BASE_DIR, zip_path: str = None, trace_id: str = None):
    """
    Creates a ZIP file containing all .txt articles for multiple instances.
    Args:
        instances (list): List of instance configurations.
        output_base (str): Base output directory.
        zip_path (str, optional): Path to the output ZIP file.
        trace_id (str, optional): Trace identifier for logs.
    """
    if zip_path is None:
        zip_path = os.path.join(output_base, 'omni_artigos.zip')
    try:
        with ZipFile(zip_path, 'w') as zipf:
            for inst in instances:
                inst_dir = os.path.join(output_base, inst['nome'])
                if not os.path.exists(inst_dir):
                    continue
                for prompt_idx in range(len(inst['prompts'])):
                    prompt_dir = os.path.join(inst_dir, f'prompt_{prompt_idx+1}')
                    if not os.path.exists(prompt_dir):
                        continue
                    for filename in os.listdir(prompt_dir):
                        if filename.endswith('.txt'):
                            arcname = os.path.join(inst['nome'], f'prompt_{prompt_idx+1}', filename)
                            zipf.write(os.path.join(prompt_dir, filename), arcname)
        logger.info('', extra={'event': 'make_zip_multi', 'status': 'success', 'source': 'storage', 'details': f'ZIP multi gerado: {zip_path}', 'trace_id': trace_id})
    except Exception as e:
        logger.error('', extra={'event': 'make_zip_multi', 'status': 'error', 'source': 'storage', 'details': str(e), 'trace_id': trace_id})
        raise

def limpar_arquivos_antigos(diretorio: str, dias: int = 7):
    """
    Removes files and folders modified more than 'dias' days ago in the given directory.
    Args:
        diretorio (str): Target directory.
        dias (int): Number of days to keep files.
    """
    import time
    agora = time.time()
    limite = dias * 86400
    for root, dirs, files in os.walk(diretorio):
        for nome in files:
            caminho = os.path.join(root, nome)
            if os.path.isfile(caminho) and agora - os.path.getmtime(caminho) > limite:
                try:
                    os.remove(caminho)
                except Exception:
                    pass
        for nome in dirs:
            caminho = os.path.join(root, nome)
            if os.path.isdir(caminho) and agora - os.path.getmtime(caminho) > limite:
                try:
                    import shutil
                    shutil.rmtree(caminho)
                except Exception:
                    pass

def init_blog_db():
    """
    Inicializa o banco de dados de blogs/prompts (cria tabelas se não existirem).
    """
    Base.metadata.create_all(engine)
    return engine

def get_blog_session():
    """
    Retorna uma nova sessão SQLAlchemy para operações de Blog/Prompt.
    """
    return SessionLocal()

def get_generation_status(trace_id: str):
    """
    Retorna o status de geração de artigos para um trace_id.
    """
    return get_status(trace_id) 