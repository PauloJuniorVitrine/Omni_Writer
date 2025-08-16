"""
Serviços para Article Service

Baseados no código real de app/services/generation_service.py e infraestructure/
"""

import os
import json
import logging
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
import zipfile
import tempfile

from .models import Article, Prompt, GenerationConfig, GenerationResult, BatchResult

class ArticleGenerationService:
    """
    Serviço de geração de artigos baseado no código real
    """
    
    def __init__(self):
        self.logger = logging.getLogger("article_generation_service")
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.deepseek_api_key = os.getenv('DEEPSEEK_API_KEY')
    
    def generate_article(self, prompt: str, model_type: str = "openai", 
                        api_key: Optional[str] = None, trace_id: Optional[str] = None) -> GenerationResult:
        """
        Gera um artigo baseado no prompt fornecido.
        
        Baseado no código real de infraestructure/openai_gateway.py e deepseek_gateway.py
        """
        try:
            # Validação
            if not prompt:
                return GenerationResult(
                    success=False,
                    error_message="Prompt é obrigatório",
                    trace_id=trace_id
                )
            
            if model_type not in ["openai", "deepseek"]:
                return GenerationResult(
                    success=False,
                    error_message="Modelo deve ser 'openai' ou 'deepseek'",
                    trace_id=trace_id
                )
            
            # Seleção da API key
            if model_type == "openai":
                api_key = api_key or self.openai_api_key
                if not api_key:
                    return GenerationResult(
                        success=False,
                        error_message="API key do OpenAI não configurada",
                        trace_id=trace_id
                    )
                content = self._generate_with_openai(prompt, api_key)
            else:
                api_key = api_key or self.deepseek_api_key
                if not api_key:
                    return GenerationResult(
                        success=False,
                        error_message="API key do DeepSeek não configurada",
                        trace_id=trace_id
                    )
                content = self._generate_with_deepseek(prompt, api_key)
            
            if not content:
                return GenerationResult(
                    success=False,
                    error_message="Falha na geração do conteúdo",
                    trace_id=trace_id
                )
            
            # Criação do artigo
            article = Article(
                title=self._extract_title(content),
                content=content,
                prompt=prompt,
                model_type=model_type,
                api_key=api_key,
                metadata={
                    'model_type': model_type,
                    'prompt_length': len(prompt),
                    'content_length': len(content),
                    'trace_id': trace_id
                }
            )
            
            return GenerationResult(
                success=True,
                article_id=article.id,
                content=content,
                title=article.title,
                trace_id=trace_id,
                metadata=article.metadata
            )
            
        except Exception as e:
            self.logger.error(f"Erro na geração: {str(e)}", extra={'trace_id': trace_id})
            return GenerationResult(
                success=False,
                error_message=f"Erro interno: {str(e)}",
                trace_id=trace_id
            )
    
    def _generate_with_openai(self, prompt: str, api_key: str) -> Optional[str]:
        """Geração via OpenAI baseada no código real"""
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "Você é um escritor profissional especializado em criar artigos longos e detalhados."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"Erro OpenAI: {str(e)}")
            return None
    
    def _generate_with_deepseek(self, prompt: str, api_key: str) -> Optional[str]:
        """Geração via DeepSeek baseada no código real"""
        try:
            import httpx
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "system", "content": "Você é um escritor profissional especializado em criar artigos longos e detalhados."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 2000,
                "temperature": 0.7
            }
            
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers=headers,
                    json=data
                )
                response.raise_for_status()
                
                result = response.json()
                return result["choices"][0]["message"]["content"]
                
        except Exception as e:
            self.logger.error(f"Erro DeepSeek: {str(e)}")
            return None
    
    def _extract_title(self, content: str) -> str:
        """Extrai título do conteúdo"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) < 100:
                return line
        return "Artigo Gerado"

class ArticleStorageService:
    """
    Serviço de armazenamento baseado no código real de infraestructure/storage.py
    """
    
    def __init__(self):
        self.logger = logging.getLogger("article_storage_service")
        self.storage_dir = os.getenv('OUTPUT_BASE_DIR', 'output')
        self.ensure_storage_dir()
    
    def ensure_storage_dir(self):
        """Garante que o diretório de armazenamento existe"""
        os.makedirs(self.storage_dir, exist_ok=True)
        os.makedirs(os.path.join(self.storage_dir, 'articles'), exist_ok=True)
        os.makedirs(os.path.join(self.storage_dir, 'batches'), exist_ok=True)
    
    def save_article(self, article: Article) -> bool:
        """Salva um artigo no sistema de arquivos"""
        try:
            article_dir = os.path.join(self.storage_dir, 'articles', article.id)
            os.makedirs(article_dir, exist_ok=True)
            
            # Salva o artigo como JSON
            article_file = os.path.join(article_dir, 'article.json')
            with open(article_file, 'w', encoding='utf-8') as f:
                json.dump(article.to_dict(), f, ensure_ascii=False, indent=2)
            
            # Salva o conteúdo como texto
            content_file = os.path.join(article_dir, 'content.txt')
            with open(content_file, 'w', encoding='utf-8') as f:
                f.write(article.content)
            
            self.logger.info(f"Artigo salvo: {article.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar artigo: {str(e)}")
            return False
    
    def get_article(self, article_id: str) -> Optional[Article]:
        """Recupera um artigo pelo ID"""
        try:
            article_file = os.path.join(self.storage_dir, 'articles', article_id, 'article.json')
            if not os.path.exists(article_file):
                return None
            
            with open(article_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return Article.from_dict(data)
            
        except Exception as e:
            self.logger.error(f"Erro ao recuperar artigo: {str(e)}")
            return None
    
    def save_batch(self, batch: BatchResult) -> bool:
        """Salva um lote de artigos"""
        try:
            batch_dir = os.path.join(self.storage_dir, 'batches', batch.batch_id)
            os.makedirs(batch_dir, exist_ok=True)
            
            # Salva o lote como JSON
            batch_file = os.path.join(batch_dir, 'batch.json')
            with open(batch_file, 'w', encoding='utf-8') as f:
                json.dump(batch.to_dict(), f, ensure_ascii=False, indent=2)
            
            # Salva os artigos individuais
            for article in batch.articles:
                self.save_article(article)
            
            self.logger.info(f"Lote salvo: {batch.batch_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar lote: {str(e)}")
            return False
    
    def get_batch(self, batch_id: str) -> Optional[BatchResult]:
        """Recupera um lote pelo ID"""
        try:
            batch_file = os.path.join(self.storage_dir, 'batches', batch_id, 'batch.json')
            if not os.path.exists(batch_file):
                return None
            
            with open(batch_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Reconstrói os artigos
            articles = []
            for article_data in data.get('articles', []):
                article = Article.from_dict(article_data)
                articles.append(article)
            
            batch = BatchResult(
                batch_id=data['batch_id'],
                total_prompts=data['total_prompts'],
                completed=data['completed'],
                failed=data['failed'],
                status=data['status'],
                created_at=datetime.fromisoformat(data['created_at']),
                completed_at=datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None,
                trace_id=data.get('trace_id'),
                articles=articles
            )
            
            return batch
            
        except Exception as e:
            self.logger.error(f"Erro ao recuperar lote: {str(e)}")
            return None
    
    def create_zip_export(self, batch_id: str) -> Optional[str]:
        """Cria arquivo ZIP com os artigos do lote"""
        try:
            batch = self.get_batch(batch_id)
            if not batch:
                return None
            
            zip_path = os.path.join(self.storage_dir, 'batches', batch_id, f'articles_{batch_id}.zip')
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for i, article in enumerate(batch.articles, 1):
                    # Adiciona o conteúdo do artigo
                    content_filename = f'article_{i:03d}.txt'
                    zipf.writestr(content_filename, article.content)
                    
                    # Adiciona metadados
                    metadata_filename = f'article_{i:03d}_metadata.json'
                    zipf.writestr(metadata_filename, json.dumps(article.to_dict(), ensure_ascii=False, indent=2))
            
            self.logger.info(f"ZIP criado: {zip_path}")
            return zip_path
            
        except Exception as e:
            self.logger.error(f"Erro ao criar ZIP: {str(e)}")
            return None
    
    def get_zip_path(self, batch_id: str) -> Optional[str]:
        """Retorna o caminho do arquivo ZIP se existir"""
        zip_path = os.path.join(self.storage_dir, 'batches', batch_id, f'articles_{batch_id}.zip')
        return zip_path if os.path.exists(zip_path) else None 