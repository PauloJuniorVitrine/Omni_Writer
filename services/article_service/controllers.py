"""
Controller para Article Service

Baseado no código real de app/controller.py
"""

import logging
import uuid
from datetime import datetime
from typing import List, Optional
import threading
import time

from .models import Article, Prompt, GenerationConfig, GenerationResult, BatchResult
from .services import ArticleGenerationService, ArticleStorageService

class ArticleController:
    """
    Controller principal do Article Service.
    
    Baseado no código real de app/controller.py
    """
    
    def __init__(self, generation_service: ArticleGenerationService, 
                 storage_service: ArticleStorageService):
        self.generation_service = generation_service
        self.storage_service = storage_service
        self.logger = logging.getLogger("article_controller")
        self.active_batches = {}  # batch_id -> BatchResult
    
    def generate_article(self, prompt: str, model_type: str = "openai", 
                        api_key: Optional[str] = None, trace_id: Optional[str] = None) -> GenerationResult:
        """
        Gera um artigo individual.
        
        Baseado no código real de app/controller.py
        """
        try:
            self.logger.info(f"Iniciando geração de artigo", extra={
                'trace_id': trace_id,
                'model_type': model_type,
                'prompt_length': len(prompt)
            })
            
            # Geração do artigo
            result = self.generation_service.generate_article(
                prompt=prompt,
                model_type=model_type,
                api_key=api_key,
                trace_id=trace_id
            )
            
            if result.success:
                # Cria o artigo
                article = Article(
                    id=result.article_id,
                    title=result.title,
                    content=result.content,
                    prompt=prompt,
                    model_type=model_type,
                    api_key=api_key,
                    metadata=result.metadata
                )
                
                # Salva o artigo
                if self.storage_service.save_article(article):
                    self.logger.info(f"Artigo gerado e salvo: {article.id}", extra={
                        'trace_id': trace_id,
                        'article_id': article.id
                    })
                else:
                    self.logger.error(f"Falha ao salvar artigo: {article.id}", extra={
                        'trace_id': trace_id,
                        'article_id': article.id
                    })
                    result.success = False
                    result.error_message = "Falha ao salvar artigo"
            
            return result
            
        except Exception as e:
            self.logger.error(f"Erro no controller: {str(e)}", extra={'trace_id': trace_id})
            return GenerationResult(
                success=False,
                error_message=f"Erro interno: {str(e)}",
                trace_id=trace_id
            )
    
    def generate_batch(self, prompts: List[str], model_type: str = "openai", 
                      api_key: Optional[str] = None, trace_id: Optional[str] = None) -> BatchResult:
        """
        Gera múltiplos artigos em lote.
        
        Baseado no código real de app/pipeline.py
        """
        try:
            batch_id = str(uuid.uuid4())
            
            self.logger.info(f"Iniciando geração em lote", extra={
                'trace_id': trace_id,
                'batch_id': batch_id,
                'total_prompts': len(prompts),
                'model_type': model_type
            })
            
            # Cria o lote
            batch = BatchResult(
                batch_id=batch_id,
                total_prompts=len(prompts),
                status="processing",
                trace_id=trace_id
            )
            
            # Salva o lote inicial
            self.storage_service.save_batch(batch)
            self.active_batches[batch_id] = batch
            
            # Inicia processamento em background
            thread = threading.Thread(
                target=self._process_batch,
                args=(batch_id, prompts, model_type, api_key, trace_id)
            )
            thread.daemon = True
            thread.start()
            
            return batch
            
        except Exception as e:
            self.logger.error(f"Erro ao iniciar lote: {str(e)}", extra={'trace_id': trace_id})
            return BatchResult(
                batch_id=str(uuid.uuid4()),
                total_prompts=len(prompts),
                status="failed",
                trace_id=trace_id
            )
    
    def _process_batch(self, batch_id: str, prompts: List[str], model_type: str, 
                      api_key: Optional[str], trace_id: Optional[str]):
        """
        Processa um lote de prompts em background.
        
        Baseado no código real de app/pipeline.py
        """
        try:
            batch = self.active_batches.get(batch_id)
            if not batch:
                return
            
            self.logger.info(f"Processando lote: {batch_id}", extra={
                'trace_id': trace_id,
                'batch_id': batch_id,
                'total_prompts': len(prompts)
            })
            
            for i, prompt in enumerate(prompts, 1):
                try:
                    # Gera o artigo
                    result = self.generation_service.generate_article(
                        prompt=prompt,
                        model_type=model_type,
                        api_key=api_key,
                        trace_id=trace_id
                    )
                    
                    if result.success:
                        # Cria o artigo
                        article = Article(
                            id=result.article_id,
                            title=result.title,
                            content=result.content,
                            prompt=prompt,
                            model_type=model_type,
                            api_key=api_key,
                            metadata=result.metadata
                        )
                        
                        # Adiciona ao lote
                        batch.articles.append(article)
                        batch.completed += 1
                        
                        self.logger.info(f"Artigo {i}/{len(prompts)} gerado", extra={
                            'trace_id': trace_id,
                            'batch_id': batch_id,
                            'article_id': article.id,
                            'progress': f"{i}/{len(prompts)}"
                        })
                    else:
                        batch.failed += 1
                        self.logger.error(f"Falha na geração do artigo {i}", extra={
                            'trace_id': trace_id,
                            'batch_id': batch_id,
                            'error': result.error_message
                        })
                    
                    # Atualiza o lote
                    self.storage_service.save_batch(batch)
                    
                    # Pequena pausa para não sobrecarregar as APIs
                    time.sleep(1)
                    
                except Exception as e:
                    batch.failed += 1
                    self.logger.error(f"Erro no artigo {i}: {str(e)}", extra={
                        'trace_id': trace_id,
                        'batch_id': batch_id
                    })
            
            # Finaliza o lote
            batch.status = "completed"
            batch.completed_at = datetime.utcnow()
            self.storage_service.save_batch(batch)
            
            # Remove do cache ativo
            if batch_id in self.active_batches:
                del self.active_batches[batch_id]
            
            self.logger.info(f"Lote concluído: {batch_id}", extra={
                'trace_id': trace_id,
                'batch_id': batch_id,
                'completed': batch.completed,
                'failed': batch.failed
            })
            
        except Exception as e:
            self.logger.error(f"Erro no processamento do lote: {str(e)}", extra={
                'trace_id': trace_id,
                'batch_id': batch_id
            })
            
            # Marca o lote como falhado
            batch = self.active_batches.get(batch_id)
            if batch:
                batch.status = "failed"
                self.storage_service.save_batch(batch)
                del self.active_batches[batch_id]
    
    def get_article(self, article_id: str) -> Optional[Article]:
        """Recupera um artigo pelo ID"""
        return self.storage_service.get_article(article_id)
    
    def get_batch_status(self, batch_id: str) -> Optional[dict]:
        """Recupera o status de um lote"""
        # Primeiro verifica no cache ativo
        if batch_id in self.active_batches:
            batch = self.active_batches[batch_id]
            return {
                'batch_id': batch.batch_id,
                'status': batch.status,
                'total_prompts': batch.total_prompts,
                'completed': batch.completed,
                'failed': batch.failed,
                'progress_percentage': (batch.completed / batch.total_prompts * 100) if batch.total_prompts > 0 else 0
            }
        
        # Se não estiver no cache, busca no storage
        batch = self.storage_service.get_batch(batch_id)
        if batch:
            return {
                'batch_id': batch.batch_id,
                'status': batch.status,
                'total_prompts': batch.total_prompts,
                'completed': batch.completed,
                'failed': batch.failed,
                'progress_percentage': (batch.completed / batch.total_prompts * 100) if batch.total_prompts > 0 else 0,
                'completed_at': batch.completed_at.isoformat() if batch.completed_at else None
            }
        
        return None
    
    def export_batch(self, batch_id: str) -> Optional[str]:
        """Exporta um lote como ZIP"""
        return self.storage_service.create_zip_export(batch_id)
    
    def get_batch_zip_path(self, batch_id: str) -> Optional[str]:
        """Retorna o caminho do ZIP de um lote"""
        return self.storage_service.get_zip_path(batch_id) 