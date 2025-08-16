"""
Comandos CQRS para geração de artigos.

Baseados no código real de generate_articles.py e data_models.py.
Implementa operações de geração de artigos usando IA providers reais.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
import os
import zipfile
from datetime import datetime
from typing import Dict, Any, Optional
from .base_command import BaseCommand, CommandResult
from omni_writer.domain.orm_models import Blog, Categoria, Cluster
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput
from omni_writer.domain.ia_providers import IAProvider, OpenAIProvider, GeminiProvider, ClaudeProvider
from shared.prompts.parser_prompt_base_artigos import PromptBaseArtigosParser

logger = logging.getLogger("domain.commands.article")

class GenerateArticleCommand(BaseCommand):
    """
    Comando para gerar um artigo específico.
    Baseado no código real de generate_articles.py e data_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para geração de artigo baseado no código real."""
        categoria_id = data.get('categoria_id')
        artigo_idx = data.get('artigo_idx')
        semana = data.get('semana')
        output_dir = data.get('output_dir', 'output')
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em GenerateArticleCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
        
        if not isinstance(artigo_idx, int) or not (1 <= artigo_idx <= 6):
            logger.error(f"Validação falhou: artigo_idx inválido em GenerateArticleCommand: {artigo_idx}")
            raise ValueError("Índice do artigo deve ser entre 1 e 6")
        
        if semana is not None and not isinstance(semana, str):
            logger.error(f"Validação falhou: semana inválida em GenerateArticleCommand: {type(semana)}")
            raise ValueError("Semana deve ser uma string ou None")
        
        if not isinstance(output_dir, str) or not output_dir.strip():
            logger.error(f"Validação falhou: output_dir inválido em GenerateArticleCommand: '{output_dir}'")
            raise ValueError("Diretório de saída deve ser uma string não vazia")
    
    def execute(self, session) -> CommandResult:
        """Executa geração de artigo baseado no código real."""
        try:
            self._log_execution_start()
            
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria or not categoria.prompt_path:
                error_msg = f"Categoria {self._data['categoria_id']} não encontrada ou sem prompt_path"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            blog = categoria.blog
            clusters = categoria.clusters
            
            # Usar parser real do código existente
            parser = PromptBaseArtigosParser(categoria.prompt_path)
            prompt_data = parser.parse()
            
            semana = self._data.get('semana') or datetime.utcnow().strftime("%Y-%W")
            base_path = os.path.join(
                self._data.get('output_dir', 'output'),
                blog.nome,
                categoria.nome,
                semana
            )
            os.makedirs(base_path, exist_ok=True)
            
            artigo_path = os.path.join(base_path, f"artigo_{self._data['artigo_idx']}.txt")
            
            # Gerar conteúdo usando provider real
            provider = self._get_provider(categoria)
            prompt = f"Artigo {self._data['artigo_idx']} | Cluster: {clusters} | Dados: {prompt_data}"
            config = {
                "idx": self._data['artigo_idx'],
                "prompt_data": prompt_data,
                "clusters": clusters
            }
            
            artigo_content = provider.generate_article(prompt, config)
            
            # Salvar arquivo
            with open(artigo_path, "w", encoding="utf-8") as f:
                f.write(artigo_content)
            
            result = self._create_success_result({
                'artigo_path': artigo_path,
                'artigo_idx': self._data['artigo_idx'],
                'categoria_id': self._data['categoria_id'],
                'blog_nome': blog.nome,
                'categoria_nome': categoria.nome,
                'semana': semana,
                'content_length': len(artigo_content)
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            self._log_execution_error(e)
            return self._create_error_result(e)
    
    def _get_provider(self, categoria: Categoria) -> IAProvider:
        """Obtém provider de IA baseado no código real."""
        if categoria.ia_provider == 'gemini':
            return GeminiProvider()
        elif categoria.ia_provider == 'claude':
            return ClaudeProvider()
        # Default: OpenAI
        return OpenAIProvider()

class GenerateArticlesForCategoriaCommand(BaseCommand):
    """
    Comando para gerar 6 artigos para uma categoria.
    Baseado no método generate_for_categoria do código real.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para geração de artigos por categoria."""
        categoria_id = data.get('categoria_id')
        semana = data.get('semana')
        output_dir = data.get('output_dir', 'output')
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em GenerateArticlesForCategoriaCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
        
        if semana is not None and not isinstance(semana, str):
            logger.error(f"Validação falhou: semana inválida em GenerateArticlesForCategoriaCommand: {type(semana)}")
            raise ValueError("Semana deve ser uma string ou None")
        
        if not isinstance(output_dir, str) or not output_dir.strip():
            logger.error(f"Validação falhou: output_dir inválido em GenerateArticlesForCategoriaCommand: '{output_dir}'")
            raise ValueError("Diretório de saída deve ser uma string não vazia")
    
    def execute(self, session) -> CommandResult:
        """Executa geração de 6 artigos para categoria baseado no código real."""
        try:
            self._log_execution_start()
            
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria or not categoria.prompt_path:
                error_msg = f"Categoria {self._data['categoria_id']} não encontrada ou sem prompt_path"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            blog = categoria.blog
            clusters = categoria.clusters
            
            # Usar parser real do código existente
            parser = PromptBaseArtigosParser(categoria.prompt_path)
            prompt_data = parser.parse()
            
            semana = self._data.get('semana') or datetime.utcnow().strftime("%Y-%W")
            base_path = os.path.join(
                self._data.get('output_dir', 'output'),
                blog.nome,
                categoria.nome,
                semana
            )
            os.makedirs(base_path, exist_ok=True)
            
            provider = self._get_provider(categoria)
            artigos_gerados = []
            
            # Gerar 6 artigos (baseado no código real)
            for idx in range(1, 7):
                artigo_path = os.path.join(base_path, f"artigo_{idx}.txt")
                prompt = f"Artigo {idx} | Cluster: {clusters} | Dados: {prompt_data}"
                config = {
                    "idx": idx,
                    "prompt_data": prompt_data,
                    "clusters": clusters
                }
                
                artigo_content = provider.generate_article(prompt, config)
                
                with open(artigo_path, "w", encoding="utf-8") as f:
                    f.write(artigo_content)
                
                artigos_gerados.append({
                    'artigo_idx': idx,
                    'artigo_path': artigo_path,
                    'content_length': len(artigo_content)
                })
            
            result = self._create_success_result({
                'categoria_id': self._data['categoria_id'],
                'blog_nome': blog.nome,
                'categoria_nome': categoria.nome,
                'semana': semana,
                'artigos_gerados': artigos_gerados,
                'total_artigos': len(artigos_gerados)
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            self._log_execution_error(e)
            return self._create_error_result(e)
    
    def _get_provider(self, categoria: Categoria) -> IAProvider:
        """Obtém provider de IA baseado no código real."""
        if categoria.ia_provider == 'gemini':
            return GeminiProvider()
        elif categoria.ia_provider == 'claude':
            return ClaudeProvider()
        # Default: OpenAI
        return OpenAIProvider()

class GenerateZipEntregaCommand(BaseCommand):
    """
    Comando para gerar ZIP de entrega com todos os artigos.
    Baseado no método generate_zip_entrega do código real.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para geração de ZIP de entrega."""
        semana = data.get('semana')
        output_dir = data.get('output_dir', 'output')
        
        if semana is not None and not isinstance(semana, str):
            logger.error(f"Validação falhou: semana inválida em GenerateZipEntregaCommand: {type(semana)}")
            raise ValueError("Semana deve ser uma string ou None")
        
        if not isinstance(output_dir, str) or not output_dir.strip():
            logger.error(f"Validação falhou: output_dir inválido em GenerateZipEntregaCommand: '{output_dir}'")
            raise ValueError("Diretório de saída deve ser uma string não vazia")
    
    def execute(self, session) -> CommandResult:
        """Executa geração de ZIP de entrega baseado no código real."""
        try:
            self._log_execution_start()
            
            blogs = session.query(Blog).all()
            semana = self._data.get('semana') or datetime.utcnow().strftime("%Y-%W")
            base_output = os.path.join(self._data.get('output_dir', 'output'), "entrega_tmp")
            
            # Limpar diretório temporário se existir
            if os.path.exists(base_output):
                import shutil
                shutil.rmtree(base_output)
            os.makedirs(base_output, exist_ok=True)
            
            total_artigos = 0
            
            for blog in blogs:
                nicho_path = os.path.join(base_output, blog.nome)
                os.makedirs(nicho_path, exist_ok=True)
                
                # Garantir 7 categorias (baseado no código real)
                categorias = blog.categorias[:7]
                
                for categoria in categorias:
                    cat_path = os.path.join(nicho_path, categoria.nome)
                    os.makedirs(cat_path, exist_ok=True)
                    
                    # Usar parser real do código existente
                    parser = PromptBaseArtigosParser(categoria.prompt_path)
                    prompt_data = parser.parse()
                    clusters = categoria.clusters
                    provider = self._get_provider(categoria)
                    
                    # Gerar 6 artigos por categoria
                    for idx in range(1, 7):
                        artigo_path = os.path.join(cat_path, f"artigo{idx}.txt")
                        prompt = f"Artigo {idx} | Cluster: {clusters} | Dados: {prompt_data}"
                        config = {
                            "idx": idx,
                            "prompt_data": prompt_data,
                            "clusters": clusters
                        }
                        
                        artigo_content = provider.generate_article(prompt, config)
                        
                        with open(artigo_path, "w", encoding="utf-8") as f:
                            f.write(artigo_content)
                        
                        total_artigos += 1
            
            # Criar ZIP (baseado no código real)
            zip_path = os.path.join(self._data.get('output_dir', 'output'), "entrega.zip")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(base_output):
                    for file in files:
                        abs_path = os.path.join(root, file)
                        rel_path = os.path.relpath(abs_path, base_output)
                        zipf.write(abs_path, rel_path)
            
            result = self._create_success_result({
                'zip_path': zip_path,
                'semana': semana,
                'total_blogs': len(blogs),
                'total_artigos': total_artigos,
                'temp_dir': base_output
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            self._log_execution_error(e)
            return self._create_error_result(e)
    
    def _get_provider(self, categoria: Categoria) -> IAProvider:
        """Obtém provider de IA baseado no código real."""
        if categoria.ia_provider == 'gemini':
            return GeminiProvider()
        elif categoria.ia_provider == 'claude':
            return ClaudeProvider()
        # Default: OpenAI
        return OpenAIProvider() 