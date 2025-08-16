"""
Serviço de validação para limites de blogs, categorias e prompts.
"""
import logging
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from .orm_models import Blog, Categoria, Prompt

logger = logging.getLogger("domain.validation_service")

class ValidationService:
    """
    Serviço para validar limites e regras de negócio.
    """
    
    # Limites definidos
    MAX_BLOGS = 15
    MAX_CATEGORIAS_PER_BLOG = 7
    MAX_PROMPTS_PER_CATEGORIA = 3
    
    def __init__(self, session: Session):
        self.session = session
    
    def validate_blog_creation(self, nome: str) -> Tuple[bool, Optional[str]]:
        """
        Valida se é possível criar um novo blog.
        
        Args:
            nome: Nome do blog
            
        Returns:
            Tuple[bool, Optional[str]]: (sucesso, mensagem_erro)
        """
        try:
            # Verificar se já existe blog com este nome
            existing_blog = self.session.query(Blog).filter_by(nome=nome).first()
            if existing_blog:
                return False, f"Já existe um blog com o nome '{nome}'"
            
            # Verificar limite de blogs
            total_blogs = self.session.query(Blog).count()
            if total_blogs >= self.MAX_BLOGS:
                return False, f"Limite máximo de {self.MAX_BLOGS} blogs atingido"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Erro ao validar criação de blog: {e}")
            return False, "Erro interno na validação"
    
    def validate_categoria_creation(self, blog_id: int, nome: str) -> Tuple[bool, Optional[str]]:
        """
        Valida se é possível criar uma nova categoria.
        
        Args:
            blog_id: ID do blog
            nome: Nome da categoria
            
        Returns:
            Tuple[bool, Optional[str]]: (sucesso, mensagem_erro)
        """
        try:
            # Verificar se o blog existe
            blog = self.session.query(Blog).get(blog_id)
            if not blog:
                return False, "Blog não encontrado"
            
            # Verificar se já existe categoria com este nome no blog
            existing_categoria = self.session.query(Categoria).filter_by(
                blog_id=blog_id, nome=nome
            ).first()
            if existing_categoria:
                return False, f"Já existe uma categoria '{nome}' neste blog"
            
            # Verificar limite de categorias por blog
            total_categorias = self.session.query(Categoria).filter_by(blog_id=blog_id).count()
            if total_categorias >= self.MAX_CATEGORIAS_PER_BLOG:
                return False, f"Limite máximo de {self.MAX_CATEGORIAS_PER_BLOG} categorias por blog atingido"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Erro ao validar criação de categoria: {e}")
            return False, "Erro interno na validação"
    
    def validate_prompt_creation(self, categoria_id: int, text: str) -> Tuple[bool, Optional[str]]:
        """
        Valida se é possível criar um novo prompt.
        
        Args:
            categoria_id: ID da categoria
            text: Texto do prompt
            
        Returns:
            Tuple[bool, Optional[str]]: (sucesso, mensagem_erro)
        """
        try:
            # Verificar se a categoria existe
            categoria = self.session.query(Categoria).get(categoria_id)
            if not categoria:
                return False, "Categoria não encontrada"
            
            # Verificar se já existe prompt com este texto na categoria
            existing_prompt = self.session.query(Prompt).filter_by(
                categoria_id=categoria_id, text=text
            ).first()
            if existing_prompt:
                return False, "Já existe um prompt com este texto nesta categoria"
            
            # Verificar limite de prompts por categoria
            total_prompts = self.session.query(Prompt).filter_by(categoria_id=categoria_id).count()
            if total_prompts >= self.MAX_PROMPTS_PER_CATEGORIA:
                return False, f"Limite máximo de {self.MAX_PROMPTS_PER_CATEGORIA} prompts por categoria atingido"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Erro ao validar criação de prompt: {e}")
            return False, "Erro interno na validação"
    
    def validate_prompt_upload(self, categoria_id: int, file_content: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Valida upload de arquivo .txt com prompts.
        
        Args:
            categoria_id: ID da categoria
            file_content: Conteúdo do arquivo
            
        Returns:
            Tuple[bool, Optional[str], List[str]]: (sucesso, mensagem_erro, prompts_extraídos)
        """
        try:
            # Verificar se a categoria existe
            categoria = self.session.query(Categoria).get(categoria_id)
            if not categoria:
                return False, "Categoria não encontrada", []
            
            # Extrair prompts do arquivo (separados por linha)
            prompts = [line.strip() for line in file_content.split('\n') if line.strip()]
            
            if not prompts:
                return False, "Arquivo não contém prompts válidos", []
            
            if len(prompts) > self.MAX_PROMPTS_PER_CATEGORIA:
                return False, f"Arquivo contém {len(prompts)} prompts, máximo permitido é {self.MAX_PROMPTS_PER_CATEGORIA}", []
            
            # Verificar se algum prompt já existe
            existing_prompts = self.session.query(Prompt).filter_by(categoria_id=categoria_id).all()
            existing_texts = [p.text for p in existing_prompts]
            
            duplicates = [text for text in prompts if text in existing_texts]
            if duplicates:
                return False, f"Prompts duplicados encontrados: {', '.join(duplicates[:3])}", []
            
            return True, None, prompts
            
        except Exception as e:
            logger.error(f"Erro ao validar upload de prompts: {e}")
            return False, "Erro interno na validação", []
    
    def get_blog_stats(self, blog_id: int) -> Dict[str, int]:
        """
        Retorna estatísticas de um blog.
        
        Args:
            blog_id: ID do blog
            
        Returns:
            Dict[str, int]: Estatísticas do blog
        """
        try:
            categorias_count = self.session.query(Categoria).filter_by(blog_id=blog_id).count()
            prompts_count = self.session.query(Prompt).filter_by(blog_id=blog_id).count()
            
            return {
                "categorias_count": categorias_count,
                "prompts_count": prompts_count,
                "max_categorias": self.MAX_CATEGORIAS_PER_BLOG,
                "max_prompts_per_categoria": self.MAX_PROMPTS_PER_CATEGORIA
            }
            
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas do blog: {e}")
            return {}
    
    def get_system_stats(self) -> Dict[str, int]:
        """
        Retorna estatísticas gerais do sistema.
        
        Returns:
            Dict[str, int]: Estatísticas do sistema
        """
        try:
            total_blogs = self.session.query(Blog).count()
            total_categorias = self.session.query(Categoria).count()
            total_prompts = self.session.query(Prompt).count()
            
            return {
                "total_blogs": total_blogs,
                "total_categorias": total_categorias,
                "total_prompts": total_prompts,
                "max_blogs": self.MAX_BLOGS,
                "max_categorias_per_blog": self.MAX_CATEGORIAS_PER_BLOG,
                "max_prompts_per_categoria": self.MAX_PROMPTS_PER_CATEGORIA
            }
            
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas do sistema: {e}")
            return {} 