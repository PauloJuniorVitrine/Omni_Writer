#!/usr/bin/env python3
"""
Script de demonstração das funcionalidades de gerenciamento de blogs.
Mostra como criar blogs, categorias e prompts com as validações implementadas.
"""
import os
import sys
import logging
from pathlib import Path

# Adicionar o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from omni_writer.domain.orm_models import Base, Blog, Categoria, Prompt
from omni_writer.domain.validation_service import ValidationService

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BlogManagementDemo:
    """Demonstração do sistema de gerenciamento de blogs."""
    
    def __init__(self, db_path="demo_blog.db"):
        """Inicializa a demonstração."""
        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        
    def run_demo(self):
        """Executa a demonstração completa."""
        logger.info("🚀 Iniciando demonstração do sistema de gerenciamento de blogs")
        
        session = self.Session()
        validation_service = ValidationService(session)
        
        try:
            # 1. Mostrar estatísticas iniciais
            self.show_system_stats(validation_service)
            
            # 2. Criar blogs de exemplo
            blogs = self.create_sample_blogs(session, validation_service)
            
            # 3. Criar categorias para cada blog
            categorias = self.create_sample_categorias(session, validation_service, blogs)
            
            # 4. Criar prompts para as categorias
            self.create_sample_prompts(session, validation_service, categorias)
            
            # 5. Demonstrar upload de arquivo .txt
            self.demonstrate_file_upload(session, validation_service, categorias[0])
            
            # 6. Mostrar estatísticas finais
            self.show_system_stats(validation_service)
            
            # 7. Demonstrar validações de limite
            self.demonstrate_limit_validations(session, validation_service)
            
            logger.info("✅ Demonstração concluída com sucesso!")
            
        except Exception as e:
            logger.error(f"❌ Erro durante a demonstração: {e}")
            session.rollback()
        finally:
            session.close()
    
    def show_system_stats(self, validation_service):
        """Mostra estatísticas do sistema."""
        logger.info("📊 Estatísticas do Sistema:")
        stats = validation_service.get_system_stats()
        for key, value in stats.items():
            logger.info(f"  {key}: {value}")
        print()
    
    def create_sample_blogs(self, session, validation_service):
        """Cria blogs de exemplo."""
        logger.info("📝 Criando blogs de exemplo...")
        
        sample_blogs = [
            {"nome": "Blog de Tecnologia", "desc": "Artigos sobre inovação e tecnologia"},
            {"nome": "Blog de Finanças", "desc": "Dicas de investimento e economia"},
            {"nome": "Blog de Saúde", "desc": "Bem-estar e qualidade de vida"},
            {"nome": "Blog de Viagens", "desc": "Destinos e experiências de viagem"},
            {"nome": "Blog de Culinária", "desc": "Receitas e técnicas culinárias"}
        ]
        
        created_blogs = []
        for blog_data in sample_blogs:
            is_valid, error_message = validation_service.validate_blog_creation(blog_data["nome"])
            
            if is_valid:
                blog = Blog(nome=blog_data["nome"], desc=blog_data["desc"])
                session.add(blog)
                session.commit()
                created_blogs.append(blog)
                logger.info(f"  ✅ Blog criado: {blog.nome}")
            else:
                logger.warning(f"  ⚠️ Não foi possível criar blog '{blog_data['nome']}': {error_message}")
        
        print()
        return created_blogs
    
    def create_sample_categorias(self, session, validation_service, blogs):
        """Cria categorias de exemplo para os blogs."""
        logger.info("📂 Criando categorias de exemplo...")
        
        sample_categorias = {
            "Blog de Tecnologia": [
                {"nome": "Inteligência Artificial", "desc": "IA e machine learning"},
                {"nome": "Desenvolvimento Web", "desc": "Frontend e backend"},
                {"nome": "Mobile", "desc": "Apps e desenvolvimento mobile"},
                {"nome": "Cloud Computing", "desc": "Serviços em nuvem"},
                {"nome": "Cybersecurity", "desc": "Segurança digital"},
                {"nome": "IoT", "desc": "Internet das Coisas"},
                {"nome": "Blockchain", "desc": "Criptomoedas e DLT"}
            ],
            "Blog de Finanças": [
                {"nome": "Investimentos", "desc": "Dicas de investimento"},
                {"nome": "Economia", "desc": "Análise econômica"},
                {"nome": "Pessoal", "desc": "Finanças pessoais"},
                {"nome": "Empresarial", "desc": "Finanças corporativas"},
                {"nome": "Impostos", "desc": "Legislação tributária"},
                {"nome": "Aposentadoria", "desc": "Planejamento previdenciário"},
                {"nome": "Seguros", "desc": "Proteção financeira"}
            ]
        }
        
        created_categorias = []
        for blog in blogs[:2]:  # Apenas para os 2 primeiros blogs
            if blog.nome in sample_categorias:
                for cat_data in sample_categorias[blog.nome]:
                    is_valid, error_message = validation_service.validate_categoria_creation(blog.id, cat_data["nome"])
                    
                    if is_valid:
                        categoria = Categoria(
                            nome=cat_data["nome"],
                            desc=cat_data["desc"],
                            blog_id=blog.id,
                            ia_provider="openai"
                        )
                        session.add(categoria)
                        session.commit()
                        created_categorias.append(categoria)
                        logger.info(f"  ✅ Categoria criada: {categoria.nome} (Blog: {blog.nome})")
                    else:
                        logger.warning(f"  ⚠️ Não foi possível criar categoria '{cat_data['nome']}': {error_message}")
        
        print()
        return created_categorias
    
    def create_sample_prompts(self, session, validation_service, categorias):
        """Cria prompts de exemplo para as categorias."""
        logger.info("💬 Criando prompts de exemplo...")
        
        sample_prompts = {
            "Inteligência Artificial": [
                "Como a IA está transformando o mercado de trabalho",
                "Machine Learning para iniciantes: conceitos básicos",
                "ChatGPT e o futuro da comunicação"
            ],
            "Investimentos": [
                "Como começar a investir com pouco dinheiro",
                "Diferenças entre renda fixa e variável",
                "Planejamento financeiro para aposentadoria"
            ]
        }
        
        for categoria in categorias:
            if categoria.nome in sample_prompts:
                for prompt_text in sample_prompts[categoria.nome]:
                    is_valid, error_message = validation_service.validate_prompt_creation(categoria.id, prompt_text)
                    
                    if is_valid:
                        prompt = Prompt(
                            text=prompt_text,
                            nome=f"Prompt {len(categoria.prompts) + 1}",
                            categoria_id=categoria.id,
                            blog_id=categoria.blog_id
                        )
                        session.add(prompt)
                        session.commit()
                        logger.info(f"  ✅ Prompt criado: {prompt_text[:50]}...")
                    else:
                        logger.warning(f"  ⚠️ Não foi possível criar prompt: {error_message}")
        
        print()
    
    def demonstrate_file_upload(self, session, validation_service, categoria):
        """Demonstra upload de arquivo .txt com prompts."""
        logger.info("📁 Demonstrando upload de arquivo .txt...")
        
        # Simular conteúdo de arquivo .txt
        file_content = """Como otimizar seu portfólio de investimentos
Estratégias de diversificação para reduzir riscos
Análise fundamentalista vs análise técnica"""
        
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria.id, file_content)
        
        if is_valid:
            logger.info(f"  ✅ Arquivo válido! {len(prompts)} prompts extraídos:")
            for i, prompt_text in enumerate(prompts, 1):
                logger.info(f"    {i}. {prompt_text}")
                
                # Criar o prompt no banco
                prompt = Prompt(
                    text=prompt_text,
                    nome=f"Upload Prompt {i}",
                    categoria_id=categoria.id,
                    blog_id=categoria.blog_id,
                    file_path="prompts_upload.txt"
                )
                session.add(prompt)
            
            session.commit()
            logger.info("  ✅ Prompts do arquivo criados no banco!")
        else:
            logger.warning(f"  ⚠️ Arquivo inválido: {error_message}")
        
        print()
    
    def demonstrate_limit_validations(self, session, validation_service):
        """Demonstra as validações de limite."""
        logger.info("🔒 Demonstrando validações de limite...")
        
        # Tentar criar um blog com nome duplicado
        logger.info("  Testando criação de blog com nome duplicado...")
        is_valid, error_message = validation_service.validate_blog_creation("Blog de Tecnologia")
        if not is_valid:
            logger.info(f"    ✅ Validação funcionou: {error_message}")
        
        # Tentar criar categoria com nome duplicado
        logger.info("  Testando criação de categoria com nome duplicado...")
        blog = session.query(Blog).filter_by(nome="Blog de Tecnologia").first()
        if blog:
            is_valid, error_message = validation_service.validate_categoria_creation(blog.id, "Inteligência Artificial")
            if not is_valid:
                logger.info(f"    ✅ Validação funcionou: {error_message}")
        
        # Tentar criar prompt com texto duplicado
        logger.info("  Testando criação de prompt com texto duplicado...")
        categoria = session.query(Categoria).filter_by(nome="Inteligência Artificial").first()
        if categoria:
            is_valid, error_message = validation_service.validate_prompt_creation(
                categoria.id, "Como a IA está transformando o mercado de trabalho"
            )
            if not is_valid:
                logger.info(f"    ✅ Validação funcionou: {error_message}")
        
        print()
    
    def cleanup(self):
        """Remove o arquivo de banco de demonstração."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            logger.info(f"🧹 Arquivo de demonstração removido: {self.db_path}")


def main():
    """Função principal."""
    demo = BlogManagementDemo()
    
    try:
        demo.run_demo()
    except KeyboardInterrupt:
        logger.info("⏹️ Demonstração interrompida pelo usuário")
    except Exception as e:
        logger.error(f"❌ Erro inesperado: {e}")
    finally:
        # Opcional: remover arquivo de demonstração
        # demo.cleanup()
        pass


if __name__ == "__main__":
    main() 