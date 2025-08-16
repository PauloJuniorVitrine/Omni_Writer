"""
Testes de integração para validação da separação de modelos.

Prompt: Separação de Modelos - IMP-004
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:10:00Z
Tracing ID: ENTERPRISE_20250127_004
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Testando imports do barrel module
from omni_writer.domain.models import (
    # Data models
    PromptInput,
    ArticleOutput,
    GenerationConfig,
    # ORM models
    Base,
    Blog,
    Prompt,
    Categoria,
    Cluster,
)


class TestModelsIntegration:
    """Testes de integração para validação da separação de modelos."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.session.close()
        self.engine.dispose()
    
    def test_barrel_module_imports(self):
        """Testa se o barrel module está exportando corretamente todos os modelos."""
        # Verificar se todos os modelos estão disponíveis
        assert PromptInput is not None
        assert ArticleOutput is not None
        assert GenerationConfig is not None
        assert Base is not None
        assert Blog is not None
        assert Prompt is not None
        assert Categoria is not None
        assert Cluster is not None
    
    def test_data_models_independence(self):
        """Testa se data models funcionam independentemente dos ORM models."""
        # Criar data models sem depender de ORM
        prompt_input = PromptInput(text="Como criar um blog profissional", index=0)
        article_output = ArticleOutput(
            content="Conteúdo do artigo",
            filename="artigo.txt",
            metadata={"model": "openai"}
        )
        generation_config = GenerationConfig(
            api_key="test-api-key-123456789",
            model_type="openai",
            prompts=[prompt_input],
            temperature=0.7,
            max_tokens=4096,
            language="pt-BR"
        )
        
        # Validar que funcionam corretamente
        assert prompt_input.text == "Como criar um blog profissional"
        assert article_output.content == "Conteúdo do artigo"
        assert generation_config.model_type == "openai"
    
    def test_orm_models_independence(self):
        """Testa se ORM models funcionam independentemente dos data models."""
        # Criar ORM models sem depender de data models
        blog = Blog(nome="Blog Teste", desc="Descrição do blog")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(
            nome="Categoria Teste",
            desc="Descrição da categoria",
            blog_id=blog.id,
            prompt_path="/path/to/prompt.txt",
            ia_provider="openai"
        )
        self.session.add(categoria)
        self.session.commit()
        
        # Validar que funcionam corretamente
        assert blog.nome == "Blog Teste"
        assert categoria.nome == "Categoria Teste"
        assert categoria.blog_id == blog.id
    
    def test_models_separation_validation(self):
        """Testa se a separação está funcionando corretamente."""
        # Data models não devem ter dependências de SQLAlchemy
        from omni_writer.domain.data_models import PromptInput as DataPromptInput
        
        # ORM models devem ter dependências de SQLAlchemy
        from omni_writer.domain.orm_models import Blog as ORMBlog
        
        # Verificar que são diferentes
        assert DataPromptInput != ORMBlog
        
        # Verificar que data models não têm atributos SQLAlchemy
        prompt_input = DataPromptInput(text="Teste", index=0)
        assert not hasattr(prompt_input, '__tablename__')
        assert not hasattr(prompt_input, '__table_args__')
        
        # Verificar que ORM models têm atributos SQLAlchemy
        blog = ORMBlog(nome="Teste")
        assert hasattr(blog, '__tablename__')
        assert hasattr(blog, '__table_args__')
    
    def test_clean_architecture_compliance(self):
        """Testa se a separação está em conformidade com Clean Architecture."""
        # Domain layer não deve ter dependências externas
        from omni_writer.domain.data_models import PromptInput
        
        # Verificar que data models são puros (sem dependências de infraestrutura)
        prompt_input = PromptInput(text="Teste", index=0)
        
        # Verificar que podem ser serializados sem dependências externas
        data_dict = prompt_input.to_dict()
        assert isinstance(data_dict, dict)
        assert 'text' in data_dict
        assert 'index' in data_dict
    
    def test_models_consistency(self):
        """Testa consistência entre os modelos separados."""
        # Criar data model
        prompt_input = PromptInput(text="Como criar um blog profissional", index=0)
        
        # Criar ORM model correspondente
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text=prompt_input.text,
            categoria_id=categoria.id,
            blog_id=blog.id
        )
        self.session.add(prompt)
        self.session.commit()
        
        # Validar que os dados são consistentes
        assert prompt.text == prompt_input.text
        assert prompt.categoria_id == categoria.id
        assert prompt.blog_id == blog.id
    
    def test_models_imports_workflow(self):
        """Testa o fluxo de trabalho com imports separados."""
        # Simular uso real do sistema
        from omni_writer.domain.data_models import GenerationConfig, PromptInput
        from omni_writer.domain.orm_models import Blog, Categoria, Prompt
        
        # 1. Criar configuração de geração (data model)
        prompts = [PromptInput(text="Como criar um blog profissional", index=0)]
        config = GenerationConfig(
            api_key="test-api-key-123456789",
            model_type="openai",
            prompts=prompts,
            temperature=0.7,
            max_tokens=4096,
            language="pt-BR"
        )
        
        # 2. Criar entidades no banco (ORM models)
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        # 3. Usar dados do data model para criar ORM model
        for prompt_input in config.prompts:
            prompt = Prompt(
                text=prompt_input.text,
                categoria_id=categoria.id,
                blog_id=blog.id
            )
            self.session.add(prompt)
        
        self.session.commit()
        
        # 4. Validar que tudo funcionou
        assert len(config.prompts) == 1
        assert config.prompts[0].text == "Como criar um blog profissional"
        
        saved_prompts = self.session.query(Prompt).filter_by(blog_id=blog.id).all()
        assert len(saved_prompts) == 1
        assert saved_prompts[0].text == "Como criar um blog profissional" 