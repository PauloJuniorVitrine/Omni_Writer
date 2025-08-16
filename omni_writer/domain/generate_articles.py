import os
import logging
import zipfile
from datetime import datetime
from omni_writer.domain.models import Blog, Categoria, Cluster
from shared.prompts.parser_prompt_base_artigos import PromptBaseArtigosParser
from omni_writer.domain.ia_providers import IAProvider, OpenAIProvider, GeminiProvider, ClaudeProvider

logger = logging.getLogger("domain.generate_articles")

class ArticleGenerator:
    """
    Gera 6 artigos para uma categoria, usando o prompt .txt associado.
    Salva os artigos em /output/{blog}/{categoria}/{semana}/artigo_X.txt
    """
    def __init__(self, session, output_dir="output"):
        self.session = session
        self.output_dir = output_dir

    def _get_provider(self, categoria):
        if categoria.ia_provider == 'gemini':
            return GeminiProvider()
        elif categoria.ia_provider == 'claude':
            return ClaudeProvider()
        # Default: OpenAI
        return OpenAIProvider()

    def generate_for_categoria(self, categoria_id: int, semana: str = None):
        categoria = self.session.query(Categoria).get(categoria_id)
        if not categoria or not categoria.prompt_path:
            logger.error(f"Categoria {categoria_id} não encontrada ou sem prompt_path.")
            raise ValueError("Categoria inválida ou sem prompt associado.")
        blog = categoria.blog
        clusters = categoria.clusters
        parser = PromptBaseArtigosParser(categoria.prompt_path)
        prompt_data = parser.parse()
        semana = semana or datetime.utcnow().strftime("%Y-%W")
        base_path = os.path.join(self.output_dir, blog.nome, categoria.nome, semana)
        os.makedirs(base_path, exist_ok=True)
        for idx in range(1, 7):
            artigo_path = os.path.join(base_path, f"artigo_{idx}.txt")
            artigo_content = self._generate_article_content(idx, prompt_data, clusters, categoria)
            with open(artigo_path, "w", encoding="utf-8") as f:
                f.write(artigo_content)
            logger.info(f"Artigo {idx} salvo em {artigo_path}")

    def _generate_article_content(self, idx, prompt_data, clusters, categoria=None):
        # Monta o prompt para o artigo idx conforme regras do prompt_data
        prompt = f"Artigo {idx} | Cluster: {clusters} | Dados: {prompt_data}"
        provider = self._get_provider(categoria) if categoria else OpenAIProvider()
        config = {"idx": idx, "prompt_data": prompt_data, "clusters": clusters}
        return provider.generate_article(prompt, config)

    def generate_for_all(self, semana: str = None):
        """
        Gera artigos para todas as categorias de todos os blogs cadastrados.
        """
        from omni_writer.domain.models import Blog, Categoria
        blogs = self.session.query(Blog).all()
        for blog in blogs:
            for categoria in blog.categorias:
                try:
                    self.generate_for_categoria(categoria.id, semana=semana)
                    logger.info(f"Artigos gerados para Blog '{blog.nome}', Categoria '{categoria.nome}'")
                except Exception as e:
                    logger.error(f"Erro ao gerar artigos para Blog '{blog.nome}', Categoria '{categoria.nome}': {e}")

    def generate_zip_entrega(self, semana: str = None):
        """
        Gera a estrutura de entrega: /output/{nicho}/{categoria}/artigo1.txt ... artigo6.txt
        Cria 7 categorias por nicho, gera 6 artigos por categoria, e zipa tudo em output/entrega.zip
        """
        from omni_writer.domain.models import Blog, Categoria
        blogs = self.session.query(Blog).all()
        semana = semana or datetime.utcnow().strftime("%Y-%W")
        base_output = os.path.join(self.output_dir, "entrega_tmp")
        if os.path.exists(base_output):
            import shutil
            shutil.rmtree(base_output)
        os.makedirs(base_output, exist_ok=True)
        for blog in blogs:
            nicho_path = os.path.join(base_output, blog.nome)
            os.makedirs(nicho_path, exist_ok=True)
            categorias = blog.categorias[:7]  # Garante 7 categorias
            for categoria in categorias:
                cat_path = os.path.join(nicho_path, categoria.nome)
                os.makedirs(cat_path, exist_ok=True)
                parser = PromptBaseArtigosParser(categoria.prompt_path)
                prompt_data = parser.parse()
                clusters = categoria.clusters
                for idx in range(1, 7):
                    artigo_path = os.path.join(cat_path, f"artigo{idx}.txt")
                    artigo_content = self._generate_article_content(idx, prompt_data, clusters, categoria)
                    with open(artigo_path, "w", encoding="utf-8") as f:
                        f.write(artigo_content)
                    logger.info(f"Artigo {idx} salvo em {artigo_path}")
        # Zipar estrutura
        zip_path = os.path.join(self.output_dir, "entrega.zip")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(base_output):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, base_output)
                    zipf.write(abs_path, rel_path)
        logger.info(f"ZIP de entrega gerado em {zip_path}")
        return zip_path 