import os
import pytest
from unittest.mock import MagicMock
from omni_writer.domain.generate_articles import ArticleGenerator

@pytest.fixture
def mock_session(tmp_path):
    # Mock de Blog, Categoria e Cluster
    class Blog:
        nome = "BlogTeste"
    class Categoria:
        nome = "CategoriaTeste"
        prompt_path = str(tmp_path / "prompt.txt")
        blog = Blog()
        clusters = []
    session = MagicMock()
    session.query().get.return_value = Categoria()
    # Criar prompt.txt fictício
    with open(Categoria.prompt_path, "w", encoding="utf-8") as f:
        f.write("[NICHO]: Teste\n[CATEGORIA]: Teste\n[CLUSTER DE CONTEÚDO]: Teste\n[PERFIL DO CLIENTE / PERSONA]: Teste\n[PALAVRA-CHAVE PRINCIPAL DO CLUSTER]: Teste\n[ESTILO DE REDAÇÃO]: Teste\n")
    return session

def test_generate_for_categoria_creates_files(tmp_path, mock_session):
    generator = ArticleGenerator(mock_session, output_dir=str(tmp_path))
    generator.generate_for_categoria(1, semana="2024-30")
    base_path = tmp_path / "BlogTeste" / "CategoriaTeste" / "2024-30"
    for idx in range(1, 7):
        artigo_path = base_path / f"artigo_{idx}.txt"
        assert artigo_path.exists()
        content = artigo_path.read_text(encoding="utf-8")
        assert f"Artigo {idx}" in content 

def test_generate_for_all_creates_files(tmp_path):
    # Mock de múltiplos blogs e categorias
    class Blog:
        def __init__(self, nome, categorias):
            self.nome = nome
            self.categorias = categorias
    class Categoria:
        def __init__(self, nome, prompt_path, blog):
            self.nome = nome
            self.prompt_path = prompt_path
            self.blog = blog
            self.clusters = []
            blog.categorias.append(self)
    blogs = []
    for bidx in range(2):
        blog = Blog(f"Blog{bidx}", [])
        blogs.append(blog)
        for cidx in range(2):
            prompt_path = str(tmp_path / f"prompt_{bidx}_{cidx}.txt")
            with open(prompt_path, "w", encoding="utf-8") as f:
                f.write("[NICHO]: Teste\n[CATEGORIA]: Teste\n[CLUSTER DE CONTEÚDO]: Teste\n[PERFIL DO CLIENTE / PERSONA]: Teste\n[PALAVRA-CHAVE PRINCIPAL DO CLUSTER]: Teste\n[ESTILO DE REDAÇÃO]: Teste\n")
            Categoria(f"Categoria{cidx}", prompt_path, blog)
    session = MagicMock()
    session.query().all.return_value = blogs
    generator = ArticleGenerator(session, output_dir=str(tmp_path))
    generator.generate_for_all(semana="2024-30")
    for bidx in range(2):
        for cidx in range(2):
            base_path = tmp_path / f"Blog{bidx}" / f"Categoria{cidx}" / "2024-30"
            for idx in range(1, 7):
                artigo_path = base_path / f"artigo_{idx}.txt"
                assert artigo_path.exists() 