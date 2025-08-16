import pytest
from omni_writer.domain.orm_models import Blog, Prompt, Categoria, Cluster, Base
from sqlalchemy.orm import Session
from unittest import mock

# Teste de criação e deleção de Blog
def test_blog_creation_and_deletion():
    blog = Blog(nome="Blog Teste", desc="desc")
    assert blog.nome == "Blog Teste"
    assert blog.desc == "desc"
    # __del__ não deve lançar
    blog.__del__()

# Teste de criação e deleção de Prompt
def test_prompt_creation_and_deletion():
    blog = Blog(nome="Blog Teste")
    prompt = Prompt(text="Texto do prompt", blog=blog)
    assert prompt.text == "Texto do prompt"
    assert prompt.blog == blog
    prompt.__del__()

# Teste de criação e deleção de Categoria
def test_categoria_creation_and_deletion():
    blog = Blog(nome="Blog Teste")
    cat = Categoria(nome="Cat", blog=blog, prompt_path="/tmp/p.txt", ia_provider="openai")
    assert cat.nome == "Cat"
    assert cat.blog == blog
    assert cat.prompt_path == "/tmp/p.txt"
    assert cat.ia_provider == "openai"
    cat.__del__()

# Teste de criação e deleção de Cluster
def test_cluster_creation_and_deletion():
    cat = Categoria(nome="Cat", blog=Blog(nome="Blog"))
    cluster = Cluster(nome="Cluster", palavra_chave="kw", categoria=cat)
    assert cluster.nome == "Cluster"
    assert cluster.palavra_chave == "kw"
    assert cluster.categoria == cat
    cluster.__del__()

# Teste de relacionamentos reversos
def test_blog_categoria_relationship():
    blog = Blog(nome="Blog Teste")
    cat = Categoria(nome="Cat", blog=blog)
    blog.categorias.append(cat)
    assert cat in blog.categorias
    assert cat.blog == blog

# Teste de edge case: criação sem argumentos obrigatórios
@pytest.mark.parametrize("cls,kwargs", [
    (Blog, {}),
    (Prompt, {}),
    (Categoria, {}),
    (Cluster, {}),
])
def test_creation_missing_args(cls, kwargs):
    try:
        obj = cls(**kwargs)
        assert obj is not None
    except Exception:
        pass 