import os
import json
import tempfile
import shutil
import pytest
from app.app_factory import create_app

def test_save_and_load_blogs():
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, 'blogs.json')
    blogs = [
        {'id': 1, 'nome': 'Blog Teste', 'desc': 'Desc'},
        {'id': 2, 'nome': 'Outro', 'desc': ''}
    ]
    # Substituir caminho do arquivo temporariamente
    old_file = create_app.BLOGS_FILE
    create_app.BLOGS_FILE = temp_file
    create_app.save_blogs(blogs)
    loaded = create_app.load_blogs()
    assert loaded == blogs
    create_app.BLOGS_FILE = old_file
    shutil.rmtree(temp_dir)

def test_save_and_load_prompts():
    temp_dir = tempfile.mkdtemp()
    blog_id = 99
    temp_prompts_dir = os.path.join(temp_dir, 'prompts')
    os.makedirs(temp_prompts_dir)
    old_dir = create_app.PROMPTS_DIR
    create_app.PROMPTS_DIR = temp_prompts_dir
    prompts = [
        {'id': 1, 'text': 'Prompt 1'},
        {'id': 2, 'text': 'Prompt 2'}
    ]
    create_app.save_prompts(blog_id, prompts)
    loaded = create_app.load_prompts(blog_id)
    assert loaded == prompts
    create_app.PROMPTS_DIR = old_dir
    shutil.rmtree(temp_dir) 