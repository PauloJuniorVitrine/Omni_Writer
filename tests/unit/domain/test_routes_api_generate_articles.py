import pytest
from app import app as flask_app

def test_api_generate_articles_success(client, mocker):
    mocker.patch('app.blog_routes.engine')
    mocker.patch('omni_writer.domain.generate_articles.ArticleGenerator.generate_for_all', return_value=None)
    resp = client.post('/api/generate-articles')
    assert resp.status_code == 200
    assert resp.json['status'] == 'ok'

def test_api_generate_articles_exception(client, mocker):
    mocker.patch('app.blog_routes.engine')
    mocker.patch('omni_writer.domain.generate_articles.ArticleGenerator.generate_for_all', side_effect=Exception('Erro simulado'))
    resp = client.post('/api/generate-articles')
    assert resp.status_code == 500
    assert resp.json['status'] == 'erro' 