import pytest
from app import app as flask_app

def test_api_entrega_zip_success(client, mocker):
    mocker.patch('app.blog_routes.engine')
    mocker.patch('omni_writer.domain.generate_articles.ArticleGenerator.generate_zip_entrega', return_value='output/entrega.zip')
    resp = client.post('/api/entrega-zip')
    assert resp.status_code == 200
    assert resp.headers['Content-Disposition'].startswith('attachment;')

def test_api_entrega_zip_exception(client, mocker):
    mocker.patch('app.blog_routes.engine')
    mocker.patch('omni_writer.domain.generate_articles.ArticleGenerator.generate_zip_entrega', side_effect=Exception('Erro simulado'))
    resp = client.post('/api/entrega-zip')
    assert resp.status_code == 500
    assert resp.json['status'] == 'erro' 