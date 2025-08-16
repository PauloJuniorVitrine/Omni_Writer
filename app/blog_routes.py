"""
Module for blog and prompt management routes (API REST).
Handles routes: /api/blogs, /api/blogs/<id>, /api/blogs/<id>/prompts, etc.
"""
from flask import Blueprint, request, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from omni_writer.domain.models import Base, Blog, Prompt, Categoria, Cluster
from omni_writer.domain.validation_service import ValidationService
import os
import logging

blog_routes_bp = Blueprint('blog_routes', __name__)
logger = logging.getLogger("app.blog_routes")

# As rotas serão migradas aqui incrementalmente a partir de main.py 

DB_PATH = os.getenv('BLOG_DB_PATH', 'blog.db')
engine = create_engine(f'sqlite:///{DB_PATH}', connect_args={"check_same_thread": False})
Session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(engine)

@blog_routes_bp.route('/api/blogs', methods=['GET'])
def api_list_blogs():
    session = Session()
    try:
        blogs = session.query(Blog).all()
        result = []
        for b in blogs:
            # Incluir estatísticas de cada blog
            validation_service = ValidationService(session)
            stats = validation_service.get_blog_stats(b.id)
            result.append({
                "id": b.id, 
                "nome": b.nome, 
                "desc": b.desc,
                "stats": stats
            })
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Erro ao listar blogs: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs', methods=['POST'])
def api_create_blog():
    session = Session()
    try:
        data = request.get_json() or request.form
        nome = data.get('nome')
        desc = data.get('desc')
        
        if not nome:
            return jsonify({"error": "Nome do blog é obrigatório"}), 400
        
        # Validar criação do blog
        validation_service = ValidationService(session)
        is_valid, error_message = validation_service.validate_blog_creation(nome)
        
        if not is_valid:
            return jsonify({"error": error_message}), 400
        
        blog = Blog(nome=nome, desc=desc)
        session.add(blog)
        session.commit()
        
        result = {"id": blog.id, "nome": blog.nome, "desc": blog.desc}
        logger.info(f"Blog criado com sucesso: {blog.nome}")
        return jsonify(result), 201
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao criar blog: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>', methods=['DELETE'])
def api_delete_blog(blog_id):
    """
    Exclui um blog apenas se não houver prompts vinculados. Caso contrário, retorna erro 409.
    """
    session = Session()
    try:
        blog = session.query(Blog).get(blog_id)
        if not blog:
            return jsonify({"error": "Blog não encontrado"}), 404
        
        if blog.prompts and len(blog.prompts) > 0:
            return jsonify({"error": "Não é possível excluir: existem prompts vinculados."}), 409
        
        session.delete(blog)
        session.commit()
        logger.info(f"Blog excluído: {blog.nome}")
        return '', 204
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao excluir blog: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>/prompts', methods=['GET'])
def api_list_prompts(blog_id):
    session = Session()
    try:
        prompts = session.query(Prompt).filter_by(blog_id=blog_id).all()
        result = [{"id": p.id, "text": p.text, "nome": p.nome} for p in prompts]
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Erro ao listar prompts: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>/prompts', methods=['POST'])
def api_add_prompt(blog_id):
    session = Session()
    try:
        data = request.get_json() or request.form
        text = data.get('text')
        
        if not text:
            return jsonify({"error": "Texto do prompt é obrigatório"}), 400
        
        # Para compatibilidade, criar prompt na primeira categoria do blog
        categoria = session.query(Categoria).filter_by(blog_id=blog_id).first()
        if not categoria:
            return jsonify({"error": "Blog deve ter pelo menos uma categoria para adicionar prompts"}), 400
        
        # Validar criação do prompt
        validation_service = ValidationService(session)
        is_valid, error_message = validation_service.validate_prompt_creation(categoria.id, text)
        
        if not is_valid:
            return jsonify({"error": error_message}), 400
        
        prompt = Prompt(
            text=text,
            categoria_id=categoria.id,
            blog_id=blog_id
        )
        session.add(prompt)
        session.commit()
        
        result = {"id": prompt.id, "text": prompt.text}
        logger.info(f"Prompt adicionado ao blog {blog_id}")
        return jsonify(result), 201
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao adicionar prompt: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>/prompts/<int:prompt_id>', methods=['DELETE'])
def api_delete_prompt(blog_id, prompt_id):
    session = Session()
    try:
        prompt = session.query(Prompt).filter_by(id=prompt_id, blog_id=blog_id).first()
        if not prompt:
            return jsonify({"error": "Prompt não encontrado"}), 404
        
        session.delete(prompt)
        session.commit()
        logger.info(f"Prompt excluído: {prompt_id}")
        return '', 204
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao excluir prompt: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>', methods=['PUT'])
def api_update_blog(blog_id):
    """
    Atualiza os dados de um blog existente.
    """
    session = Session()
    try:
        data = request.get_json() or request.form
        nome = data.get('nome')
        desc = data.get('desc')
        if not nome:
            return jsonify({"error": "Nome do blog é obrigatório"}), 400
        blog = session.query(Blog).get(blog_id)
        if not blog:
            return jsonify({"error": "Blog não encontrado"}), 404
        blog.nome = nome
        blog.desc = desc
        session.commit()
        result = {"id": blog.id, "nome": blog.nome, "desc": blog.desc}
        logger.info(f"Blog atualizado: {blog.nome}")
        return jsonify(result), 200
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao atualizar blog: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>/categorias', methods=['GET'])
def api_list_categorias(blog_id):
    session = Session()
    try:
        categorias = session.query(Categoria).filter_by(blog_id=blog_id).all()
        result = []
        for c in categorias:
            # Incluir contagem de prompts por categoria
            prompts_count = session.query(Prompt).filter_by(categoria_id=c.id).count()
            result.append({
                "id": c.id, 
                "nome": c.nome,
                "desc": c.desc,
                "prompt_path": c.prompt_path,
                "ia_provider": c.ia_provider,
                "prompts_count": prompts_count
            })
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Erro ao listar categorias: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/blogs/<int:blog_id>/categorias', methods=['POST'])
def api_create_categoria(blog_id):
    session = Session()
    try:
        data = request.get_json() or request.form
        nome = data.get('nome')
        desc = data.get('desc')
        prompt_path = data.get('prompt_path')
        ia_provider = data.get('ia_provider')
        
        if not nome:
            return jsonify({"error": "Nome da categoria é obrigatório"}), 400
        
        # Validar criação da categoria
        validation_service = ValidationService(session)
        is_valid, error_message = validation_service.validate_categoria_creation(blog_id, nome)
        
        if not is_valid:
            return jsonify({"error": error_message}), 400
        
        categoria = Categoria(
            nome=nome, 
            desc=desc,
            blog_id=blog_id, 
            prompt_path=prompt_path, 
            ia_provider=ia_provider
        )
        session.add(categoria)
        session.commit()
        
        result = {
            "id": categoria.id, 
            "nome": categoria.nome,
            "desc": categoria.desc,
            "prompt_path": categoria.prompt_path, 
            "ia_provider": categoria.ia_provider
        }
        logger.info(f"Categoria criada: {categoria.nome} no blog {blog_id}")
        return jsonify(result), 201
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao criar categoria: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>/prompts', methods=['GET'])
def api_list_prompts_by_categoria(categoria_id):
    session = Session()
    try:
        prompts = session.query(Prompt).filter_by(categoria_id=categoria_id).all()
        result = [{"id": p.id, "text": p.text, "nome": p.nome, "file_path": p.file_path} for p in prompts]
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Erro ao listar prompts: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>/prompts', methods=['POST'])
def api_add_prompt_to_categoria(categoria_id):
    session = Session()
    try:
        data = request.get_json() or request.form
        text = data.get('text')
        nome = data.get('nome')
        
        if not text:
            return jsonify({"error": "Texto do prompt é obrigatório"}), 400
        
        # Validar criação do prompt
        validation_service = ValidationService(session)
        is_valid, error_message = validation_service.validate_prompt_creation(categoria_id, text)
        
        if not is_valid:
            return jsonify({"error": error_message}), 400
        
        # Obter blog_id da categoria
        categoria = session.query(Categoria).get(categoria_id)
        if not categoria:
            return jsonify({"error": "Categoria não encontrada"}), 404
        
        prompt = Prompt(
            text=text, 
            nome=nome,
            categoria_id=categoria_id,
            blog_id=categoria.blog_id
        )
        session.add(prompt)
        session.commit()
        
        result = {"id": prompt.id, "text": prompt.text, "nome": prompt.nome}
        logger.info(f"Prompt adicionado à categoria {categoria_id}")
        return jsonify(result), 201
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao adicionar prompt: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>/prompts/upload', methods=['POST'])
def api_upload_prompts_file(categoria_id):
    """
    Upload de arquivo .txt com prompts para uma categoria.
    """
    session = Session()
    try:
        if 'file' not in request.files:
            return jsonify({"error": "Nenhum arquivo enviado"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Nenhum arquivo selecionado"}), 400
        
        if not file.filename.endswith('.txt'):
            return jsonify({"error": "Apenas arquivos .txt são permitidos"}), 400
        
        # Ler conteúdo do arquivo
        file_content = file.read().decode('utf-8')
        
        # Validar upload
        validation_service = ValidationService(session)
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria_id, file_content)
        
        if not is_valid:
            return jsonify({"error": error_message}), 400
        
        # Obter categoria e blog_id
        categoria = session.query(Categoria).get(categoria_id)
        if not categoria:
            return jsonify({"error": "Categoria não encontrada"}), 404
        
        # Salvar prompts
        saved_prompts = []
        for i, text in enumerate(prompts, 1):
            prompt = Prompt(
                text=text,
                nome=f"Prompt {i}",
                categoria_id=categoria_id,
                blog_id=categoria.blog_id,
                file_path=file.filename
            )
            session.add(prompt)
            saved_prompts.append({
                "id": prompt.id,
                "text": prompt.text,
                "nome": prompt.nome,
                "file_path": prompt.file_path
            })
        
        session.commit()
        logger.info(f"{len(prompts)} prompts carregados da categoria {categoria_id}")
        
        return jsonify({
            "message": f"{len(prompts)} prompts carregados com sucesso",
            "prompts": saved_prompts
        }), 201
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao fazer upload de prompts: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/prompts/<int:prompt_id>', methods=['DELETE'])
def api_delete_prompt(prompt_id):
    session = Session()
    try:
        prompt = session.query(Prompt).get(prompt_id)
        if not prompt:
            return jsonify({"error": "Prompt não encontrado"}), 404
        
        session.delete(prompt)
        session.commit()
        logger.info(f"Prompt excluído: {prompt_id}")
        return '', 204
        
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao excluir prompt: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/stats', methods=['GET'])
def api_get_system_stats():
    """
    Retorna estatísticas gerais do sistema.
    """
    session = Session()
    try:
        validation_service = ValidationService(session)
        stats = validation_service.get_system_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>/clusters', methods=['GET'])
def api_list_clusters(categoria_id):
    session = Session()
    try:
        clusters = session.query(Cluster).filter_by(categoria_id=categoria_id).all()
        result = [{"id": cl.id, "nome": cl.nome, "palavra_chave": cl.palavra_chave} for cl in clusters]
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Erro ao listar clusters: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>/clusters', methods=['POST'])
def api_create_cluster(categoria_id):
    session = Session()
    try:
        data = request.get_json() or request.form
        nome = data.get('nome')
        palavra_chave = data.get('palavra_chave')
        if not nome or not palavra_chave:
            return jsonify({"error": "Nome e palavra-chave são obrigatórios"}), 400
        cluster = Cluster(nome=nome, palavra_chave=palavra_chave, categoria_id=categoria_id)
        session.add(cluster)
        session.commit()
        result = {"id": cluster.id, "nome": cluster.nome, "palavra_chave": cluster.palavra_chave}
        logger.info(f"Cluster criado: {cluster.nome} na categoria {categoria_id}")
        return jsonify(result), 201
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao criar cluster: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>', methods=['DELETE'])
def api_delete_categoria(categoria_id):
    session = Session()
    try:
        categoria = session.query(Categoria).get(categoria_id)
        if not categoria:
            return jsonify({"error": "Categoria não encontrada"}), 404
        session.delete(categoria)
        session.commit()
        logger.info(f"Categoria excluída: {categoria_id}")
        return '', 204
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao excluir categoria: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/categorias/<int:categoria_id>', methods=['PUT'])
def api_update_categoria(categoria_id):
    session = Session()
    try:
        data = request.get_json() or request.form
        nome = data.get('nome')
        prompt_path = data.get('prompt_path')
        ia_provider = data.get('ia_provider')
        categoria = session.query(Categoria).get(categoria_id)
        if not categoria:
            return jsonify({"error": "Categoria não encontrada"}), 404
        if nome:
            categoria.nome = nome
        if prompt_path:
            categoria.prompt_path = prompt_path
        if ia_provider:
            categoria.ia_provider = ia_provider
        session.commit()
        result = {"id": categoria.id, "nome": categoria.nome, "prompt_path": categoria.prompt_path, "ia_provider": categoria.ia_provider}
        logger.info(f"Categoria atualizada: {categoria.nome}")
        return jsonify(result), 200
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao atualizar categoria: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close()

@blog_routes_bp.route('/api/clusters/<int:cluster_id>', methods=['DELETE'])
def api_delete_cluster(cluster_id):
    session = Session()
    try:
        cluster = session.query(Cluster).get(cluster_id)
        if not cluster:
            return jsonify({"error": "Cluster não encontrado"}), 404
        session.delete(cluster)
        session.commit()
        logger.info(f"Cluster excluído: {cluster_id}")
        return '', 204 
    except Exception as e:
        session.rollback()
        logger.error(f"Erro ao excluir cluster: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        session.close() 