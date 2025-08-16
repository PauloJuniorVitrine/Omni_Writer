from flask import Blueprint, request, jsonify
from feedback.models import FeedbackEntry
from feedback.storage import save_feedback, get_feedback_by_article

feedback_bp = Blueprint('feedback', __name__)

@feedback_bp.route('/feedback', methods=['POST'])
def submit_feedback():
    """
    Recebe e armazena feedback do usuário para um artigo.
    """
    data = request.json
    required = ['id_artigo', 'prompt', 'avaliacao']
    if not all(k in data for k in required):
        return jsonify({'error': 'Campos obrigatórios ausentes'}), 400
    if not isinstance(data['avaliacao'], int) or data['avaliacao'] not in (0, 1):
        return jsonify({'error': 'Avaliação deve ser 0 ou 1'}), 400
    comentario = data.get('comentario')
    if comentario and not isinstance(comentario, str):
        return jsonify({'error': 'Comentário inválido'}), 400
    entry = FeedbackEntry(
        id_artigo=data['id_artigo'],
        prompt=data['prompt'],
        avaliacao=int(data['avaliacao']),
        comentario=comentario,
        timestamp=FeedbackEntry.now()
    )
    status = save_feedback(entry)
    if status == 'duplicate':
        return jsonify({'status': 'duplicado'}), 200
    return jsonify({'status': 'ok'}), 201

@feedback_bp.route('/feedback/<id_artigo>', methods=['GET'])
def get_feedback(id_artigo):
    """
    Lista feedbacks associados a um artigo.
    """
    feedbacks = get_feedback_by_article(id_artigo)
    return jsonify(feedbacks) 