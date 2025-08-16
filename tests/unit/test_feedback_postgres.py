import pytest
from feedback import storage

def setup_function():
    # Limpa a tabela de feedback antes de cada teste
    storage.init_db()
    session = storage.Session()
    session.query(storage.Feedback).delete()
    session.commit()
    session.close()

def test_save_and_get_feedback():
    storage.save_feedback('user1', 'art1', 'positivo', 'Muito bom!')
    feedbacks = storage.get_feedbacks('art1')
    assert any(fb['user_id'] == 'user1' and fb['artigo_id'] == 'art1' for fb in feedbacks)

def test_save_feedback_multiple():
    storage.save_feedback('user2', 'art2', 'negativo', 'Ruim')
    storage.save_feedback('user3', 'art2', 'neutro', 'Ok')
    feedbacks = storage.get_feedbacks('art2')
    assert len(feedbacks) == 2
    users = {fb['user_id'] for fb in feedbacks}
    assert 'user2' in users and 'user3' in users

def test_get_feedbacks_empty():
    feedbacks = storage.get_feedbacks('artigo_inexistente')
    assert feedbacks == [] 