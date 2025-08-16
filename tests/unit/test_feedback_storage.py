import os
import json
import pytest
from unittest import mock
from feedback import storage as fb_storage
from feedback.models import FeedbackEntry
from types import SimpleNamespace
from datetime import datetime

def test_save_feedback_json_success(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    entry = FeedbackEntry(id_artigo='a1', prompt='p1', avaliacao=5, comentario='bom', timestamp=datetime.utcnow().isoformat())
    r = fb_storage.save_feedback(entry)
    assert r == 'ok'
    with open(feedback_file, encoding='utf-8') as f:
        data = json.load(f)
        assert data[0]['id_artigo'] == 'a1'

def test_save_feedback_json_duplicate(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    entry = FeedbackEntry(id_artigo='a1', prompt='p1', avaliacao=5, comentario='bom', timestamp=datetime.utcnow().isoformat())
    fb_storage.save_feedback(entry)
    r = fb_storage.save_feedback(entry)
    assert r == 'duplicate'

def test_save_feedback_json_ioerror(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    entry = FeedbackEntry(id_artigo='a2', prompt='p2', avaliacao=3, comentario=None, timestamp=datetime.utcnow().isoformat())
    monkeypatch.setattr('builtins.open', mock.Mock(side_effect=OSError('fail')))
    monkeypatch.setattr('feedback.storage.NamedTemporaryFile', mock.Mock(side_effect=OSError('fail')))
    with pytest.raises(OSError):
        fb_storage.save_feedback(entry)

def test_save_feedback_sqlalchemy(monkeypatch):
    dummy_session = mock.MagicMock()
    monkeypatch.setattr(fb_storage, 'Session', lambda: dummy_session)
    r = fb_storage.save_feedback('u1', 'a1', 'tipo', 'coment')
    assert r == 'ok'
    assert dummy_session.add.called
    assert dummy_session.commit.called
    assert dummy_session.close.called

def test_save_feedback_invalid():
    with pytest.raises(TypeError):
        fb_storage.save_feedback(1, 2, 3)

def test_get_feedbacks(monkeypatch):
    dummy_fb = SimpleNamespace(id=1, user_id='u', artigo_id='a', tipo='t', comentario='c', criado_em='now')
    dummy_session = mock.MagicMock()
    dummy_session.query.return_value.filter_by.return_value.all.return_value = [dummy_fb]
    dummy_session.query.return_value.all.return_value = [dummy_fb]
    monkeypatch.setattr(fb_storage, 'Session', lambda: dummy_session)
    res = fb_storage.get_feedbacks('a')
    assert res[0]['artigo_id'] == 'a'
    res2 = fb_storage.get_feedbacks()
    assert res2[0]['user_id'] == 'u'
    assert dummy_session.close.called

def test_list_feedbacks(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    with open(feedback_file, 'w', encoding='utf-8') as f:
        json.dump([{'id_artigo': 'a', 'prompt': 'p', 'avaliacao': 5}], f)
    res = fb_storage.list_feedbacks()
    assert res[0]['id_artigo'] == 'a'

def test_list_feedbacks_empty(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    res = fb_storage.list_feedbacks()
    assert res == []

def test_list_feedbacks_jsonerror(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    with open(feedback_file, 'w', encoding='utf-8') as f:
        f.write('{invalid json}')
    res = fb_storage.list_feedbacks()
    assert res == []

def test_get_feedback_by_article(tmp_path, monkeypatch):
    feedback_file = tmp_path / 'feedback_data.json'
    monkeypatch.setattr(fb_storage, 'FEEDBACK_FILE', str(feedback_file))
    data = [
        {'id_artigo': 'a', 'prompt': 'p', 'avaliacao': 5},
        {'id_artigo': 'b', 'prompt': 'p', 'avaliacao': 4}
    ]
    with open(feedback_file, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    res = fb_storage.get_feedback_by_article('a')
    assert len(res) == 1 and res[0]['id_artigo'] == 'a' 