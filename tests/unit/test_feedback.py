import os
import json
import pytest
from unittest import mock
from feedback import storage, analysis
from feedback.models import FeedbackEntry

def make_entry(id_artigo, prompt, avaliacao, comentario=None, timestamp=1234567890):
    return FeedbackEntry(id_artigo=id_artigo, prompt=prompt, avaliacao=avaliacao, comentario=comentario, timestamp=timestamp)

def test_save_and_list_feedback(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    entry = make_entry("a1", "prompt1", 1, "bom")
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        r = storage.save_feedback(entry)
        assert r == "ok"
        feedbacks = storage.list_feedbacks()
        assert any(fb["id_artigo"] == "a1" for fb in feedbacks)

def test_save_feedback_duplicate(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    entry = make_entry("a2", "prompt2", 1, "igual")
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        assert storage.save_feedback(entry) == "ok"
        # Mesmo id_artigo, avaliacao e comentario
        assert storage.save_feedback(entry) == "duplicate"

def test_get_feedback_by_article(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    entry1 = make_entry("a3", "prompt3", 1)
    entry2 = make_entry("a3", "prompt4", 0)
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        storage.save_feedback(entry1)
        storage.save_feedback(entry2)
        res = storage.get_feedback_by_article("a3")
        assert len(res) == 2
        assert any(fb["prompt"] == "prompt3" for fb in res)

def test_list_feedbacks_empty(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        res = storage.list_feedbacks()
        assert res == []

def test_list_feedbacks_ioerror(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    # Cria o arquivo fora do mock
    with open(fb_file, 'w', encoding='utf-8') as f:
        f.write('[]')
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        # Mock apenas durante a leitura
        with pytest.raises(OSError):
            with mock.patch("builtins.open", side_effect=OSError("fail")):
                storage.list_feedbacks()

def test_save_feedback_ioerror(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    entry = make_entry("a10", "prompt10", 1)
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        with mock.patch("feedback.storage.NamedTemporaryFile", side_effect=OSError("fail")):
            with pytest.raises(OSError):
                storage.save_feedback(entry)

def test_get_best_prompts(tmp_path):
    fb_file = tmp_path / "feedback_data.json"
    entries = [
        make_entry("a4", "promptX", 1),
        make_entry("a5", "promptX", 1),
        make_entry("a6", "promptX", 0),
        make_entry("a7", "promptY", 1),
        make_entry("a8", "promptY", 1),
        make_entry("a9", "promptY", 1),
    ]
    with mock.patch("feedback.storage.FEEDBACK_FILE", str(fb_file)):
        for e in entries:
            storage.save_feedback(e)
        with mock.patch("feedback.analysis.list_feedbacks", storage.list_feedbacks):
            best = analysis.get_best_prompts(min_feedbacks=2)
            prompts = [b["prompt"] for b in best]
            assert "promptY" in prompts
            assert "promptX" in prompts
            assert best[0]["taxa_aprovacao"] >= best[1]["taxa_aprovacao"]

def test_get_best_prompts_empty():
    with mock.patch("feedback.analysis.list_feedbacks", return_value=[]):
        res = analysis.get_best_prompts(min_feedbacks=1)
        assert res == []

def test_feedbackentry_valid():
    entry = FeedbackEntry(id_artigo='a1', prompt='p', avaliacao=1, comentario='ok', timestamp='2024-01-01T00:00:00')
    d = entry.to_dict()
    assert d['id_artigo'] == 'a1'
    assert d['avaliacao'] == 1
    assert isinstance(entry.to_dict(), dict)

def test_feedbackentry_now():
    now = FeedbackEntry.now()
    assert isinstance(now, str)
    assert 'T' in now 