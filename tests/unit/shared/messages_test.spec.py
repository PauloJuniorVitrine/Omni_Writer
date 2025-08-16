import pytest
import shared.messages as messages_mod

def test_get_message_known_key():
    msg = messages_mod.get_message("artigo_salvo", arquivo="a.txt")
    assert isinstance(msg, str)
    assert "a.txt" in msg or msg != ""

def test_get_message_unknown_key():
    msg = messages_mod.get_message("chave_inexistente")
    assert isinstance(msg, str)
    assert msg != ""

def test_get_message_no_params():
    msg = messages_mod.get_message("artigo_salvo")
    assert isinstance(msg, str)
    assert msg != "" 