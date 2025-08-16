from shared.messages import get_message

def test_get_message_ptbr():
    assert get_message('erro_processar_instancias') == 'Erro ao processar instâncias.'

def test_get_message_placeholder():
    msg = get_message('erro_gerar_artigos_massa', erro='X')
    assert 'X' in msg

def test_get_message_fallback():
    assert get_message('nao_existe_chave') == 'nao_existe_chave'

def test_get_message_outro_idioma():
    assert get_message('erro_processar_instancias', lang='en') == 'erro_processar_instancias'

def test_get_message_multiplos_placeholders():
    msg = get_message('erro_gerar_artigos_massa', erro='Y', extra='Z')
    assert 'Y' in msg

def test_get_message_kwargs_ausentes():
    # Não deve quebrar se placeholder não for fornecido
    msg = get_message('erro_gerar_artigos_massa')
    assert '{erro}' in msg or 'erro' in msg 