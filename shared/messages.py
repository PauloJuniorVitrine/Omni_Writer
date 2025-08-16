"""
Message utilities for internationalized user and system messages.
Provides message retrieval and formatting for multiple languages.
"""
MESSAGES = {
    'pt-BR': {
        'erro_processar_instancias': 'Erro ao processar instâncias.',
        'erro_ler_prompts': 'Erro ao ler o arquivo de prompts. Certifique-se de que está em UTF-8.',
        'prompts_obrigatorios': 'Prompts obrigatórios.',
        'campos_obrigatorios': 'Todos os campos são obrigatórios.',
        'erro_gerar_artigos': 'Erro ao gerar artigos.',
        'erro_gerar_artigos_massa': 'Erro ao gerar artigos em massa: {erro}',
        'arquivo_zip_nao_encontrado': 'Arquivo ZIP não encontrado.',
        'instancia_obrigatoria': 'É obrigatório cadastrar ao menos uma instância.',
        'prompt_obrigatorio': 'É obrigatório informar ao menos um prompt.',
        'sucesso_geracao': 'Artigos gerados com sucesso!',
        'erro_prompt_vazio': 'O texto do prompt deve ser uma string não vazia.',
        'erro_indice_invalido': 'O índice do prompt deve ser um inteiro não negativo.',
        'erro_api_key_vazia': 'A chave da API deve ser uma string não vazia.',
        'modelo_nao_suportado': 'Modelo não suportado: {modelo}',
        'erro_lista_prompts': 'Prompts deve ser uma lista de PromptInput.',
        'erro_temperature': 'Temperature deve estar entre 0.0 e 2.0.',
        'erro_max_tokens': 'max_tokens deve estar entre 256 e 8192.',
        'erro_idioma': 'O idioma deve ser uma string não vazia.',
        'artigo_salvo': 'Artigo salvo com sucesso: {arquivo}',
        'artigo_duplicado_ignorado': 'Artigo duplicado ignorado: {arquivo}',
        'erro_salvar_artigo': 'Erro ao salvar artigo: {erro}'
    }
}

def get_message(key, lang='pt-BR', **kwargs):
    """
    Retrieves a localized message by key and language, formatting with kwargs if provided.
    Args:
        key (str): Message key.
        lang (str): Language code (default: 'pt-BR').
        **kwargs: Optional formatting arguments for the message.
    Returns:
        str: Localized and formatted message.
    """
    msg = MESSAGES.get(lang, {}).get(key, key)
    if kwargs:
        return msg.format(**kwargs)
    return msg 