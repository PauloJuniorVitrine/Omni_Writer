import re
import logging
from typing import Dict, Optional

logger = logging.getLogger("parser.prompt_base_artigos")

class PromptBaseArtigosParser:
    """
    Parser para arquivos no formato prompt_base_artigos.txt.
    Extrai variáveis obrigatórias e opcionais, validando formato e preenchimento.
    """
    VARIAVEIS = [
        "NICHO",
        "CATEGORIA",
        "CLUSTER DE CONTEÚDO",
        "PERFIL DO CLIENTE / PERSONA",
        "PRODUTO FINAL (opcional)",
        "PALAVRA-CHAVE PRINCIPAL DO CLUSTER",
        "PALAVRAS-CHAVE SECUNDÁRIAS (opcional)",
        "ESTILO DE REDAÇÃO"
    ]

    def __init__(self, path: str):
        self.path = path
        self.data = {}

    def parse(self) -> Dict[str, Optional[str]]:
        with open(self.path, 'r', encoding='utf-8') as f:
            content = f.read()
        for var in self.VARIAVEIS:
            pattern = rf'\[{re.escape(var)}\]:\s*(.*)'
            match = re.search(pattern, content)
            if match:
                self.data[var] = match.group(1).strip()
                logger.info(f"Variável '{var}' extraída: {self.data[var]}")
            else:
                self.data[var] = None
                logger.warning(f"Variável '{var}' não encontrada no prompt.")
        self._validate_obrigatorias()
        return self.data

    def _validate_obrigatorias(self):
        obrigatorias = [v for v in self.VARIAVEIS if "(opcional)" not in v]
        for var in obrigatorias:
            if not self.data.get(var):
                logger.error(f"Variável obrigatória '{var}' não preenchida.")
                raise ValueError(f"Variável obrigatória '{var}' não preenchida.") 