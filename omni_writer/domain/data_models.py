import logging
from dataclasses import dataclass, field, asdict
from typing import List, Literal, Optional
from shared.messages import get_message

logger = logging.getLogger("domain.data_models")

@dataclass
class PromptInput:
    """
    Represents an input prompt for article generation.
    Attributes:
        text (str): The prompt text.
        index (int): The index of the prompt in the list.
    """
    text: str
    index: int

    def __post_init__(self):
        if not isinstance(self.text, str) or not self.text.strip():
            logger.error(f"Validação falhou: texto inválido em PromptInput: '{self.text}'")
            raise ValueError(get_message('erro_prompt_vazio'))
        if not isinstance(self.index, int) or self.index < 0:
            logger.error(f"Validação falhou: índice inválido em PromptInput: '{self.index}'")
            raise ValueError(get_message('erro_indice_invalido'))

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ArticleOutput:
    """
    Represents a generated article and its filename.
    Attributes:
        content (str): The article content.
        filename (str): The filename for the article.
        metadata (dict, optional): Additional metadata.
    """
    content: str
    filename: str
    metadata: Optional[dict] = field(default=None)

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class GenerationConfig:
    """
    Configuration for article generation via AI model.
    Attributes:
        api_key (str): API key for the model provider.
        model_type (Literal): Model type ('openai' or 'deepseek').
        prompts (List[PromptInput]): List of input prompts.
        temperature (float): Sampling temperature.
        max_tokens (int): Maximum number of tokens.
        language (str): Language code.
        extra (dict, optional): Additional configuration.
    """
    api_key: str
    model_type: Literal["openai", "deepseek"]
    prompts: List[PromptInput]
    temperature: float = 0.7
    max_tokens: int = 4096
    language: str = "pt-BR"
    extra: Optional[dict] = field(default=None)

    def __post_init__(self):
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            logger.error("Validação falhou: api_key vazia em GenerationConfig")
            raise ValueError(get_message('erro_api_key_vazia'))
        if self.model_type not in ("openai", "deepseek"):
            logger.error(f"Validação falhou: modelo não suportado em GenerationConfig: '{self.model_type}'")
            raise ValueError(get_message('modelo_nao_suportado', modelo=self.model_type))
        if not isinstance(self.prompts, list) or not all(isinstance(p, PromptInput) for p in self.prompts):
            logger.error("Validação falhou: prompts inválidos em GenerationConfig")
            raise ValueError(get_message('erro_lista_prompts'))
        if not self.prompts:
            logger.error("Validação falhou: lista de prompts vazia em GenerationConfig")
            raise ValueError(get_message('erro_lista_prompts'))
        if not (0.0 <= self.temperature <= 2.0):
            logger.error(f"Validação falhou: temperature fora do intervalo em GenerationConfig: {self.temperature}")
            raise ValueError(get_message('erro_temperature'))
        if not (256 <= self.max_tokens <= 8192):
            logger.error(f"Validação falhou: max_tokens fora do intervalo em GenerationConfig: {self.max_tokens}")
            raise ValueError(get_message('erro_max_tokens'))
        if not isinstance(self.language, str) or not self.language.strip():
            logger.error("Validação falhou: idioma inválido em GenerationConfig")
            raise ValueError(get_message('erro_idioma'))

    def to_dict(self) -> dict:
        return asdict(self) 