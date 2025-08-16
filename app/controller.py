from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from infraestructure.openai_gateway import generate_article_openai
from infraestructure.deepseek_gateway import generate_article_deepseek
from shared.messages import get_message


def generate_article(
    config: GenerationConfig,
    prompt: PromptInput,
    trace_id: str = None,
    variation: int = 0,
    gateways: dict = None
) -> ArticleOutput:
    """
    Generates an article using the model specified in config.
    Allows gateway injection for testability and extensibility.

    Args:
        config (GenerationConfig): Configuration for article generation (API key, model, etc).
        prompt (PromptInput): Prompt to be used for generation.
        trace_id (str, optional): Trace identifier for logging/tracking.
        variation (int, optional): Variation index for prompt/model.
        gateways (dict, optional): Custom gateway functions for extensibility/testing.

    Returns:
        ArticleOutput: Generated article output object.

    Raises:
        ValueError: If the model_type is not supported.
        Exception: Propagates any exception from the gateway call.
    """
    # Use default gateways if none provided
    gateways = gateways or {
        'openai': generate_article_openai,
        'deepseek': generate_article_deepseek,
    }
    try:
        # Select and call the appropriate gateway based on model_type
        if config.model_type in gateways:
            return gateways[config.model_type](config, prompt, trace_id=trace_id, variation=variation)
        # Raise error if model_type is not supported
        raise ValueError(get_message('modelo_nao_suportado', modelo=config.model_type))
    except Exception as e:
        # Optionally log error details here for observability
        raise 