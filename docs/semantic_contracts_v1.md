# Contratos Semânticos — Omni Writer

## Hierarquia de Exceções
```python
class OmniWriterError(Exception):
    """Base para todas as exceções do sistema."""
    pass

class PipelineError(OmniWriterError):
    """Erros relacionados ao pipeline."""
    pass

class GatewayError(OmniWriterError):
    """Erros de comunicação com APIs externas."""
    pass

class StorageError(OmniWriterError):
    """Erros de persistência."""
    pass

class ControllerError(OmniWriterError):
    """Erros de controle e orquestração."""
    pass

class ValidationError(OmniWriterError):
    """Erros de validação de dados."""
    pass
```

## Contratos de Domínio

### Article
```python
class Article:
    """
    Contrato para representação de artigos gerados.
    """
    id: str                    # UUID único
    content: str              # Conteúdo do artigo
    model: str                # Modelo usado (openai, deepseek)
    status: str               # Status atual (pending, completed, failed)
    created_at: datetime      # Data de criação
    updated_at: datetime      # Data de atualização
    metadata: dict            # Metadados adicionais
```

### Pipeline
```python
class Pipeline:
    """
    Contrato para execução do pipeline de geração.
    """
    def execute(self, config: dict) -> Article:
        """
        Executa o pipeline de geração.
        Retorna: Article
        Raises: PipelineError
        """
        pass
```

## Contratos de Infraestrutura

### Gateway
```python
class Gateway:
    """
    Contrato base para gateways de IA.
    """
    def generate(self, prompt: str, config: dict) -> str:
        """
        Gera conteúdo via API externa.
        Retorna: str (conteúdo gerado)
        Raises: GatewayError
        """
        pass
```

### Storage
```python
class Storage:
    """
    Contrato para persistência de artigos.
    """
    def save(self, article: Article) -> bool:
        """
        Salva artigo no storage.
        Retorna: bool (sucesso)
        Raises: StorageError
        """
        pass

    def load(self, article_id: str) -> Article:
        """
        Carrega artigo do storage.
        Retorna: Article
        Raises: StorageError
        """
        pass
```

## Contratos de Aplicação

### Controller
```python
class Controller:
    """
    Contrato para controle de geração.
    """
    def generate_article(self, prompt: str, model: str) -> Article:
        """
        Coordena geração de artigo.
        Retorna: Article
        Raises: ControllerError
        """
        pass
```

## Contratos de Teste

### TestSuite
```python
class TestSuite:
    """
    Contrato para suítes de teste.
    """
    def setup(self) -> None:
        """
        Prepara ambiente de teste.
        """
        pass

    def teardown(self) -> None:
        """
        Limpa ambiente de teste.
        """
        pass

    def run(self) -> TestResult:
        """
        Executa suíte de testes.
        Retorna: TestResult
        """
        pass
```

## Contratos de Logging

### Logger
```python
class Logger:
    """
    Contrato para logging estruturado.
    """
    def info(self, message: str, context: dict = None) -> None:
        """
        Registra informação.
        """
        pass

    def error(self, message: str, error: Exception, context: dict = None) -> None:
        """
        Registra erro.
        """
        pass

    def metric(self, name: str, value: float, tags: dict = None) -> None:
        """
        Registra métrica.
        """
        pass
```

## Contratos de Eventos

### Event
```python
class Event:
    """
    Contrato para eventos do sistema.
    """
    type: str                # Tipo do evento
    payload: dict           # Dados do evento
    timestamp: datetime     # Momento do evento
    source: str            # Origem do evento
```

### EventBus
```python
class EventBus:
    """
    Contrato para sistema de eventos.
    """
    def publish(self, event: Event) -> None:
        """
        Publica evento.
        """
        pass

    def subscribe(self, event_type: str, handler: callable) -> None:
        """
        Registra handler para tipo de evento.
        """
        pass
```

## Observações
- Todos os contratos devem ser implementados conforme especificação
- Exceções devem seguir hierarquia definida
- Testes devem validar conformidade com contratos
- Documentação deve refletir alterações em contratos
- Logs devem seguir estrutura definida
- Eventos devem ser rastreáveis e consistentes 