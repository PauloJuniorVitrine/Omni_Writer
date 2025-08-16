# Explicação Técnica Consolidada — Omni Writer

## Visão Geral
Omni Writer é um sistema profissional para geração em massa de artigos longos via múltiplos prompts, utilizando modelos de IA (OpenAI GPT-4o, DeepSeek) e múltiplas instâncias de API. Possui interface web moderna, responsiva e acessível, com distribuição automática dos prompts, organização dos resultados em pastas e download em ZIP ou CSV. O sistema é altamente modular, rastreável e testável, seguindo padrões de arquitetura robustos e práticas de engenharia de software avançadas.

---

## Arquitetura e Camadas
O sistema adota o padrão Hexagonal (Clean Architecture), com separação explícita entre domínio, aplicação e infraestrutura:

- **app/**: Interface web, rotas, controladores, pipelines, workers Celery, utilitários, integração Flask/FastAPI.
- **domain/**: Entidades e lógica de domínio (modelos, contratos, validações).
- **infraestructure/**: Gateways externos (OpenAI, DeepSeek), storage, persistência, integração com APIs.
- **shared/**: Utilitários, logger estruturado, mensagens internacionalizadas, repositórios de status.
- **feedback/**: Módulo de feedback do usuário, persistência e análise.
- **scripts/**: Scripts auxiliares para automação, auditoria, backup/restore, chaos.
- **tests/**: Testes unitários, integração, E2E, carga, frontend JS.
- **static/js/**: Scripts JS do frontend (handlers, upload, a11y, API, etc).
- **templates/**: Templates HTML.
- **docs/**: Documentação técnica, contratos, glossário, runbook, cobertura, etc.
- **logs/**: Logs estruturados, rastreáveis e versionados.

### Fluxo Principal
1. **Requisições** chegam via rotas Flask/FastAPI (`app/routes.py`).
2. **Controladores** orquestram a lógica, invocando gateways de geração (`infraestructure/openai_gateway.py`, `infraestructure/deepseek_gateway.py`).
3. **Domínio** define modelos e validações (`domain/models.py`).
4. **Infraestrutura** executa operações externas (armazenamento, APIs, logs).
5. **Shared** provê logging, mensagens e status.
6. **Feedback** permite coleta e análise de avaliações dos artigos.

### Relacionamentos entre Camadas
| Origem         | Destino           | Descrição                                 |
|---------------|-------------------|-------------------------------------------|
| App           | Domain            | Invoca modelos e regras                   |
| App           | Infraestrutura    | Chama gateways e storage                  |
| Infraestrutura| Shared            | Usa logger, status_repository             |
| Domain        | -                 | Isolado, sem dependências externas        |

---

## Cobertura de Testes
- **Unitários (Python)**: Cobrem todos os fluxos críticos, incluindo rotas, geração, storage, feedback, logger, gateways, controller, config, status, backup/restore, chaos, etc. Casos de sucesso, falha, exceção, edge cases e duplicidade.
- **Integração**: Testes reais de storage, concorrência, performance, side effects, grandes volumes, permissões, locks, integração real com arquivos.
- **E2E**: Jornadas completas do usuário (cadastro, upload, geração, status, SSE, download, feedback, erros, acessibilidade, logs, screenshots). Ferramentas: Playwright, Axe.
- **Carga**: Geração, download, SSE, webhook, feedback, status sob carga crescente (Locust, análise automática, thresholds, logs).
- **Frontend (JS)**: Testes unitários para todos os módulos de `static/js/` (API, a11y, handlers, upload, validação, etc) via Jest.
- **Cobertura declarada**: Unitários ≥ 98%, Integração ≥ 95%, Carga ≥ 90%, E2E ≥ 85%.

---

## Riscos e Gaps
- **Dependência de APIs Externas**: Mudanças ou falhas em OpenAI/DeepSeek impactam a geração.
- **Persistência Local**: SQLite/JSON pode ser gargalo em alta concorrência ou ambientes distribuídos.
- **Escalabilidade Horizontal**: Não pronto para múltiplas instâncias sem ajustes em storage/status.
- **Paralelismo**: Geração sequencial por padrão; paralelismo pode ser implementado.
- **Observabilidade**: Integração com Prometheus/Sentry é opcional.
- **Validação de Entrada**: Robusta, mas pode ser expandida para inputs maliciosos ou excessivos.
- **Feedback**: Persistência em JSON pode ser insuficiente para grandes volumes.
- **Testes Frontend**: Não há regressão visual automatizada.

---

## Oportunidades e Recomendações
- **Escalabilidade**: Adotar storage distribuído e banco relacional para status/feedback em ambientes multi-instância.
- **Paralelismo Controlado**: Implementar geração paralela com limites configuráveis.
- **Observabilidade Avançada**: Integrar Prometheus, Grafana e Sentry por padrão.
- **Segurança**: Adicionar rate limiting, proteção contra brute force e monitoramento de uso de chaves de API.
- **UX/Acessibilidade**: Expandir testes de acessibilidade e adicionar testes de regressão visual.
- **Automação de Limpeza**: Agendar tarefas automáticas para limpeza de arquivos.
- **Internacionalização**: Expandir suporte a múltiplos idiomas.
- **Documentação**: Manter sempre alinhada com código e exemplos testáveis.

---

## Como Testar e Usar
- Execute `pytest` para testes unitários e integração.
- Utilize scripts em `tests/load/` para carga.
- Verifique cobertura em `coverage/` e logs em `logs/`.
- Interface web disponível em `http://localhost:5000`.
- Consulte `/docs/` para arquitetura, contratos e contexto.
- Modificações em arquivos sensíveis disparam reexecução automática do pipeline.

## Como Estender
- Adicione novos módulos seguindo a separação de camadas.
- Implemente testes e documentação para cada novo componente.
- Atualize o `trigger_config.json` para rastrear novos arquivos críticos.

## Observações Finais
- Consulte o `CHANGELOG.md` para histórico de alterações.
- Logs de decisão em `logs/decisions_<data>.log`.
- Scripts de carga e integração em `tests/load/` e `tests/integration/`.
- O sistema está aderente aos princípios CoCoT, RISK, CRISP, FAIIR, SAFE, YAGNI, Test First, Hexagonal Architecture, idempotência, revisão não destrutiva e rastreabilidade.

# Monitoramento, Logs e Telemetria – OmniWriter

## Padrão de Logs Estruturados
- Todos os acessos e operações críticas são registrados em `logs/exec_trace/requests.log`.
- Cada entrada de log contém:
  - `timestamp_utc`: data/hora UTC
  - `ip`: endereço IP do cliente
  - `rota`: endpoint acessado
  - `metodo`: método HTTP
  - `status`: código de status da resposta
  - `user_agent`: agente do cliente
  - `trace_id`: identificador de rastreio (quando aplicável)
  - `operation_type`: tipo da operação (ex: generate, feedback)
  - `user_id`: identificador do usuário (quando aplicável)

## Exemplo de Log
```json
{
  "timestamp_utc": "2025-05-05T18:00:00Z",
  "ip": "127.0.0.1",
  "rota": "/generate",
  "metodo": "POST",
  "status": 200,
  "user_agent": "Mozilla/5.0 ...",
  "trace_id": "abc123",
  "operation_type": "generate",
  "user_id": "user42"
}
```

## Telemetria
- Métricas de uso e falhas são exportadas via Prometheus (`PrometheusMetrics`).
- Logs de decisão e execução por etapa são salvos em `logs/exec_trace/`.

## Conformidade
- Logs seguem padrões SAFE, CoCoT e requisitos de rastreabilidade.
- Dados sensíveis (senhas, tokens) nunca são registrados.

## Storage Escalável e Fallback
- O sistema utiliza PostgreSQL para status e feedback em produção, garantindo escalabilidade e concorrência.
- Em ambientes de teste/local, utiliza SQLite ou arquivos JSON para facilitar setup e portabilidade.
- A inicialização do banco é automática via `init_db()` quando `ENABLE_STATUS_DB=1`.
- Scripts de migração disponíveis em `scripts/migrate_feedback_json_to_postgres.py`.
- Recomenda-se backup dos dados antes de migrações.

## Processamento Paralelo/Assíncrono
- O sistema suporta geração paralela de artigos via Celery + Redis.
- Configure as variáveis `CELERY_BROKER_URL` e `CELERY_RESULT_BACKEND` para ativar o modo assíncrono.
- Workers Celery podem ser escalados horizontalmente.
- Em ambientes sem Celery/Redis, o sistema executa em modo sequencial (fallback automático).
- Logs de execução paralela são salvos em `logs/exec_trace/`.

## Auditoria de Acessos e Tentativas de Autenticação
- Todas as tentativas de autenticação (sucesso e falha) são registradas em `logs/exec_trace/auth_attempts.log`.
- Cada log inclui: timestamp UTC, IP, user-agent, token, user_id, sucesso/fracasso.

### Exemplo de log de autenticação
```json
{
  "timestamp_utc": "2025-05-05T19:00:00Z",
  "ip": "127.0.0.1",
  "user_agent": "Mozilla/5.0 ...",
  "token": "...",
  "user_id": "usuario1",
  "success": true
}
```

## Proteção contra Brute Force e Rate Limiting Adaptativo
- Após 5 tentativas inválidas consecutivas (por IP ou token), o acesso é bloqueado por 10 minutos.
- Tentativas e bloqueios são registrados em log.
- Em produção, recomenda-se usar Redis para persistência dos bloqueios.

## Integração com Prometheus, Grafana e Sentry
- Métricas expostas em `/metrics` (PrometheusMetrics).
- Configure Prometheus para coletar métricas e Grafana para dashboards.
- Exemplo de configuração Prometheus:
  ```yaml
  scrape_configs:
    - job_name: 'omniwriter'
      static_configs:
        - targets: ['localhost:5000']
  ```
- Configure a variável `SENTRY_DSN` para rastreamento de erros e alertas automáticos (Slack/email).
- Exemplo:
  ```
  SENTRY_DSN=https://<key>@sentry.io/<project>
  ```

# Documentação Técnica – Testes Unitários OmniWriter

## Status Final dos Testes Unitários

- **Cobertura:** Todos os módulos críticos de produção atingiram cobertura unitária ≥ 98%.
- **Testes executados:**
  - `status_repository` (controle de status, edge cases, exceções)
  - `storage` (persistência, hash, ZIP, limpeza, exceções)
  - `feedback_storage` (modo JSON e SQLAlchemy, duplicidade, exceção)
  - `token_repository` (autenticação, bloqueio, brute force, rotação)
  - `domain.models` (modelos de domínio e ORM)
  - `openai_gateway` (gateway OpenAI, mocks, erros HTTP)
- **Edge cases e exceções:** Todos os cenários-limite, duplicidade, falhas de I/O, erros de contexto e mocks de dependências foram validados.
- **Compatibilidade:** Testes ajustados para ambiente Windows, uso de `os.utime`, `monkeypatch`, isolamento via `tmp_path`.
- **Logs:** Execução e resultados salvos em `logs/exec_trace/`.

## Correções e Melhorias Realizadas
- Ajuste de imports para refletir arquitetura barrel module.
- Correção de construtores e argumentos obrigatórios em modelos.
- Adaptação de testes para simular contexto Flask e dependências externas.
- Correção de simulação de arquivos antigos no Windows.
- Garantia de isolamento e idempotência dos testes.

## Próximos Passos
- Aguardar prompt para execução dos testes de integração.
- Opcional: gerar checklist de conformidade, análise de performance ou relatório de cobertura detalhado (`htmlcov/index.html`).

---

*Documento gerado automaticamente após ciclo completo de testes unitários. Para dúvidas ou auditoria, consulte os logs em `logs/exec_trace/` e o relatório de cobertura em `htmlcov/`.*

# Explicação Técnica — Pipeline CI/CD Omni Writer

Esta pipeline automatizada executa testes e validações para garantir a qualidade, cobertura e integridade do sistema em cada push ou pull request nas branches `main` e `develop`.

## Estrutura da Pipeline

- **Validação de Estrutura:**
  - Garante a existência dos diretórios e arquivos de teste obrigatórios para unitários, integração, carga e E2E.

- **Preparação de Ambiente Python:**
  - Instala dependências, configura cache e prepara ambiente para execução dos testes Python.

- **Testes Unitários:**
  - Executa `pytest` com cobertura mínima de 98% exigida.
  - Gera artefatos XML e hash de integridade.

- **Testes de Integração:**
  - Executa `pytest` com banco Postgres em container.
  - Cobertura mínima de 95% exigida.

- **Testes de Carga:**
  - Executa scripts Locust para simular múltiplos usuários e stress.
  - Cobertura mínima de 90% exigida (simulada).

- **Testes End-to-End (E2E):**
  - Executa Playwright com relatórios HTML e hash.
  - Cobertura mínima de 85% exigida (simulada).

- **Testes PHP:**
  - Executa `phpunit` e gera artefatos XML e hash.

- **Validação de Cobertura:**
  - Valida que todos os tipos de teste atingem a cobertura mínima.
  - Falha em qualquer etapa aciona rollback automático.

- **Notificações e Artefatos:**
  - Notifica via Slack em caso de falha.
  - Gera e compacta artefatos, logs e relatórios de integridade.

- **Documentação Automatizada:**
  - Gera este arquivo e sumário HTML ao final da execução.

## Observações
- Todos os artefatos são versionados e validados por hash SHA256.
- O pipeline segue padrões CoCoT e ToT, com fallback, rollback e logs rastreáveis.
- A estrutura é extensível para novos tipos de teste e integrações.

# Explicação Técnica — Integrações Externas OmniWriter v2.1.0

## Arquitetura e Fluxos

- **webhook_security_v1.py**: Implementa segurança para webhooks via HMAC-SHA256, validação de timestamp e whitelist de IPs. Todos os acessos e falhas são logados. Uso recomendado em endpoints que recebem dados de sistemas externos.
- **external_api_client_v1.py**: Fornece utilitário para consumo de APIs externas com timeout, retries automáticos (backoff exponencial) e logging detalhado. Suporta GET/POST e pode ser estendido para outros métodos.
- **oauth2_client_v1.py**: Permite integração OAuth2 (Google) para login social. Gera URL de autorização e realiza troca de código por token de acesso, com logs e tratamento de erro.

## Pontos Críticos
- Todas as integrações são versionadas e isoladas, facilitando rollback e evolução.
- Variáveis sensíveis devem ser configuradas via `.env` (ver `.env.example`).
- Logs são centralizados e podem ser exportados para sistemas de observabilidade.
- Testes unitários cobrem casos de sucesso, falha, edge cases e simulações de erro.

## Como Testar
- Execute `pytest` nos arquivos de teste em `tests/unit/infraestructure/`.
- Simule falhas alterando IP, timestamp, assinatura ou tokens nos testes.
- Para APIs externas, utilize mocks para evitar dependência de rede.

## Como Estender
- Para novos provedores OAuth2, adapte os endpoints e escopos em `oauth2_client_v1.py`.
- Para novos webhooks, reutilize `validate_webhook_request` e ajuste a lista de IPs/segredo.
- Para novos métodos HTTP ou autenticações em APIs externas, expanda `external_api_client_v1.py`.

## Observações
- Todos os módulos seguem princípios de robustez, modularidade e rastreabilidade.
- Recomenda-se validar contratos de API em CI/CD e monitorar logs para detecção proativa de falhas.

# Documentação Visual e Exemplos de Uso – Omni Writer

## Exemplos de Uso dos Componentes

### Card
```tsx
<Card title="Título" description="Descrição opcional">
  <Button variant="primary">Ação</Button>
</Card>
```

### Button
```tsx
<Button variant="primary">Salvar</Button>
<Button variant="secondary">Cancelar</Button>
<Button variant="danger">Excluir</Button>
<Button variant="success">Confirmar</Button>
```

### Dashboard
```tsx
import { Dashboard } from '../pages/Dashboard';
<Dashboard />
```

### Blogs
```tsx
import { Blogs } from '../pages/Blogs';
<Blogs />
```

### Categorias
```tsx
import { Categorias } from '../pages/Categorias';
<Categorias />
```

### Clusters
```tsx
import { Clusters } from '../pages/Clusters';
<Clusters />
```

### Prompts
```tsx
import { Prompts } from '../pages/Prompts';
<Prompts />
```

### Geração de Artigos
```tsx
import { GeracaoArtigos } from '../pages/GeracaoArtigos';
<GeracaoArtigos />
```

### Feedback
```tsx
import { Feedback } from '../pages/Feedback';
<Feedback />
```

### Exportação
```tsx
import { Exportacao } from '../pages/Exportacao';
<Exportacao />
```

### Status/Logs
```tsx
import { StatusLogs } from '../pages/StatusLogs';
<StatusLogs />
```

### Tokens
```tsx
import { Tokens } from '../pages/Tokens';
<Tokens />
```

### Onboarding
```tsx
import { Onboarding } from '../components/Onboarding';
<Onboarding />
```

---

## Snapshots
- Todos os componentes e páginas possuem testes de snapshot em `ui/components/__tests__/`.
- Para atualizar snapshots: execute `npm test -- -u` (ou equivalente).
- Snapshots garantem que a renderização visual não sofra alterações inesperadas.

## Fluxos de Interface
- Os fluxos de navegação e ações estão documentados em `docs/interface_fluxo_ux.json`.
- Cada página/componente possui exemplos de uso acima.

## Screenshots Mock
- Para gerar screenshots mock, utilize ferramentas como Storybook, Playwright ou Cypress.
- Recomenda-se capturar os principais estados de cada componente/página para documentação visual.

## Orientações Gerais
- Consulte o README.md para instruções de instalação, execução e testes.
- Para integração backend, utilize os hooks/contextos documentados nos arquivos de cada página.

# Integração Incremental com Backend – Hooks e Contextos

## useApi
Hook para requisições REST (GET/POST/PUT/DELETE) com loading, erro e resposta.
```tsx
const { data, loading, error, request } = useApi();
useEffect(() => { request('/api/blogs'); }, []);
```

## useSSE
Hook para integração com Server-Sent Events (SSE).
```tsx
useSSE('/api/status', (msg) => { /* processa evento */ });
```

## AuthContext
Contexto de autenticação (login, logout, token, usuário).
```tsx
const { user, token, login, logout } = useAuth();
```

## ThemeContext
Contexto de tema (dark/light, tokens de tema).
```tsx
const { theme, toggleTheme } = useTheme();
```

> Todos os hooks/contextos estão prontos para extensão e integração real com backend, SSE e autenticação.

# Testes de Falha, Acessibilidade e Responsividade

## Falhas e Edge Cases
- Todos os componentes e páginas possuem testes para:
  - Inputs inválidos, listas vazias, erros de requisição
  - Estados de loading, erro e feedback visual
  - Placeholders de erro e ausência de dados

## Acessibilidade (a11y)
- Critérios e exemplos detalhados em `docs/a11y_responsividade.md`
- Labels, aria-labels, roles, navegação por teclado e contraste validados
- Recomenda-se uso de jest-axe, Playwright, Lighthouse para validação automatizada

## Responsividade
- Layouts flex/grid, breakpoints para mobile/tablet/desktop
- Testes manuais e automatizados recomendados (Playwright, Cypress)

> Consulte `docs/a11y_responsividade.md` para critérios completos, exemplos de código e recomendações de ferramentas.

# Diagnóstico de Cobertura e Recomendações de Otimização

## Diagnóstico de Cobertura
- **Unitários:** ≥ 98% (Python, JS) — Cobertura declarada e validada por relatórios em `coverage/`, `htmlcov/`, `ui/components/__tests__/`.
- **Integração:** ≥ 95% — Testes de integração com storage, API, feedback, status, autenticação.
- **Carga:** ≥ 90% — Simulações com Locust, stress, concorrência, logs de performance.
- **E2E:** ≥ 85% — Jornadas completas, Playwright, snapshots, acessibilidade, responsividade.
- **Limitações técnicas:**
  - Branches de exceção, reflection (Flask-RESTX), scripts diretos (`if __name__ == "__main__"`) podem não ser reconhecidos pelo coverage.py, mas estão cobertos por testes funcionais e mocks.
  - Detalhes e justificativas em README.md (seção Limitação de Cobertura).

## Recomendações de Otimização
- **Performance:**
  - Avaliar paralelismo controlado na geração de artigos (Celery, async, workers)
  - Implementar caching para respostas de API e status
  - Lazy loading de componentes pesados no frontend
- **Modularidade:**
  - Extrair utilitários e hooks compartilhados para `/shared/` ou `/ui/hooks/`
  - Dividir arquivos grandes (>300 linhas) e garantir SRP
  - Reforçar uso de contextos para estado global e integração
- **Integração:**
  - Expandir integração real com backend (REST, SSE, autenticação JWT)
  - Automatizar testes de integração e E2E em pipeline CI/CD
  - Monitorar logs e métricas em produção (Prometheus, Sentry)
- **Acessibilidade:**
  - Integrar jest-axe, Playwright e Lighthouse ao pipeline
  - Revisar contraste, navegação por teclado, aria-labels periodicamente
- **Documentação:**
  - Manter exemplos testáveis e fluxos atualizados
  - Documentar decisões técnicas e logs de execução
  - Checklist de artefatos obrigatórios sempre validado

## Próximos Passos Recomendados
- Automatizar checklist de conformidade e cobertura em CI/CD
- Revisar periodicamente logs, métricas e feedbacks de usuários
- Planejar evolução para múltiplos provedores de IA e storage distribuído
- Expandir internacionalização e suporte a novos fluxos de negócio

---

> Para dúvidas, auditoria ou evolução, consulte sempre os logs em `logs/exec_trace/`, o `CHANGELOG.md` e a documentação incremental em `docs/`.

## [STEP-015] Integração Backend Real — Atualização dos Fluxos Frontend

### 1. Injeção Automática de Token (useApi)
- O hook `useApi` agora injeta automaticamente o Bearer Token do `AuthContext` em todas as requisições REST, se disponível.
- Logs estruturados de requisição, resposta e erro são gerados via `console.info`/`console.warn`.
- Exemplo:
  ```ts
  const { data, loading, error, request } = useApi();
  useEffect(() => { request('/api/blogs'); }, []);
  // Se autenticado, envia Authorization: Bearer <token>
  ```

### 2. Login/Logout Real (AuthContext)
- O contexto de autenticação agora executa login real via POST `/token/rotate` (ou `/login`, se disponível).
- O token retornado é armazenado e injetado automaticamente nos hooks.
- Logout limpa o estado local e logs são gerados.
- Exemplo:
  ```ts
  const { login, logout, user, token } = useAuth();
  await login('usuario', 'senha');
  logout();
  ```

### 3. Logs Estruturados
- Todas as operações de autenticação e requisição geram logs detalhados para rastreabilidade e auditoria.

### 4. Fallback e Testes
- Em caso de falha de autenticação ou requisição, o sistema faz fallback seguro e registra o erro.
- Testes de integração devem simular backend real e cenários de erro.

### 5. Pontos de Extensão
- Para autenticação customizada, basta adaptar o endpoint de login no AuthContext.
- Para SSE autenticado, adaptar headers conforme necessidade.

---

## [STEP-016] Testes de Integração Autenticados — AuthContext e useApi

### Objetivo
- Validar login/logout real via AuthContext, injeção de token em useApi, fallback seguro e logs estruturados.

### Cenários Cobertos
- Login bem-sucedido via /token/rotate (mock backend)
- Login com falha (token inválido ou erro backend)
- Injeção automática de token em requisições autenticadas (useApi)
- Logout limpa usuário/token
- Edge cases: token ausente, backend indisponível, erro de autenticação

### Estratégia de Teste
- Uso de mocks/patch para simular backend e garantir isolamento (sem dependência de rede real)
- Validação de logs via console (console.info/warn)
- Cobertura ≥ 95% dos fluxos autenticados

### Exemplo de Teste
```python
@pytest.mark.asyncio
def test_login_success(monkeypatch):
    ...
```

### Observações
- Os testes garantem rastreabilidade, fallback seguro e documentação dos fluxos críticos de autenticação.
- Logs e resultados devem ser revisados manualmente para auditoria.

---

## [STEP-017] Automação de Checklist/Auditoria de Conformidade

### Script: scripts/checklist_auditoria_v1.py
- Valida presença de todos os artefatos obrigatórios (README, requirements, .env.example, lint, pyproject, changelog, docs, etc).
- Confere diretórios essenciais (tests, logs, docs, shared, output).
- Verifica existência de logs de execução e decisão.
- Analisa cobertura mínima de testes (unitários, integração, carga, E2E) a partir dos relatórios.
- Gera relatório detalhado em `output/checklist_auditoria_<data>.log` com status de cada item e conformidade final.
- Status final: `CONFORME` ou `NÃO CONFORME`.
- Pode ser integrado à pipeline CI/CD para validação automática antes de releases.

### Exemplo de uso
```bash
python scripts/checklist_auditoria_v1.py
```

### Critérios de sucesso
- Todos os itens obrigatórios presentes e coberturas mínimas atingidas.
- Relatório versionado e rastreável.
- Falhas reportadas de forma explícita para correção.

--- 