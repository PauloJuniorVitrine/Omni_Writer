# Proposta de Interface Moderna — Omni Writer

## 1. Estrutura Geral
- Dashboard com menu lateral (Blogs, Geração, Exportação, Feedback, Tokens, Logs, Configurações)
- Header fixo com branding, toggle de tema, usuário
- Área principal com cards, tabelas, formulários e painéis de status

## 2. Módulos e Fluxos
- Gestão CRUD de blogs, categorias, clusters, prompts (cards/tabelas, ações inline, modais de confirmação)
- Upload drag & drop de prompts, feedback visual imediato
- Geração de artigos com formulário validado, barra de progresso (SSE), download ZIP/CSV
- Painel de status/logs com filtros, busca, exportação, badges de status
- Feedback do usuário com formulário validado, histórico, gráficos de satisfação
- Gestão de tokens com rotação/revogação, modal de confirmação, logs

## 3. Identidade Visual e Tema
- Paleta de cores consistente, tipografia padronizada, tokens de tema
- Componentes reutilizáveis: Button, Card, Modal, Badge, Tooltip
- Branding/logotipo no header
- Toggle de dark/light mode

## 4. UX, Acessibilidade e Microinterações
- Layout responsivo, mobile first, acessível (WCAG 2.1)
- Loader/spinner, toasts, modais, validação visual instantânea
- Tooltips, agrupamento de campos, etapas progressivas (wizard)
- Onboarding/tour guiado para novos usuários

## 5. Segurança Visual
- Modais de confirmação para ações críticas, rollback/desfazer
- Feedback visual para falhas, bloqueios temporários, status persistente
- Painel de logs/auditoria visual

## 6. Benchmarking
- Inspirado em Stripe, Supabase, Notion: dashboard modular, feedbacks modernos, identidade forte, acessibilidade e microinterações

## 7. Estrutura Técnica Recomendada
- `/ui/theme/`: tokens de tema (colors, typography, shadows)
- `/ui/components/`: componentes base
- `/ui/layout/`: Header, Branding, Sidebar
- `/docs/`: documentação, benchmarking, snapshots, logs

## 8. Resumo
A proposta cobre 100% das funcionalidades do backend, garante segurança, rastreabilidade, acessibilidade e identidade visual, alinhada aos melhores padrões de SaaS técnico.

# Proposta de Interface – Incremento CRUD

## Páginas Geradas

### Blogs
- Gerenciamento de blogs e nichos
- Lista mock de blogs
- Botão para novo blog
- Placeholders para editar/excluir
- Componentes: Card, Button

### Categorias
- Gerenciamento de categorias
- Lista mock de categorias
- Botão para nova categoria
- Placeholders para editar/excluir
- Componentes: Card, Button

### Clusters
- Gerenciamento de clusters
- Lista mock de clusters
- Botão para novo cluster
- Placeholders para editar/excluir
- Componentes: Card, Button

## Cobertura de Testes Unitários (STEP-004)

- **Blogs**: renderização, lista mock, lista vazia, clique em criar/editar/excluir, snapshot, edge case
- **Categorias**: renderização, lista mock, lista vazia, clique em criar/editar/excluir, snapshot, edge case
- **Clusters**: renderização, lista mock, lista vazia, clique em criar/editar/excluir, snapshot, edge case

## Incremento: Prompts e Geração de Artigos (STEP-005)

### Prompts
- Gerenciamento de prompts (mock)
- Botão para novo prompt
- Placeholders para editar/excluir
- Componentes: Card, Button
- Testes: renderização, lista mock, lista vazia, cliques, snapshot, edge case

### Geração de Artigos
- Formulário mock para geração
- Botão de gerar, status/resultados mock
- Componentes: Card, Button
- Testes: renderização, preenchimento, clique, status/resultados, snapshot, edge case

## Incremento: Feedback e Exportação (STEP-006)

### Feedback
- Formulário mock para envio
- Listagem mock de feedbacks
- Placeholders para integração backend
- Componentes: Card, Button
- Testes: renderização, envio, lista mock, edge case, snapshot

### Exportação
- Painel de exportação de artigos e prompts
- Botões de exportação, status mock
- Componentes: Card, Button
- Testes: renderização, exportação, status mock, edge case, snapshot

## Incremento: Status/Logs, Tokens e Onboarding (STEP-007)

### Status/Logs
- Painel de status do sistema
- Listagem mock de logs, filtros
- Placeholders para SSE/integr. backend
- Componentes: Card, Button
- Testes: renderização, filtro, clique, edge case, snapshot

### Tokens
- Painel de gestão de tokens
- Listagem mock, rotação/revogação (placeholders)
- Componentes: Card, Button
- Testes: renderização, clique, edge case, snapshot

### Onboarding
- Componente/página de tour guiado
- Instruções passo a passo, navegação
- Placeholders para integração futura
- Componentes: Card, Button
- Testes: renderização, navegação, edge case, snapshot

## Próximos Passos
- Implementar formulários/modais reais
- Integração com backend
- Testes unitários e snapshots
- Expansão para demais módulos (Prompts, Geração, Feedback, etc.) 