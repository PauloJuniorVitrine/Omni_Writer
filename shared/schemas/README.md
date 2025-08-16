# Schemas Compartilhados OmniWriter

Este diretório contém os contratos JSON Schema derivados do OpenAPI para garantir integração e validação consistente entre backend e frontend.

## Como usar

- **Frontend:**
  - Pode ser usado para validação dinâmica de dados (ex: com ajv, zod-to-json-schema, etc).
  - Permite geração automática de tipos TypeScript (ex: com `json-schema-to-typescript`).
- **Backend:**
  - Referência para validação de payloads e documentação.

## Versionamento
- Sempre que um schema for alterado, criar uma nova versão (`blog.v2.json`, etc) e atualizar o changelog.
- Não sobrescrever schemas antigos sem validação e aprovação.

## Segurança
- Endpoints sensíveis exigem autenticação Bearer (exemplo: `Authorization: Bearer token_valido`).
- Veja exemplos na documentação OpenAPI.

## Schemas disponíveis
- `blog.json` / `blog_create.json`
- `prompt.json` / `prompt_create.json`
- `feedback.json`
- `error.json`

## Exemplo de uso (TypeScript)
```ts
import blogSchema from './schemas/blog.json';
import { FromSchema } from 'json-schema-to-ts';
type Blog = FromSchema<typeof blogSchema>;
``` 