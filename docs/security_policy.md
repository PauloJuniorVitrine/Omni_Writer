# Política de Segurança e Privacidade — Omni Writer

## Autenticação e Autorização
- APIs protegidas por token JWT (verifique validade e escopo)
- Controle de acesso por perfil de usuário

## Tratamento de Dados Sensíveis
- Nunca registre senhas, tokens ou chaves de API em logs
- Variáveis sensíveis devem ser definidas via `.env` e nunca hardcoded
- Dados de usuários e artigos são armazenados apenas localmente

## Logs e Retenção
- Logs de operação e decisão são armazenados em `/logs/`
- Logs não devem conter dados pessoais identificáveis
- Retenção mínima: 90 dias, com rotação semanal

## Incidentes de Segurança
- Detecção automática de falhas críticas via logs
- Procedimento de resposta: isolar serviço, analisar logs, comunicar responsável
- Reporte de incidente: security@empresa.com

## Conformidade
- Alinhado à LGPD/GDPR: direito ao esquecimento, portabilidade e consentimento
- Auditoria periódica de acessos e integrações 