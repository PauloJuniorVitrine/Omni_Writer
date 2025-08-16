# Testes de Acessibilidade (a11y) e Responsividade – Omni Writer

## Critérios de Acessibilidade (a11y)
- Todos os campos de formulário possuem `label` ou `aria-label`.
- Botões e links possuem texto descritivo e/ou `aria-label`.
- Navegação por teclado garantida (tabindex, foco visível).
- Contraste mínimo recomendado (WCAG AA): 4.5:1 para texto normal.
- Uso de roles semânticos (`role="button"`, `role="main"`, etc) quando necessário.
- Feedback visual para erros, loading e sucesso.
- Mensagens de erro são lidas por leitores de tela (ex: `aria-live`).

### Ferramentas recomendadas
- [axe-core](https://www.deque.com/axe/): integração com Jest, Playwright, Cypress
- [jest-axe](https://github.com/nickcolley/jest-axe): validação automatizada em testes unitários
- [Playwright](https://playwright.dev/) + [axe-playwright](https://github.com/abhinaba-ghosh/axe-playwright)
- [Lighthouse](https://developers.google.com/web/tools/lighthouse)

### Exemplo de teste automatizado (jest-axe)
```tsx
import { render } from '@testing-library/react';
import { axe } from 'jest-axe';
import { Blogs } from '../../pages/Blogs';

test('Blogs page is accessible', async () => {
  const { container } = render(<Blogs />);
  const results = await axe(container);
  expect(results).toHaveNoViolations();
});
```

---

## Critérios de Responsividade
- Layouts usam flexbox/grid e adaptam-se a diferentes larguras de tela.
- Componentes possuem breakpoints para mobile/tablet/desktop.
- Fontes e espaçamentos relativos (`em`, `%`, `rem`).
- Testes manuais em diferentes tamanhos de tela (devtools, Playwright, Cypress).

### Ferramentas recomendadas
- [Playwright](https://playwright.dev/) e [Cypress](https://www.cypress.io/): simulação de múltiplos viewports
- Devtools do navegador (modo responsivo)

### Exemplo de teste automatizado (Playwright)
```ts
import { test, expect } from '@playwright/test';

test('Dashboard responsivo', async ({ page }) => {
  await page.goto('/dashboard');
  await page.setViewportSize({ width: 375, height: 667 }); // mobile
  await expect(page.locator('h1')).toBeVisible();
});
```

---

## Edge Cases e Recomendações
- Testar formulários com campos vazios, inválidos e preenchimento por teclado
- Simular ausência de dados, erros de API, loading prolongado
- Garantir foco visível e navegação por tab
- Validar contraste e legibilidade em todos os temas
- Documentar e corrigir qualquer violação encontrada

---

> Para cobertura total, recomenda-se integrar testes a11y e responsividade ao pipeline CI/CD e revisar periodicamente com ferramentas automatizadas e manuais. 