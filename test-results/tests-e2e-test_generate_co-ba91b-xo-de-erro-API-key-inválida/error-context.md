# Test info

- Name: Jornada E2E: Geração de Conteúdo >> Fluxo de erro: API key inválida
- Location: C:\Users\SEDUC\Desktop\PROJETOS\omni_gerador_artigos\tests\e2e\test_generate_content.spec.ts:97:7

# Error details

```
TimeoutError: page.waitForSelector: Timeout 10000ms exceeded.
Call log:
  - waiting for locator('[data-testid="error-message"]') to be visible

    at C:\Users\SEDUC\Desktop\PROJETOS\omni_gerador_artigos\tests\e2e\test_generate_content.spec.ts:113:16
```

# Page snapshot

```yaml
- banner:
  - img "Artigos"
  - heading "Omni Gerador de Artigos" [level=1]
  - button "Alternar modo claro/escuro": 🌙
  - button "Ativar/desativar som": 🔈
- main:
  - heading "Omni Gerador de Artigos" [level=1]
  - heading "Instâncias (máx. 15, até 7 prompts por instância)" [level=2]
  - text: Nome da instância
  - textbox "Nome da instância"
  - text: Modelo da instância
  - combobox "Modelo da instância":
    - option "OpenAI" [selected]
    - option "DeepSeek"
  - text: Chave da instância
  - textbox "Chave da instância"
  - text: "Prompts desta instância (máx. 7, um por linha):"
  - textbox "Prompts desta instância (máx. 7, um por linha):"
  - text: "Ou carregue um arquivo .txt ou .csv (máx. 7 prompts): Arquivo de prompts"
  - button "Arquivo de prompts"
  - button "Adicionar Instância"
  - list:
    - listitem:
      - text: Instância Erro [openai] inva...-key 1. Teste E2E fluxo real.
      - button "Editar"
      - button "Remover"
  - heading "Configuração" [level=2]
  - button "Limpar Tudo"
  - button "🚀 Gerar em Lote"
- button "Como usar?": ❓
```

# Test source

```ts
   13 | // Utilitários
   14 | async function preencherInstancia(page: Page, nome: string, apiKey: string, modelType: string, prompt: string) {
   15 |   await page.fill('[data-testid="instance-name"]', nome);
   16 |   await page.selectOption('[data-testid="model-type"]', modelType);
   17 |   await page.fill('[data-testid="api-key"]', apiKey);
   18 |   await page.fill('[data-testid="prompts"]', prompt);
   19 | }
   20 |
   21 | async function registrarWebhook(page: Page, url: string) {
   22 |   await page.evaluate(async (webhookUrl) => {
   23 |     await fetch('/webhook', {
   24 |       method: 'POST',
   25 |       headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
   26 |       body: `url=${encodeURIComponent(webhookUrl)}`
   27 |     });
   28 |   }, url);
   29 | }
   30 |
   31 | async function realizarDownload(page: Page): Promise<Download> {
   32 |   const [download] = await Promise.all([
   33 |     page.waitForEvent('download'),
   34 |     page.click('[data-testid="download-link"]'),
   35 |   ]);
   36 |   return download;
   37 | }
   38 |
   39 | test.describe('Jornada E2E: Geração de Conteúdo', () => {
   40 |   test('Fluxo principal: geração, status, SSE, download, a11y e visual', async ({ page }) => {
   41 |     const logs: string[] = [];
   42 |     page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
   43 |     page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
   44 |     page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
   45 |     await page.goto(BASE_URL);
   46 |     await expect(page).toHaveTitle(/Omni Gerador de Artigos/i);
   47 |
   48 |     // Diagnóstico: salvar HTML e screenshot iniciais
   49 |     const html = await page.content();
   50 |     require('fs').writeFileSync('diagnostico_inicial.html', html);
   51 |     await page.screenshot({ path: 'diagnostico_inicial.png', fullPage: true });
   52 |
   53 |     // Acessibilidade inicial
   54 |     const accessibilityScan = await new AxeBuilder({ page }).analyze();
   55 |     expect(accessibilityScan.violations).toEqual([]);
   56 |
   57 |     // Esperar campo de instância estar disponível
   58 |     await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
   59 |     // Preencher e adicionar instância
   60 |     await preencherInstancia(page, 'Instância E2E', API_KEY, MODEL_TYPE, PROMPT);
   61 |     await page.click('button[type="submit"]:has-text("Adicionar Instância")');
   62 |     // Aguarda a instância aparecer na lista
   63 |     await page.waitForSelector('#instancias_lista li', { timeout: 3000 });
   64 |     await registrarWebhook(page, mockWebhookUrl);
   65 |
   66 |     // Gerar artigos
   67 |     await page.click('[data-testid="submit-btn"]');
   68 |     // Diagnóstico: salvar HTML e screenshot pós-envio
   69 |     const htmlPosEnvio = await page.content();
   70 |     require('fs').writeFileSync('diagnostico_pos_envio.html', htmlPosEnvio);
   71 |     await page.screenshot({ path: 'diagnostico_pos_envio.png', fullPage: true });
   72 |     // Esperar feedback visual de processamento ou download
   73 |     await page.waitForSelector('[data-testid="download-link"], #progress-bar, [data-testid="status-message"]', { timeout: 15000 });
   74 |
   75 |     // Snapshot intermediário
   76 |     await expect(page).toHaveScreenshot('pos-envio.png', { fullPage: true });
   77 |
   78 |     // Status de processamento
   79 |     await expect(page.locator('[data-testid="download-link"]')).toBeVisible({ timeout: 60000 });
   80 |     await expect(page.locator('text=/Concluído|Sucesso|Download/i')).toBeVisible();
   81 |
   82 |     // Download
   83 |     const download = await realizarDownload(page);
   84 |     const downloadPath = await download.path();
   85 |     expect(downloadPath).toBeTruthy();
   86 |
   87 |     // Snapshot final
   88 |     await expect(page).toHaveScreenshot('final-geracao.png', { fullPage: true });
   89 |
   90 |     // Acessibilidade final
   91 |     const a11yFinal = await new AxeBuilder({ page }).analyze();
   92 |     expect(a11yFinal.violations).toEqual([]);
   93 |
   94 |     require('fs').writeFileSync('diagnostico_logs_fluxo_principal.log', logs.join('\n'));
   95 |   });
   96 |
   97 |   test('Fluxo de erro: API key inválida', async ({ page }) => {
   98 |     const logs: string[] = [];
   99 |     page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
  100 |     page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
  101 |     page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
  102 |     await page.goto(BASE_URL);
  103 |     await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
  104 |     await preencherInstancia(page, 'Instância Erro', INVALID_API_KEY, MODEL_TYPE, PROMPT);
  105 |     await page.click('button[type="submit"]:has-text("Adicionar Instância")');
  106 |     await registrarWebhook(page, mockWebhookUrl);
  107 |     await page.click('[data-testid="submit-btn"]');
  108 |     // Diagnóstico: salvar HTML e screenshot pós-envio erro
  109 |     const htmlErro = await page.content();
  110 |     require('fs').writeFileSync('diagnostico_erro_envio.html', htmlErro);
  111 |     await page.screenshot({ path: 'diagnostico_erro_envio.png', fullPage: true });
  112 |     // Esperar mensagem de erro
> 113 |     await page.waitForSelector('[data-testid="error-message"]', { timeout: 10000 });
      |                ^ TimeoutError: page.waitForSelector: Timeout 10000ms exceeded.
  114 |     await expect(page).toHaveScreenshot('erro-api-key.png', { fullPage: true });
  115 |
  116 |     require('fs').writeFileSync('diagnostico_logs_fluxo_erro.log', logs.join('\n'));
  117 |   });
  118 |
  119 |   test('E2E fluxo real: submit completo', async ({ page }) => {
  120 |     const logs: string[] = [];
  121 |     page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
  122 |     page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
  123 |     page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
  124 |     try {
  125 |       await page.goto(BASE_URL);
  126 |       await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
  127 |       await page.fill('[data-testid="instance-name"]', 'Instância E2E');
  128 |       await page.selectOption('[data-testid="model-type"]', MODEL_TYPE);
  129 |       await page.fill('[data-testid="api-key"]', API_KEY);
  130 |       await page.fill('[data-testid="prompts"]', PROMPT);
  131 |       await page.click('button[type="submit"]:has-text("Adicionar Instância")');
  132 |       // Aguarda a instância aparecer na lista
  133 |       await page.waitForSelector('#instancias_lista li', { timeout: 3000 });
  134 |       // Clica no botão real de submit
  135 |       await page.click('[data-testid="submit-btn"]');
  136 |       // Espera resposta ou erro
  137 |       await page.waitForTimeout(5000);
  138 |     } catch (e) {
  139 |       logs.push(`[erro] ${e}`);
  140 |     } finally {
  141 |       fs.writeFileSync('diagnostico_e2e_fluxo_real.log', logs.join('\n'));
  142 |     }
  143 |   });
  144 | }); 
```