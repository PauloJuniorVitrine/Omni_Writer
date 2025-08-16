# scripts/run_e2e_tests.ps1
# Executa os testes E2E Playwright
npx playwright test tests/e2e/test_generate_content.spec.ts --reporter=list 