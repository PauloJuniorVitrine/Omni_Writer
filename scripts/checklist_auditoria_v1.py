import os
import glob
import datetime

ARQUIVOS_OBRIGATORIOS = [
    'README.md', 'requirements.txt', '.env.example', '.eslintrc.json', 'pyproject.toml',
    'CHANGELOG.md', 'docs/explanation.md', 'docs/interface_fluxo_ux.json', 'docs/a11y_responsividade.md'
]
DIRETORIOS_OBRIGATORIOS = [
    'tests', 'logs', 'docs', 'shared', 'output'
]
RELATORIOS_COBERTURA = [
    'coverage/.coverage', 'htmlcov/index.html', 'unit_coverage_report.log', 'test_results_storage.log'
]
LOGS_EXECUCAO = [
    'logs/exec_trace/', 'logs/decisions_' # prefixo
]

MIN_COBERTURA_UNIT = 98
MIN_COBERTURA_INT = 95
MIN_COBERTURA_CARGA = 90
MIN_COBERTURA_E2E = 85

# Função utilitária para validar presença de arquivos

def check_artefatos():
    faltantes = [f for f in ARQUIVOS_OBRIGATORIOS if not os.path.isfile(f)]
    return faltantes

def check_diretorios():
    faltantes = [d for d in DIRETORIOS_OBRIGATORIOS if not os.path.isdir(d)]
    return faltantes

def check_logs():
    logs_faltantes = []
    for l in LOGS_EXECUCAO:
        if l.endswith('/'):
            if not os.path.isdir(l) or not os.listdir(l):
                logs_faltantes.append(l)
        else:
            if not glob.glob(l + '*'):
                logs_faltantes.append(l)
    return logs_faltantes

def check_cobertura():
    # Busca nos logs/relatórios por percentuais
    cobertura = {'unit': 0, 'integration': 0, 'load': 0, 'e2e': 0}
    try:
        with open('unit_coverage_report.log') as f:
            for line in f:
                if 'Unitários' in line:
                    cobertura['unit'] = int(line.split('≥')[1].split('%')[0].strip())
                if 'Integração' in line:
                    cobertura['integration'] = int(line.split('≥')[1].split('%')[0].strip())
                if 'Carga' in line:
                    cobertura['load'] = int(line.split('≥')[1].split('%')[0].strip())
                if 'E2E' in line:
                    cobertura['e2e'] = int(line.split('≥')[1].split('%')[0].strip())
    except Exception:
        pass
    return cobertura

def main():
    now = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    relatorio_path = f'output/checklist_auditoria_{now}.log'
    os.makedirs('output', exist_ok=True)
    faltam_artefatos = check_artefatos()
    faltam_dirs = check_diretorios()
    faltam_logs = check_logs()
    cobertura = check_cobertura()
    with open(relatorio_path, 'w', encoding='utf-8') as f:
        f.write(f'# Checklist de Auditoria — {now} UTC\n')
        f.write('## Artefatos Obrigatórios\n')
        for arq in ARQUIVOS_OBRIGATORIOS:
            status = 'OK' if arq not in faltam_artefatos else 'FALTA'
            f.write(f'- {arq}: {status}\n')
        f.write('\n## Diretórios Essenciais\n')
        for d in DIRETORIOS_OBRIGATORIOS:
            status = 'OK' if d not in faltam_dirs else 'FALTA'
            f.write(f'- {d}: {status}\n')
        f.write('\n## Logs de Execução\n')
        for l in LOGS_EXECUCAO:
            status = 'OK' if l not in faltam_logs else 'FALTA'
            f.write(f'- {l}: {status}\n')
        f.write('\n## Cobertura de Testes\n')
        f.write(f"- Unitários: {cobertura['unit']}% (mínimo {MIN_COBERTURA_UNIT}%)\n")
        f.write(f"- Integração: {cobertura['integration']}% (mínimo {MIN_COBERTURA_INT}%)\n")
        f.write(f"- Carga: {cobertura['load']}% (mínimo {MIN_COBERTURA_CARGA}%)\n")
        f.write(f"- E2E: {cobertura['e2e']}% (mínimo {MIN_COBERTURA_E2E}%)\n")
        f.write('\n## Status Final\n')
        if not faltam_artefatos and not faltam_dirs and not faltam_logs and all([
            cobertura['unit'] >= MIN_COBERTURA_UNIT,
            cobertura['integration'] >= MIN_COBERTURA_INT,
            cobertura['load'] >= MIN_COBERTURA_CARGA,
            cobertura['e2e'] >= MIN_COBERTURA_E2E
        ]):
            f.write('STATUS: CONFORME\n')
        else:
            f.write('STATUS: NÃO CONFORME\n')
    print(f'Relatório de checklist gerado em: {relatorio_path}')

if __name__ == '__main__':
    main() 