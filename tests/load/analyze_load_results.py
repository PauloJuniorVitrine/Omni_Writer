import os
import csv
import glob
from datetime import datetime

THRESHOLDS = {
    'response_time_ms': 800,
    'fail_rate': 0.02,  # 2%
}

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
REPORT_MD = os.path.join(RESULTS_DIR, f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md')


def analyze_csv(file_path):
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        total = 0
        fail = 0
        slow = 0
        response_times = []
        for row in reader:
            if 'Average Response Time' in row:
                try:
                    rt = float(row['Average Response Time'])
                    response_times.append(rt)
                    total += int(row['Request Count'])
                    fail += int(row['Failure Count'])
                    if rt > THRESHOLDS['response_time_ms']:
                        slow += int(row['Request Count'])
                except Exception:
                    continue
        fail_rate = fail / total if total else 0
        slow_rate = slow / total if total else 0
        return {
            'file': os.path.basename(file_path),
            'total': total,
            'fail': fail,
            'fail_rate': fail_rate,
            'slow_rate': slow_rate,
            'avg_response_time': sum(response_times)/len(response_times) if response_times else 0,
        }

def main():
    csv_files = glob.glob(os.path.join(RESULTS_DIR, '*.csv'))
    summary = []
    for f in csv_files:
        res = analyze_csv(f)
        summary.append(res)
    # Geração de relatório
    with open(REPORT_MD, 'w', encoding='utf-8') as f:
        f.write(f"# Relatório de Testes de Carga - {datetime.now().isoformat()}\n\n")
        f.write("| Arquivo | Total Req | Fails | % Fails | % >800ms | Avg Resp (ms) | ALERTA |\n")
        f.write("|---------|-----------|-------|---------|----------|--------------|--------|\n")
        for s in summary:
            alerta = []
            if s['fail_rate'] > THRESHOLDS['fail_rate']:
                alerta.append('FAIL RATE')
            if s['slow_rate'] > 0.2:
                alerta.append('SLOW RESP')
            f.write(f"| {s['file']} | {s['total']} | {s['fail']} | {s['fail_rate']:.2%} | {s['slow_rate']:.2%} | {s['avg_response_time']:.1f} | {'; '.join(alerta) or 'OK'} |\n")
    print(f"Relatório gerado: {REPORT_MD}")

if __name__ == '__main__':
    main() 