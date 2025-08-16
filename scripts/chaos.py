"""
Script de Chaos Engineering para simulação de falhas no omni_gerador_artigos.

Uso:
  python scripts/chaos.py redis      # Simula indisponibilidade do Redis
  python scripts/chaos.py api        # Simula falha nas APIs externas
  python scripts/chaos.py disk       # Simula falha de permissão de escrita
"""
import sys
import os
import requests

def simulate_redis_failure():
    print("[Chaos] Simulando indisponibilidade do Redis...")
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.shutdown()
    except Exception as e:
        print(f"[Chaos] Redis já está indisponível ou não pode ser parado: {e}")

def simulate_api_failure():
    print("[Chaos] Simulando falha nas APIs externas...")
    # Substitui variáveis de ambiente para URLs inválidas
    os.environ['OPENAI_API_URL'] = 'http://localhost:9999/fail'
    os.environ['DEEPSEEK_API_URL'] = 'http://localhost:9999/fail'
    print("[Chaos] Variáveis de ambiente de API alteradas para endpoints inválidos.")

def simulate_disk_failure():
    print("[Chaos] Simulando falha de permissão de escrita em disco...")
    target_dir = os.getenv('ARTIGOS_DIR', 'artigos_gerados')
    try:
        os.chmod(target_dir, 0o400)
        print(f"[Chaos] Permissão removida de {target_dir}.")
    except Exception as e:
        print(f"[Chaos] Falha ao alterar permissão: {e}")

def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    if sys.argv[1] == 'redis':
        simulate_redis_failure()
    elif sys.argv[1] == 'api':
        simulate_api_failure()
    elif sys.argv[1] == 'disk':
        simulate_disk_failure()
    else:
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main() 