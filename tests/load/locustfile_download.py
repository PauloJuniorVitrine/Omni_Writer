from locust import HttpUser, task, between
from utils_load import log_response_time
import time
import random

class DownloadUser(HttpUser):
    """Usuário Locust para carga nos endpoints /download e /download_multi."""
    wait_time = between(1, 2)

    @task(2)
    def download_zip(self):
        start = time.time()
        with self.client.get("/download", catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/download", resp.status_code)
            if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("application/zip"):
                resp.success()
            else:
                resp.failure(f"/download falhou: {resp.status_code}, Content-Type: {resp.headers.get('Content-Type')}")

    @task(1)
    def download_zip_multi(self):
        start = time.time()
        with self.client.get("/download_multi", catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/download_multi", resp.status_code)
            if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("application/zip"):
                resp.success()
            else:
                resp.failure(f"/download_multi falhou: {resp.status_code}, Content-Type: {resp.headers.get('Content-Type')}")

    @task(1)
    def download_inexistente(self):
        """Tenta baixar arquivo inexistente para testar resposta de erro controlado."""
        idx = random.randint(10000, 99999)
        start = time.time()
        with self.client.get(f"/download?file=nao_existe_{idx}.zip", catch_response=True) as resp:
            end = time.time()
            log_response_time(start, end, "/download[inexistente]", resp.status_code)
            if resp.status_code in (302, 404, 400):
                resp.success()
            else:
                resp.failure(f"Download inexistente: {resp.status_code}, Content-Type: {resp.headers.get('Content-Type')}") 