import threading
import http.server
import socketserver
import requests
import time
import pytest
from app.app_factory import create_app
import json

PORT = 8001
received_payload = {}

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        received_payload['data'] = post_data
        self.send_response(200)
        self.end_headers()
    def log_message(self, format, *args):
        return

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.mark.integration
def test_webhook_notification(monkeypatch):
    # Sobe servidor HTTP local para simular webhook
    handler = WebhookHandler
    httpd = socketserver.TCPServer(("", PORT), handler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    try:
        # Registra webhook
        url = f"http://localhost:{PORT}"
        with app.test_client() as client:
            resp = client.post("/webhook", data={"url": url})
            assert resp.status_code == 200
        # Dispara geração Celery
        config = {"api_key": "sk-teste", "model_type": "openai", "prompts": [{"text": "webhook test", "index": 0}]}
        async_result = gerar_artigos_task.apply_async(args=[config], kwargs={"trace_id": "webhook-integration-test"})
        timeout = 60
        for _ in range(timeout):
            if async_result.ready():
                break
            time.sleep(1)
        assert async_result.ready(), "Tarefa Celery não finalizou em tempo hábil"
        # Aguarda notificação
        for _ in range(10):
            if received_payload.get('data'):
                break
            time.sleep(1)
        assert received_payload.get('data'), "Webhook não recebeu notificação"
    finally:
        httpd.shutdown()
        server_thread.join() 