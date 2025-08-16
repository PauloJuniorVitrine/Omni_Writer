from locust import HttpUser, task, between
import random

class WebhookBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def register_webhook(self):
        url = f"http://localhost:{8000 + random.randint(1, 10)}"
        payload = {"url": url}
        with self.client.post("/webhook", data=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 