from locust import HttpUser, task, between

class WebhookUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def register_webhook(self):
        data = {"url": "https://exemplo.com"}
        headers = {"Authorization": "Bearer token_valido"}
        self.client.post("/webhook", data=data, headers=headers) 