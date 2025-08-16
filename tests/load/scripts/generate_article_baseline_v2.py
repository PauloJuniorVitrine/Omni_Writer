from locust import HttpUser, task, between

class GenerateArticleUser(HttpUser):
    wait_time = between(1, 3)
    @task
    def generate_article(self):
        payload = {
            "api_key": "sk-teste",
            "model_type": "openai",
            "prompts": [{"text": "prompt celery", "index": 0}]
        }
        headers = {"Authorization": "Bearer token_valido"}
        self.client.post("/generate", json=payload, headers=headers) 