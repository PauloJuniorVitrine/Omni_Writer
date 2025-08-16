from locust import HttpUser, task, between
import uuid

class GenerateArticleWorkerUser(HttpUser):
    wait_time = between(1, 3)
    @task
    def generate_article_worker(self):
        payload = {
            "api_key": "sk-teste",
            "model_type": "openai",
            "prompts": [{"text": "prompt celery", "index": 0}]
        }
        headers = {"Authorization": "Bearer token_valido"}
        trace_id = str(uuid.uuid4())
        self.client.post("/generate", json=payload, headers=headers, params={"trace_id": trace_id}) 