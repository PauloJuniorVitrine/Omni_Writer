from locust import HttpUser, task, between
import random

class FeedbackBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def send_feedback(self):
        payload = {
            "article_id": random.randint(1, 100),
            "feedback": random.choice(["positivo", "negativo", "neutro"]),
            "comentario": f"Comentário baseline {random.randint(1,1000)}"
        }
        with self.client.post("/feedback", data=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 