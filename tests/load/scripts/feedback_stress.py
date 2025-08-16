from locust import HttpUser, task, constant_pacing
import random

class FeedbackStressUser(HttpUser):
    wait_time = constant_pacing(0.2)

    @task
    def send_feedback(self):
        payload = {
            "article_id": random.randint(1, 10000),
            "feedback": random.choice(["positivo", "negativo", "neutro"]),
            "comentario": f"Comentário stress {random.randint(1,100000)}"
        }
        with self.client.post("/feedback", data=payload, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 