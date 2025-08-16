from locust import HttpUser, task, constant_pacing
import random

class StatusStressUser(HttpUser):
    wait_time = constant_pacing(0.2)

    @task
    def get_status(self):
        trace_id = f"trace-{random.randint(1, 1000)}"
        with self.client.get(f"/status/{trace_id}", catch_response=True) as response:
            if response.status_code == 200 and 'status' in response.text:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 