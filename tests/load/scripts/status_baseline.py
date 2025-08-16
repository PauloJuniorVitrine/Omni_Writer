from locust import HttpUser, task, between
import random

class StatusBaselineUser(HttpUser):
    wait_time = between(2, 5)

    @task
    def get_status(self):
        # Para o teste, simula trace_ids variados
        trace_id = f"trace-{random.randint(1, 10)}"
        with self.client.get(f"/status/{trace_id}", catch_response=True) as response:
            if response.status_code == 200 and 'status' in response.text:
                response.success()
            else:
                response.failure(f"Status: {response.status_code}, Body: {response.text}") 