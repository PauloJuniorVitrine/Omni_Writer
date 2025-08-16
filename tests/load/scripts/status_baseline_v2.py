from locust import HttpUser, task, between

class StatusUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def check_status(self):
        trace_id = "celery-integration-test"
        self.client.get(f"/status/{trace_id}") 