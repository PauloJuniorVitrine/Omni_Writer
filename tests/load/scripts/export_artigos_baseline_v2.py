from locust import HttpUser, task, between

class ExportArtigosUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def export_artigos(self):
        self.client.get("/export_artigos_csv") 