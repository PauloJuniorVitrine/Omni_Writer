from locust import HttpUser, task, between

class DownloadUser(HttpUser):
    wait_time = between(1, 2)
    @task
    def download_article(self):
        self.client.get("/download") 