# train_model4.py
from models.model4 import HTTPAnomalyModel
from utils.http_collector import collect_http_features

model = HTTPAnomalyModel()

urls = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://cloudflare.com"
]

dataset = [collect_http_features(url) for url in urls]
model.train(dataset)
