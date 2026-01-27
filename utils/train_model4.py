# train_model4.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model4 import HTTPAnomalyModel
from utils.http_collector import collect_http_features
from utils.traffic_collector import capture_traffic

model = HTTPAnomalyModel()

urls = [
    ("https://google.com", "google.com"),
    ("https://github.com", "github.com"),
    ("https://microsoft.com", "microsoft.com"),
    ("https://amazon.com", "amazon.com"),
    ("https://cloudflare.com", "cloudflare.com")
]

dataset = []
for url, domain in urls:
    print(f"[*] Training on {domain}...")
    f = collect_http_features(url)
    t = capture_traffic(domain, duration=2)
    f.update(t)
    dataset.append(f)

model.train(dataset)

