#!/usr/bin/env python3
import base64
import json
import os
from urllib.request import Request, urlopen

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_USER = os.getenv("API_USER", "metrics")
API_PASSWORD = os.getenv("API_PASSWORD", "change-me-api")

def open_api(path: str):
    token = base64.b64encode(f"{API_USER}:{API_PASSWORD}".encode()).decode()
    req = Request(f"{API_URL}{path}", headers={"Authorization": f"Basic {token}"})
    return urlopen(req, timeout=5)

for path in ["/tables/vlans", "/events/metrics_event"]:
    with open_api(path) as resp:
        print(f"\n### {path}")
        print(json.dumps(json.load(resp), ensure_ascii=False, indent=2))
