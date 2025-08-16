"""
Module for webhook registration and notification.
Handles saving, loading, and notifying registered webhooks.
"""
import os
import json as pyjson
from typing import List, Dict, Any
import requests

WEBHOOKS_FILE = 'webhooks.json'

def load_webhooks() -> List[str]:
    """
    Loads the list of registered webhooks from the file.
    """
    if os.path.exists(WEBHOOKS_FILE):
        try:
            with open(WEBHOOKS_FILE, 'r') as f:
                return pyjson.load(f)
        except pyjson.JSONDecodeError:
            return []
    return []

def save_webhook(url: str) -> None:
    """
    Saves a new webhook to the persisted list.
    """
    webhooks = load_webhooks()
    if url not in webhooks:
        webhooks.append(url)
        with open(WEBHOOKS_FILE, 'w') as f:
            pyjson.dump(webhooks, f)

def notify_webhooks(payload: Dict[str, Any]) -> None:
    """
    Notifies all registered webhooks with the provided payload.
    """
    webhooks = load_webhooks()
    for url in webhooks:
        try:
            requests.post(url, json=payload, timeout=3)
        except Exception:
            continue 