"""
Config — persistent storage for GhostRecon settings (API key, preferences).
Stored at: ~/.ghostrecon/config.json
"""
import os
import json

CONFIG_DIR  = os.path.join(os.path.expanduser("~"), ".ghostrecon")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


def _load() -> dict:
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_api_key() -> str | None:
    """Return saved NVIDIA API key, or None."""
    return _load().get("nvidia_api_key")


def set_api_key(key: str):
    """Persist an NVIDIA API key."""
    data = _load()
    data["nvidia_api_key"] = key.strip()
    _save(data)


def remove_api_key():
    """Delete the stored API key."""
    data = _load()
    data.pop("nvidia_api_key", None)
    _save(data)


def get(key: str, default=None):
    return _load().get(key, default)


def set_value(key: str, value):
    data = _load()
    data[key] = value
    _save(data)
