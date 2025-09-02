import json
import os

def load_config():
    config_path = os.path.join("config", "config.json")
    with open(config_path) as f:
        return json.load(f)

