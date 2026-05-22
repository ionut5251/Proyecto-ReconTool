import json

from app.core.config import VULNERABILITIES_DB_PATH


def load_vulnerabilities_db() -> dict:
    with open(VULNERABILITIES_DB_PATH, encoding="utf-8") as file:
        return json.load(file)
