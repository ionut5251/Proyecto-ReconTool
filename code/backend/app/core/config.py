import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BACKEND_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_ROOT = BACKEND_ROOT.parent / "frontend"
LOGO_PATH = FRONTEND_ROOT / "img" / "recontool-logo.png"
DATA_DIR = BACKEND_ROOT / "data"
VULNERABILITIES_DB_PATH = DATA_DIR / "vulnerabilities.json"
SCREENSHOTS_DIR = DATA_DIR / "screenshots"

NMAP_ARGUMENTS = "-sS -sV -O --open -Pn -n -T4"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_RESULTS_PER_QUERY = int(os.getenv("NVD_RESULTS_PER_QUERY", "5"))
NVD_REQUEST_DELAY_SEC = float(os.getenv("NVD_REQUEST_DELAY_SEC", "6.2"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

AI_PROVIDER = os.getenv("AI_PROVIDER", "auto").lower()

REPORT_AUDITOR_NAME = os.getenv("REPORT_AUDITOR_NAME", "ReconTool — Auditoría automática")
