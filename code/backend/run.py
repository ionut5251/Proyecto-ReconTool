import sys


def _check_dependencies() -> None:
    required = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn[standard]"),
        ("nmap", "python-nmap"),
        ("httpx", "httpx"),
        ("dotenv", "python-dotenv"),
        ("pydantic", "pydantic"),
    ]
    missing = []
    for module, package in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if not missing:
        return

    print("=" * 60, file=sys.stderr)
    print("ERROR: Faltan dependencias de Python.", file=sys.stderr)
    print(f"Python en uso: {sys.executable}", file=sys.stderr)
    print(f"Instala: pip install {' '.join(missing)}", file=sys.stderr)
    print("  o bien: pip install -r requirements.txt", file=sys.stderr)
    print("", file=sys.stderr)
    print("En Kali NO ejecutes:  sudo python run.py", file=sys.stderr)
    print("Eso usa el Python del sistema (sin venv). Usa:", file=sys.stderr)
    print("  sudo ./venv/bin/python run.py", file=sys.stderr)
    print("  ./start-kali.sh", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    _check_dependencies()

    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
