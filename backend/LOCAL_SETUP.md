# Local setup quick reference

Run the backend from the `backend` folder. Do not run `uvicorn` from the repository root.

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

For UCRT64/Git Bash, the activation command above is appropriate after creating the venv with `python -m venv .venv` or `py -3 -m venv .venv`.
