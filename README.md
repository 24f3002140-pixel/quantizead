# Quantize and Admit API

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

The endpoint is:

`POST http://localhost:8000/quantize`

It accepts and returns JSON.

## Public URL

The grader needs the **public base URL only**, for example:

`https://your-service.example.com`

It will call:

`POST https://your-service.example.com/quantize`

Do not enter `/quantize` in the base URL.

## Important

This implementation stores freezes in process memory. That is enough when the grader uses one running service instance. For a multi-instance deployment, use a shared persistent store.

For Render/Railway/Fly/etc., the start command is:

```bash
uvicorn app:app --host 0.0.0.0 --port $PORT
```
