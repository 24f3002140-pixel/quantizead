from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import json

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()

        print("\n========== GRADER REQUEST ==========")
        print(json.dumps(body, ensure_ascii=False, indent=2))
        print("====================================\n")

        # TEMPORARY: always return the request so we can see
        # exactly what the grader sends.
        return JSONResponse({
            "debug": True,
            "received": body
        })

    except Exception as e:
        print("JSON ERROR:", repr(e))
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )
