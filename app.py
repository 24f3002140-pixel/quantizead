import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful store for frozen records
FREEZES = {}
LOCK = threading.Lock()

SAFE_MAX = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8(value):
    return value.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().lower()


def compact_json_bytes(inventory_list):
    """
    Constructs a manually compressed JSON array without whitespaces
    to ensure exact cryptographic key sequence match (name, bytes, sha256).
    """
    lines = []
    for item in inventory_list:
        name_str = json.dumps(item["name"], ensure_ascii=False)
        sha_str = json.dumps(item["sha256"], ensure_ascii=False)
        lines.append(f'{{"name":{name_str},"bytes":{item["bytes"]},"sha256":{sha_str}}}')
    
    compact_str = "[" + ",".join(lines) + "]"
    return compact_str.encode("utf-8")


def sort_codes(codes):
    return sorted(list(set(codes)))


def finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def safe_nonnegative_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
    )


def binary_value(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0 or value == 1
    if isinstance(value, float):
        return math.isfinite(value) and (value == 0.0 or value == 1.0)
    return False


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []
    names = set()

    for filename, text in files.items():
        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        name_key = utf8(filename)
        if name_key in names:
            return [], None, None, False
        names.add(name_key)

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")
        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    # Sort inventory systematically by UTF-8 string bytes
    inventory.sort(key=lambda item: utf8(item["name"]))
    total_bytes = sum(item["bytes"] for item in inventory)
    package_digest = sha256_bytes(compact_json_bytes(inventory))

    return inventory, total_bytes, package_digest, True


# ============================================================
# FREEZE REQUEST BOUNDARY VALIDATION
# ============================================================

def validate_freeze_request(body):
    if not isinstance(body, dict) or body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    if not isinstance(freeze_id, str) or not freeze_id or len(freeze_id) > 128:
        return False

    if not isinstance(body.get("calibrationDigest"), str) or not body.get("calibrationDigest"):
        return False

    if not isinstance(body.get("tokenizerDigest"), str) or not body.get("tokenizerDigest"):
        return False

    allowed = body.get("allowedUnsupportedReasons")
    if not isinstance(allowed, list):
        return False

    seen_reasons = set()
    for reason in allowed:
        if not isinstance(reason, str) or not reason or utf8(reason) in seen_reasons:
            return False
        seen_reasons.add(utf8(reason))

    candidates = body.get("candidates")
    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    seen_names = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        name = candidate.get("name")
        if not isinstance(name, str) or not name or utf8(name) in seen_names:
            return False
        seen_names.add(utf8(name))

    return True


def freeze_candidate(candidate, request_calibration, request_tokenizer, allowed_reasons):
    name = candidate["name"]
    reason_codes = []

    inventory, total_bytes, package_digest, files_valid = build_inventory(candidate.get("files"))

    if not files_valid:
        inventory, total_bytes, package_digest = [], None, None
        reason_codes.append("INVALID_INPUT")

    if "unsupportedReason" in candidate:
        unsupported_reason = candidate.get("unsupportedReason")
        if isinstance(unsupported_reason, str) and unsupported_reason and unsupported_reason in allowed_reasons:
            status = "unsupported"
        else:
            status = "invalid"
            reason_codes.append("UNALLOWED_UNSUPPORTED_REASON")
    else:
        status = "frozen"
        if candidate.get("loadable") is not True:
            reason_codes.append("NOT_LOADABLE")
        if candidate.get("calibrationDigest") != request_calibration:
            reason_codes.append("CALIBRATION_MISMATCH")
        if candidate.get("tokenizerDigest") != request_tokenizer:
            reason_codes.append("TOKENIZER_MISMATCH")

    if reason_codes and status != "unsupported":
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sort_codes(reason_codes),
    }


# ============================================================
# ROUTE ENDPOINT HANDLING
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

    phase = body.get("phase")

    # --------------------------------------------------------
    # EXECUTION PHASE: FREEZE
    # --------------------------------------------------------
    if phase == "freeze":
        if not validate_freeze_request(body):
            return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        freeze_id = body["freezeId"]

        with LOCK:
            if freeze_id in FREEZES:
                stored = FREEZES[freeze_id]
                if stored["input_raw"] == body:
                    return JSONResponse(status_code=200, content=stored["response_payload"])
                else:
                    return JSONResponse(status_code=409, content={"error": "FREEZE_ID_CONFLICT"})

            out_candidates = [
                freeze_candidate(c, body["calibrationDigest"], body["tokenizerDigest"], body["allowedUnsupportedReasons"])
                for c in body["candidates"]
            ]
            out_candidates.sort(key=lambda x: x["name"])

            response_payload = {
                "freezeId": freeze_id,
                "candidates": out_candidates
            }

            FREEZES[freeze_id] = {
                "input_raw": body,
                "response_payload": response_payload
            }
            return JSONResponse(status_code=200, content=response_payload)

    # --------------------------------------------------------
    # EXECUTION PHASE: SELECT
    # --------------------------------------------------------
    elif phase == "select":
        freeze_id = body.get("freezeId")
        candidates_in = body.get("candidates")
        policy = body.get("policy")
        latencies = body.get("latencies")
        rows = body.get("rows")

        if (
            not isinstance(freeze_id, str) or not freeze_id
            or not isinstance(candidates_in, list)
            or not isinstance(policy, dict)
            or not isinstance(latencies, dict)
            or not isinstance(rows, list)
        ):
            return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        # Map policies safely
        max_bytes = policy.get("maxBytes")
        agg_floor = policy.get("aggregateFloor")
        req_slices = policy.get("requiredSlices")
        max_latency = policy.get("maxLatencyMs")
        candidate_order = policy.get("candidateOrder")

        if (
            not safe_nonnegative_integer(max_bytes)
            or not finite_number(agg_floor) or not (0 <= agg_floor <= 1)
            or not finite_number(max_latency) or max_latency < 0
            or not isinstance(candidate_order, list)
            or not isinstance(req_slices, dict)
        ):
            return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        if len(candidate_order) != len(set(candidate_order)):
            return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        for k, v in req_slices.items():
            if not isinstance(k, str) or not finite_number(v) or not (0 <= v <= 1):
                return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        # Validate unique collections match constraints
        cand_in_names = [c.get("name") for c in candidates_in if isinstance(c, dict) and isinstance(c.get("name"), str)]
        if set(cand_in_names) != set(candidate_order) or len(cand_in_names) != len(candidates_in):
            return JSONResponse(status_code=400, content={"error": "INVALID_INPUT"})

        with LOCK:
            has_freeze = freeze_id in FREEZES
            stored_response = FREEZES[freeze_id]["response_payload"] if has_freeze else None

        results = []
        admitted_pool = []

