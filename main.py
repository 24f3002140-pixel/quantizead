import json
import hashlib
import math
import re
from copy import deepcopy
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

FREEZES: dict[str, dict[str, Any]] = {}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def error_response(code: str, status: int = 400):
    return JSONResponse(
        status_code=status,
        content={"error": code},
    )


def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def utf8_key(x):
    return x.encode("utf-8")


def unique_strings(values):
    if not isinstance(values, list):
        return False
    seen = set()
    for x in values:
        if not nonempty_string(x):
            return False
        if x in seen:
            return False
        seen.add(x)
    return True


def safe_nonnegative_int(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= 9007199254740991
    )


def finite_nonnegative_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and float(x) >= 0
    )


def valid_floor(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and 0 <= float(x) <= 1
    )


def compact_json_bytes(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def package_digest(inventory):
    return sha256_bytes(compact_json_bytes(inventory))


def round12(x):
    return float(round(x, 12))


def sorted_codes(codes):
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))


def canonical_equal(a, b):
    return a == b


# ------------------------------------------------------------
# FREEZE
# ------------------------------------------------------------

def validate_freeze_global(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    if not isinstance(freeze_id, str):
        return False
    if len(freeze_id) == 0 or len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")
    if not unique_strings(allowed):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = set()

    for c in candidates:
        if not isinstance(c, dict):
            return False

        name = c.get("name")
        if not nonempty_string(name):
            return False

        if name in names:
            return False
        names.add(name)

        # files must be a dict (can be empty)
        files = c.get("files")
        if not isinstance(files, dict):
            return False

        # If files has content, validate filenames
        for filename, text in files.items():
            if not nonempty_string(filename):
                return False
            if not isinstance(text, str):
                return False

        if "loadable" not in c or not isinstance(c["loadable"], bool):
            return False

        if "calibrationDigest" not in c:
            return False
        if not nonempty_string(c.get("calibrationDigest")):
            return False

        if "tokenizerDigest" not in c:
            return False
        if not nonempty_string(c.get("tokenizerDigest")):
            return False

        if "unsupportedReason" in c:
            reason = c.get("unsupportedReason")
            if reason is not None and not nonempty_string(reason):
                return False

    return True


def build_inventory(files):
    inventory = []

    for filename in sorted(files.keys(), key=utf8_key):
        text = files[filename]
        data = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        })

    total = sum(item["bytes"] for item in inventory)
    digest = package_digest(inventory)

    return inventory, total, digest


def freeze_candidate(candidate, request_cal, request_tok, allowed):
    name = candidate["name"]
    files = candidate["files"]
    loadable = candidate["loadable"]
    cand_cal = candidate["calibrationDigest"]
    cand_tok = candidate["tokenizerDigest"]
    reason = candidate.get("unsupportedReason")

    # Build inventory
    inventory, total_bytes, digest = build_inventory(files)

    # Case 1: Empty files -> invalid with empty inventory
    if len(files) == 0:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [],
        }

    codes = []

    # Case 2: Has unsupportedReason
    if reason is not None and reason != "":
        if reason in allowed:
            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": digest,
                "reasonCodes": [],
            }
        codes.append("UNALLOWED_UNSUPPORTED_REASON")
        codes = sorted_codes(codes)
        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": digest,
            "reasonCodes": codes,
        }

    # Case 3: Normal validation
    if not loadable:
        codes.append("NOT_LOADABLE")

    if cand_cal != request_cal:
        codes.append("CALIBRATION_MISMATCH")

    if cand_tok != request_tok:
        codes.append("TOKENIZER_MISMATCH")

    codes = sorted_codes(codes)

    if codes:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": codes,
        }

    return {
        "name": name,
        "status": "frozen",
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": digest,
        "reasonCodes": [],
    }


def do_freeze(body):
    freeze_id = body["freezeId"]

    if freeze_id in FREEZES:
        old = FREEZES[freeze_id]
        if canonical_equal(old["input"], body):
            return JSONResponse(
                status_code=200,
                content=deepcopy(old["response"]),
            )
        return error_response("FREEZE_ID_CONFLICT", 409)

    request_cal = body["calibrationDigest"]
    request_tok = body["tokenizerDigest"]
    allowed = set(body["allowedUnsupportedReasons"])

    results = []
    for candidate in body["candidates"]:
        results.append(
            freeze_candidate(
                candidate,
                request_cal,
                request_tok,
                allowed,
            )
        )

    results.sort(key=lambda x: x["name"].encode("utf-8"))

    response = {
        "freezeId": freeze_id,
        "candidates": results,
    }

    FREEZES[freeze_id] = {
        "input": deepcopy(body),
        "response": deepcopy(response),
    }

    return JSONResponse(status_code=200, content=response)


# ------------------------------------------------------------
# SELECT
# ------------------------------------------------------------

def validate_policy(policy):
    if not isinstance(policy, dict):
        return False

    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    ]

    for key in required:
        if key not in policy:
            return False

    if not safe_nonnegative_int(policy["maxBytes"]):
        return False

    if not valid_floor(policy["aggregateFloor"]):
        return False

    if not finite_nonnegative_number(policy["maxLatencyMs"]):
        return False

    required_slices = policy["requiredSlices"]

    if not isinstance(required_slices, dict):
        return False

    for slice_name, floor in required_slices.items():
        if not nonempty_string(slice_name):
            return False
        if not valid_floor(floor):
            return False

    if not unique_strings(policy["candidateOrder"]):
        return False

    return True


def validate_manifest(candidate):
    if not isinstance(candidate, dict):
        return False

    if not nonempty_string(candidate.get("name")):
        return False

    if candidate.get("status") not in {"frozen", "unsupported", "invalid"}:
        return False

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False

    names = []

    for item in inventory:
        if not isinstance(item, dict):
            return False

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False

        name = item["name"]
        size = item["bytes"]
        digest = item["sha256"]

        if not nonempty_string(name):
            return False

        if not safe_nonnegative_int(size):
            return False

        if not isinstance(digest, str):
            return False

        if SHA256_RE.fullmatch(digest) is None:
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    if names != sorted(names, key=utf8_key):
        return False

    total = sum(item["bytes"] for item in inventory)

    if candidate.get("totalBytes") != total:
        return False

    expected_digest = package_digest(inventory)

    if candidate.get("packageDigest") != expected_digest:
        return False

    return True


def get_lineage_info(stored_candidates, submitted_candidates):
    if not isinstance(submitted_candidates, list):
        return False
    return canonical_equal(stored_candidates, submitted_candidates)


def prediction_is_binary(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def evaluate_candidate(candidate, rows, required_slices):
    name = candidate["name"]

    aggregate = None
    slices = {}

    prediction_invalid = False

    valid_rows = []

    for row in rows:
        if not isinstance(row, dict):
            prediction_invalid = True
            break

        if "label" not in row or "slice" not in row or "predictions" not in row:
            prediction_invalid = True
            break

        label = row["label"]

        if not prediction_is_binary(label):
            prediction_invalid = True
            break

        slice_name = row["slice"]
        if not isinstance(slice_name, str) or not slice_name:
            prediction_invalid = True
            break

        predictions = row["predictions"]

        if not isinstance(predictions, dict):
            prediction_invalid = True
            break

        if name not in predictions:
            prediction_invalid = True
            break

        pred = predictions[name]

        if not prediction_is_binary(pred):
            prediction_invalid = True
            break

        valid_rows.append((label, slice_name, pred))

    if prediction_invalid or len(valid_rows) == 0:
        return None, {}, True

    correct = sum(1 for label, _, pred in valid_rows if pred == label)
    aggregate = round12(correct / len(valid_rows))

    for required_name in required_slices:
        matching = [
            (label, pred)
            for label, slice_name, pred in valid_rows
            if slice_name == required_name
        ]

        if matching:
            good = sum(1 for label, pred in matching if label == pred)
            slices[required_name] = round12(good / len(matching))

    return aggregate, slices, False


def do_select(body):
    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str) or not freeze_id:
        return error_response("INVALID_INPUT", 400)

    stored = FREEZES.get(freeze_id)

    if stored is None:
        return error_response("NOT_FROZEN", 400)

    submitted_candidates = body.get("candidates")
    
    if not isinstance(submitted_candidates, list) or len(submitted_candidates) == 0:
        return error_response("INVALID_INPUT", 400)

    if not get_lineage_info(
        stored["response"]["candidates"],
        submitted_candidates,
    ):
        return error_response("INVALID_LINEAGE", 400)

    policy = body.get("policy")

    if not validate_policy(policy):
        return error_response("INVALID_POLICY", 400)

    candidate_order = policy["candidateOrder"]

    stored_names = [
        c["name"]
        for c in stored["response"]["candidates"]
    ]

    submitted_names = [
        c.get("name") if isinstance(c, dict) else None
        for c in submitted_candidates
    ]

    if (
        len(stored_names) != len(set(stored_names))
        or len(submitted_names) != len(set(submitted_names))
        or set(stored_names) != set(submitted_names)
        or set(stored_names) != set(candidate_order)
    ):
        return error_response("INVALID_POLICY", 400)

    latencies = body.get("latencies")

    if not isinstance(latencies, dict):
        return error_response("INVALID_POLICY", 400)

    rows = body.get("rows")

    if not isinstance(rows, list) or len(rows) == 0:
        return error_response("INVALID_INPUT", 400)

    results = []

    for candidate in submitted_candidates:
        name = candidate["name"]

        codes = []

        manifest_valid = validate_manifest(candidate)

        if candidate.get("status") != "frozen":
            codes.append("INVALID_LINEAGE")

        if not manifest_valid:
            codes.append("INVALID_MANIFEST")

        latency_valid = False
        latency_value = None

        if name in latencies:
            lv = latencies[name]

            if finite_nonnegative_number(lv):
                latency_valid = True
                latency_value = float(lv)

                if isinstance(lv, int) and not isinstance(lv, bool):
                    latency_value = lv

        aggregate, slices, prediction_invalid = evaluate_candidate(
            candidate,
            rows,
            policy["requiredSlices"],
        )

        if prediction_invalid:
            codes.append("INVALID_PREDICTIONS")

        if aggregate is not None:
            if aggregate < float(policy["aggregateFloor"]):
                codes.append("AGGREGATE_FLOOR")

            for slice_name, floor in policy["requiredSlices"].items():
                if slice_name not in slices:
                    codes.append(f"MISSING_SLICE:{slice_name}")
                elif slices[slice_name] < float(floor):
                    codes.append(f"SLICE_FLOOR:{slice_name}")

        total_bytes = None

        if manifest_valid:
            total_bytes = candidate["totalBytes"]

            if total_bytes > policy["maxBytes"]:
                codes.append("SIZE_LIMIT")

        if latency_valid:
            if latency_value > float(policy["maxLatencyMs"]):
                codes.append("LATENCY_LIMIT")
        else:
            codes.append("LATENCY_LIMIT")

        codes = sorted_codes(codes)

        admitted = len(codes) == 0

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency_value if latency_valid else None,
            "admitted": admitted,
            "reasonCodes": codes,
        })

    order_index = {
        name: i
        for i, name in enumerate(candidate_order)
    }

    results.sort(
        key=lambda x: (
            order_index.get(
                x["name"],
                len(candidate_order),
            ),
            x["name"].encode("utf-8"),
        )
    )

    admitted_results = [
        r for r in results
        if r["admitted"]
    ]

    if admitted_results:
        winner = min(
            admitted_results,
            key=lambda r: (
                r["totalBytes"],
                float(r["latencyMs"]),
                order_index.get(
                    r["name"],
                    len(candidate_order),
                ),
                r["name"].encode("utf-8"),
            ),
        )

        selected = winner["name"]

        winner_candidate = next(
            c
            for c in stored["response"]["candidates"]
            if c["name"] == selected
        )

        package_manifest = deepcopy(winner_candidate)

    else:
        selected = None
        package_manifest = None

    response = {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }

    return JSONResponse(
        status_code=200,
        content=response,
    )


# ------------------------------------------------------------
# ENDPOINT
# ------------------------------------------------------------

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", 400)

    if not isinstance(body, dict):
        return error_response("INVALID_INPUT", 400)

    phase = body.get("phase")

    if phase not in {"freeze", "select"}:
        return error_response("INVALID_INPUT", 400)

    if phase == "freeze":
        if not validate_freeze_global(body):
            return error_response("INVALID_INPUT", 400)
        return do_freeze(body)

    # SELECT phase
    candidates = body.get("candidates")
    rows = body.get("rows")
    policy = body.get("policy")

    if (
        not isinstance(candidates, list) 
        or len(candidates) == 0
        or not isinstance(rows, list) 
        or len(rows) == 0
        or not isinstance(policy, dict)
        or "freezeId" not in body
        or "latencies" not in body
    ):
        return error_response("INVALID_INPUT", 400)

    return do_select(body)


@app.get("/")
async def root():
    return {
        "service": "quantize-admission",
        "status": "ok",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
