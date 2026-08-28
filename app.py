from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib
import json
import math
import threading

app = FastAPI()

FREEZES = {}
LOCK = threading.Lock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8(s):
    return s.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sorted_codes(items):
    return sorted(set(items), key=utf8)


def is_finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def is_safe_nonnegative_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE_INTEGER
    )


def is_binary(x):
    if isinstance(x, bool):
        return False

    if isinstance(x, int):
        return x == 0 or x == 1

    if isinstance(x, float):
        return math.isfinite(x) and (x == 0.0 or x == 1.0)

    return False


# ============================================================
# INVENTORY
# ============================================================

def build_inventory(files):
    if not isinstance(files, dict):
        return None

    if len(files) == 0:
        return None

    inventory = []

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return None

        if not isinstance(text, str):
            return None

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    inventory.sort(key=lambda x: utf8(x["name"]))

    total = sum(x["bytes"] for x in inventory)

    package_digest = sha256_bytes(
        compact_json(inventory)
    )

    return inventory, total, package_digest


# ============================================================
# FREEZE INPUT VALIDATION
# ============================================================

def valid_freeze_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or len(freeze_id) > 128
    ):
        return False

    calibration = body.get("calibrationDigest")
    tokenizer = body.get("tokenizerDigest")

    if not isinstance(calibration, str) or not calibration:
        return False

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    seen = set()

    for reason in allowed:
        if not isinstance(reason, str) or not reason:
            return False

        if reason in seen:
            return False

        seen.add(reason)

    candidates = body.get("candidates")

    # THIS IS IMPORTANT:
    # Empty freeze candidate array = INVALID_INPUT / HTTP 400.
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return False

        if name in names:
            return False

        names.add(name)

        # files must be a non-empty object
        files = candidate.get("files")

        if not isinstance(files, dict):
            return False

        if len(files) == 0:
            return False

        # Every filename/content must be a string.
        for filename, content in files.items():

            if not isinstance(filename, str) or not filename:
                return False

            if not isinstance(content, str):
                return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons
):

    name = candidate["name"]

    reasons = []

    manifest = build_inventory(
        candidate.get("files")
    )

    if manifest is None:
        # Candidate-level invalid manifest.
        inventory = []
        total_bytes = None
        package_digest = None
    else:
        inventory, total_bytes, package_digest = manifest

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # UNSUPPORTED CANDIDATE
    # --------------------------------------------------------

    if unsupported_reason is not None and unsupported_reason != "":

        if unsupported_reason in allowed_reasons:

            status = "unsupported"

        else:

            status = "invalid"

            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

    # --------------------------------------------------------
    # NORMAL CANDIDATE
    # --------------------------------------------------------

    else:

        status = "frozen"

        if candidate.get("loadable") is not True:
            status = "invalid"
            reasons.append("NOT_LOADABLE")

        if candidate.get("calibrationDigest") != request_calibration:
            status = "invalid"
            reasons.append("CALIBRATION_MISMATCH")

        if candidate.get("tokenizerDigest") != request_tokenizer:
            status = "invalid"
            reasons.append("TOKENIZER_MISMATCH")

    # Invalid files make candidate invalid.
    if manifest is None:
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sorted_codes(reasons)
    }


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        previous = FREEZES.get(freeze_id)

        # Replay
        if previous is not None:

            if previous["input"] == body:
                return previous["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = []

        for candidate in body["candidates"]:

            candidates.append(
                freeze_candidate(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed
                )
            )

        candidates.sort(
            key=lambda x: utf8(x["name"])
        )

        response = {
            "freezeId": freeze_id,
            "candidates": candidates
        }

        FREEZES[freeze_id] = {
            "input": body,
            "response": response
        }

        return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256"
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        if name in names:
            return False, None

        names.add(name)

        if not is_safe_nonnegative_integer(size):
            return False, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
        ):
            return False, None

        try:
            int(digest, 16)
        except Exception:
            return False, None

    expected_order = sorted(
        inventory,
        key=lambda x: utf8(x["name"])
    )

    if inventory != expected_order:
        return False, None

    total = sum(
        item["bytes"]
        for item in inventory
    )

    package = sha256_bytes(
        compact_json(inventory)
    )

    # Never trust submitted total/package.
    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package:
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")

    if not is_safe_nonnegative_integer(max_bytes):
        return False

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if (
        not is_finite_number(aggregate_floor)
        or aggregate_floor < 0
        or aggregate_floor > 1
    ):
        return False

    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(required_slices, dict):
        return False

    for name, floor in required_slices.items():

        if not isinstance(name, str) or not name:
            return False

        if (
            not is_finite_number(floor)
            or floor < 0
            or floor > 1
        ):
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if (
        not is_finite_number(max_latency)
        or max_latency < 0
    ):
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if not isinstance(name, str) or not name:
            return False

        if name in seen:
            return False

        seen.add(name)

    return True


# ============================================================
# LATENCY
# ============================================================

def get_latency(latencies, name):

    if not isinstance(latencies, dict):
        return None

    if name not in latencies:
        return None

    value = latencies[name]

    if (
        not is_finite_number(value)
        or value < 0
    ):
        return None

    return value


# ============================================================
# CANDIDATE EVALUATION
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies
):

    name = candidate.get("name", "")

    reasons = []

    # Candidate must have been frozen.
    if candidate.get("status") != "frozen":
        reasons.append("NOT_FROZEN")

    # Manifest integrity.
    manifest_ok, total_bytes = validate_manifest(
        candidate
    )

    if not manifest_ok:

        total_bytes = None

        reasons.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    prediction_valid = True

    correct = 0

    slice_total = {}
    slice_correct = {}

    if not isinstance(rows, list):
        prediction_valid = False

    for row in rows:

        if not isinstance(row, dict):
            prediction_valid = False
            continue

        label = row.get("label")
        slice_name = row.get("slice")
        predictions = row.get("predictions")

        if not is_binary(label):
            prediction_valid = False
            continue

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            prediction_valid = False
            continue

        if not isinstance(predictions, dict):
            prediction_valid = False
            continue

        if name not in predictions:
            prediction_valid = False
            continue

        prediction = predictions[name]

        if not is_binary(prediction):
            prediction_valid = False
            continue

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    required = policy.get(
        "requiredSlices",
        {}
    )

    slices = {}

    if not prediction_valid or len(rows) == 0:

        aggregate = None

        for slice_name in required:
            slices[slice_name] = None

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        aggregate = round(
            correct / len(rows),
            12
        )

        if aggregate < policy["aggregateFloor"]:
            reasons.append(
                "AGGREGATE_FLOOR"
            )

        for slice_name, floor in required.items():

            count = slice_total.get(
                slice_name,
                0
            )

            if count == 0:

                slices[slice_name] = None

                reasons.append(
                    "MISSING_SLICE:" + slice_name
                )

            else:

                accuracy = round(
                    slice_correct.get(
                        slice_name,
                        0
                    ) / count,
                    12
                )

                slices[slice_name] = accuracy

                if accuracy < floor:
                    reasons.append(
                        "SLICE_FLOOR:" + slice_name
                    )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if (
        total_bytes is not None
        and total_bytes > policy["maxBytes"]
    ):
        reasons.append("SIZE_LIMIT")

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = get_latency(
        latencies,
        name
    )

    if latency is None:

        # Cannot satisfy latency requirement.
        reasons.append("LATENCY_LIMIT")

    elif latency > policy["maxLatencyMs"]:

        reasons.append("LATENCY_LIMIT")

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": sorted_codes(reasons)
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body.get("freezeId")

    with LOCK:
        saved = FREEZES.get(freeze_id)

    candidates = body["candidates"]
    rows = body["rows"]
    policy = body["policy"]
    latencies = body.get("latencies", {})

    # --------------------------------------------------------
    # NOT FROZEN
    # --------------------------------------------------------

    if saved is None:

        results = []

        for c in candidates:

            name = (
                c.get("name", "")
                if isinstance(c, dict)
                else ""
            )

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "NOT_FROZEN"
                ]
            })

        results.sort(
            key=lambda x: utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    stored_candidates = saved["response"]["candidates"]

    # Exact candidate array comparison.
    lineage_ok = (
        candidates == stored_candidates
    )

    policy_ok = validate_policy(policy)

    names = []

    for c in candidates:

        if isinstance(c, dict):
            names.append(c.get("name"))
        else:
            names.append(None)

    order = (
        policy.get("candidateOrder", [])
        if policy_ok
        else []
    )

    order_ok = False

    if policy_ok:

        order_ok = (
            len(names) == len(order)
            and len(set(names)) == len(names)
            and len(set(order)) == len(order)
            and all(
                isinstance(x, str) and x
                for x in names
            )
            and set(names) == set(order)
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for candidate in candidates:

        if not isinstance(candidate, dict):

            results.append({
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE"
                ]
            })

            continue

        result = evaluate_candidate(
            candidate,
            rows,
            policy,
            latencies
        )

        if not lineage_ok:
            result["reasonCodes"].append(
                "INVALID_LINEAGE"
            )

        if not policy_ok or not order_ok:
            result["reasonCodes"].append(
                "INVALID_POLICY"
            )

        result["reasonCodes"] = sorted_codes(
            result["reasonCodes"]
        )

        if not lineage_ok or not policy_ok or not order_ok:
            result["admitted"] = False

        results.append(result)

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if order_ok:

        positions = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda x: (
                positions.get(
                    x["name"],
                    MAX_SAFE_INTEGER
                ),
                utf8(x["name"])
            )
        )

    else:

        results.sort(
            key=lambda x: utf8(x["name"])
        )

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    selected = None
    package_manifest = None

    admitted = [
        x for x in results
        if x["admitted"]
    ]

    if (
        admitted
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        positions = {
            name: i
            for i, name in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                positions[x["name"]]
            )
        )

        selected = winner["name"]

        for candidate in stored_candidates:

            if candidate["name"] == selected:
                package_manifest = candidate
                break

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not isinstance(body, dict):

        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    phase = body.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not valid_freeze_request(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response, status = do_freeze(body)

        return JSONResponse(
            response,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        if not isinstance(
            body.get("candidates"),
            list
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        if not isinstance(
            body.get("rows"),
            list
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        if not isinstance(
            body.get("policy"),
            dict
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        return JSONResponse(
            do_select(body),
            status_code=200
        )

    # Unknown/missing phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}
