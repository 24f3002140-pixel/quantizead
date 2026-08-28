import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

FREEZES = {}
LOCK = threading.Lock()
SAFE_MAX = 9007199254740991


def utf8(s):
    return s.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def code_sort(codes):
    return sorted(set(codes), key=utf8)


def is_finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def is_safe_int(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= SAFE_MAX
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
# FILE MANIFEST
# ============================================================

def build_inventory(files):
    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []
    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if filename in seen:
            return [], None, None, False

        seen.add(filename)

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    inventory.sort(key=lambda x: utf8(x["name"]))

    total = sum(x["bytes"] for x in inventory)

    package_digest = sha256_bytes(
        compact_json(inventory)
    )

    return inventory, total, package_digest, True


# ============================================================
# GLOBAL FREEZE VALIDATION
# ============================================================

def freeze_boundary_valid(body):

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

    allowed_seen = set()

    for x in allowed:
        if not isinstance(x, str) or not x:
            return False

        if x in allowed_seen:
            return False

        allowed_seen.add(x)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names must be unique.
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

    return True


# ============================================================
# FREEZE ONE CANDIDATE
# ============================================================

def freeze_one(candidate, request_cal, request_tok, allowed):

    name = candidate["name"]

    inventory, total, package_digest, files_valid = \
        build_inventory(candidate.get("files"))

    reasons = []

    if not files_valid:
        inventory = []
        total = None
        package_digest = None
        reasons.append("INVALID_INPUT")

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    if unsupported_reason is not None:

        if (
            isinstance(unsupported_reason, str)
            and unsupported_reason
            and unsupported_reason in allowed
        ):
            status = "unsupported"
        else:
            status = "invalid"
            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

    else:

        status = "frozen"

        if candidate.get("loadable") is not True:
            reasons.append("NOT_LOADABLE")

        if candidate.get("calibrationDigest") != request_cal:
            reasons.append("CALIBRATION_MISMATCH")

        if candidate.get("tokenizerDigest") != request_tok:
            reasons.append("TOKENIZER_MISMATCH")

    if reasons:
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package_digest,
        "reasonCodes": code_sort(reasons),
    }


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        existing = FREEZES.get(freeze_id)

        if existing is not None:

            if existing["request"] == body:
                return existing["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        output = []

        for candidate in body["candidates"]:
            output.append(
                freeze_one(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed,
                )
            )

        output.sort(
            key=lambda x: utf8(x["name"])
        )

        response = {
            "freezeId": freeze_id,
            "candidates": output,
        }

        # Reserve only after successful global validation.
        FREEZES[freeze_id] = {
            "request": body,
            "response": response,
        }

        return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    clean = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256",
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        sha = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        if name in seen:
            return False, None

        seen.add(name)

        if not is_safe_int(size):
            return False, None

        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or sha.lower() != sha
        ):
            return False, None

        try:
            int(sha, 16)
        except Exception:
            return False, None

        clean.append({
            "name": name,
            "bytes": size,
            "sha256": sha,
        })

    clean.sort(
        key=lambda x: utf8(x["name"])
    )

    if clean != inventory:
        return False, None

    total = sum(
        x["bytes"] for x in clean
    )

    package_digest = sha256_bytes(
        compact_json(clean)
    )

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package_digest:
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not is_safe_int(policy.get("maxBytes")):
        return False

    floor = policy.get("aggregateFloor")

    if (
        not is_finite_number(floor)
        or float(floor) < 0
        or float(floor) > 1
    ):
        return False

    required = policy.get("requiredSlices")

    if not isinstance(required, dict):
        return False

    for name, value in required.items():

        if not isinstance(name, str) or not name:
            return False

        if (
            not is_finite_number(value)
            or float(value) < 0
            or float(value) > 1
        ):
            return False

    latency_limit = policy.get("maxLatencyMs")

    if (
        not is_finite_number(latency_limit)
        or float(latency_limit) < 0
    ):
        return False

    order = policy.get("candidateOrder")

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
        or float(value) < 0
    ):
        return None

    if isinstance(value, float) and value.is_integer():
        return int(value)

    return value


# ============================================================
# EVALUATE CANDIDATE
# ============================================================

def evaluate(candidate, rows, policy, latencies):

    name = candidate["name"]

    reasons = []

    # --------------------------------------------------------
    # FROZEN STATUS
    # --------------------------------------------------------

    if candidate.get("status") != "frozen":
        reasons.append("NOT_FROZEN")

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total = validate_manifest(
        candidate
    )

    if not manifest_ok:
        total = None
        reasons.append("INVALID_MANIFEST")

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    predictions_valid = True

    correct = 0

    slice_counts = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_valid = False
            continue

        label = row.get("label")
        slice_name = row.get("slice")
        predictions = row.get("predictions")

        if not is_binary(label):
            predictions_valid = False
            continue

        if not isinstance(slice_name, str):
            predictions_valid = False
            continue

        if not isinstance(predictions, dict):
            predictions_valid = False
            continue

        if name not in predictions:
            predictions_valid = False
            continue

        prediction = predictions[name]

        if not is_binary(prediction):
            predictions_valid = False
            continue

        slice_counts[slice_name] = \
            slice_counts.get(slice_name, 0) + 1

        if int(label) == int(prediction):
            correct += 1
            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    required = policy.get(
        "requiredSlices",
        {}
    )

    if not predictions_valid:

        aggregate = None

        slices = {
            name: None
            for name in required
        }

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if len(rows) == 0:
            aggregate = None
            reasons.append(
                "INVALID_PREDICTIONS"
            )
        else:
            aggregate = round(
                correct / len(rows),
                12
            )

        slices = {}

        for slice_name, floor in required.items():

            count = slice_counts.get(
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

                if accuracy < float(floor):
                    reasons.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        if (
            aggregate is None
            or aggregate <
            float(policy["aggregateFloor"])
        ):
            reasons.append(
                "AGGREGATE_FLOOR"
            )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if (
        total is not None
        and total > policy["maxBytes"]
    ):
        reasons.append(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = get_latency(
        latencies,
        name
    )

    if (
        latency is not None
        and float(latency)
        > float(policy["maxLatencyMs"])
    ):
        reasons.append(
            "LATENCY_LIMIT"
        )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": code_sort(reasons),
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body.get("freezeId")

    with LOCK:
        stored = FREEZES.get(freeze_id)

    # --------------------------------------------------------
    # Unknown freeze
    # --------------------------------------------------------

    if stored is None:

        results = []

        for candidate in body["candidates"]:

            name = (
                candidate.get("name", "")
                if isinstance(candidate, dict)
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
                ],
            })

        results.sort(
            key=lambda x: utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored_candidates = stored[
        "response"
    ]["candidates"]

    stored_by_name = {
        c["name"]: c
        for c in stored_candidates
    }

    supplied = body["candidates"]

    # Exact array equality.
    lineage_ok = (
        supplied == stored_candidates
    )

    policy = body["policy"]
    policy_ok = validate_policy(policy)

    supplied_names = []

    if policy_ok:

        for c in supplied:
            if isinstance(c, dict):
                supplied_names.append(
                    c.get("name")
                )

    order = (
        policy.get("candidateOrder")
        if policy_ok
        else []
    )

    order_ok = (
        policy_ok
        and len(supplied_names) == len(supplied)
        and all(
            isinstance(x, str) and x
            for x in supplied_names
        )
        and len(set(supplied_names))
        == len(supplied_names)
        and len(order) == len(supplied_names)
        and len(set(order)) == len(order)
        and set(order) == set(supplied_names)
    )

    results = []

    for candidate in supplied:

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
                ],
            })

            continue

        # Work from the submitted candidate so that tampering
        # is detectable.
        result = evaluate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies", {})
        )

        if not lineage_ok:
            result["admitted"] = False
            result["reasonCodes"] = code_sort(
                result["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not policy_ok or not order_ok:
            result["admitted"] = False
            result["reasonCodes"] = code_sort(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(result)

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if order_ok:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                rank.get(r["name"], SAFE_MAX),
                utf8(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r: utf8(r["name"])
        )

    # --------------------------------------------------------
    # SELECT WINNER
    # --------------------------------------------------------

    admitted = [
        r for r in results
        if r["admitted"]
    ]

    selected = None
    package_manifest = None

    if (
        admitted
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                rank.get(
                    r["name"],
                    SAFE_MAX
                )
            )
        )

        selected = winner["name"]

        # Exactly the recorded winner object.
        package_manifest = stored_by_name[
            selected
        ]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
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

        if not freeze_boundary_valid(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = do_freeze(body)

        return JSONResponse(
            result,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Explicit required global boundary.
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

        result = do_select(body)

        return JSONResponse(
            result,
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
