import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

STORE = {}
LOCK = threading.Lock()

MAX_SAFE_INTEGER = 9007199254740991


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def u8(value):
    return value.encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sort_codes(values):
    return sorted(set(values), key=lambda x: u8(x))


def finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def binary(value):
    if isinstance(value, bool):
        return False

    if isinstance(value, int):
        return value == 0 or value == 1

    if isinstance(value, float):
        return (
            math.isfinite(value)
            and (value == 0.0 or value == 1.0)
        )

    return False


# ------------------------------------------------------------
# Inventory
# ------------------------------------------------------------

def make_inventory(files):
    """
    Returns:
        valid, inventory, totalBytes, packageDigest
    """

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    inventory = []

    for filename, content in files.items():

        if not isinstance(filename, str):
            return False, [], None, None

        if filename == "":
            return False, [], None, None

        if not isinstance(content, str):
            return False, [], None, None

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": digest(raw),
        })

    inventory.sort(
        key=lambda x: u8(x["name"])
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    package = digest(
        canonical_json(inventory)
    )

    return True, inventory, total, package


# ------------------------------------------------------------
# Freeze request boundary
# ------------------------------------------------------------

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

    if (
        not isinstance(calibration, str)
        or not calibration
    ):
        return False

    if (
        not isinstance(tokenizer, str)
        or not tokenizer
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    allowed_seen = set()

    for reason in allowed:

        if (
            not isinstance(reason, str)
            or not reason
        ):
            return False

        if reason in allowed_seen:
            return False

        allowed_seen.add(reason)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        if name in names:
            return False

        names.add(name)

    return True


# ------------------------------------------------------------
# Freeze candidate
# ------------------------------------------------------------

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons,
):

    name = candidate["name"]

    reasons = []

    files_valid, inventory, total, package = \
        make_inventory(candidate.get("files"))

    # File errors are candidate-level invalidity.
    # INVALID_INPUT is NOT emitted here because the
    # specification's candidate reason list does not include it.
    if not files_valid:
        inventory = []
        total = None
        package = None

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    if unsupported_reason is not None:

        if (
            isinstance(unsupported_reason, str)
            and unsupported_reason
            and unsupported_reason in allowed_reasons
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

        if (
            candidate.get("calibrationDigest")
            != request_calibration
        ):
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        if (
            candidate.get("tokenizerDigest")
            != request_tokenizer
        ):
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

    # Invalid file manifest makes candidate invalid,
    # but there is no extra candidate-level error code.
    if not files_valid:
        status = "invalid"

    if reasons:
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": sort_codes(reasons),
    }


# ------------------------------------------------------------
# Freeze
# ------------------------------------------------------------

def handle_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        old = STORE.get(freeze_id)

        if old is not None:

            # Exact replay.
            if old["request"] == body:
                return old["response"], 200

            # Same ID, different request.
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
                    allowed,
                )
            )

        candidates.sort(
            key=lambda x: u8(x["name"])
        )

        response = {
            "freezeId": freeze_id,
            "candidates": candidates,
        }

        STORE[freeze_id] = {
            "request": body,
            "response": response,
        }

        return response, 200


# ------------------------------------------------------------
# Validate stored/submitted manifest
# ------------------------------------------------------------

def validate_manifest(candidate):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    cleaned = []
    names = set()

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

        if (
            not isinstance(name, str)
            or not name
        ):
            return False, None

        if name in names:
            return False, None

        names.add(name)

        if not safe_integer(size):
            return False, None

        if (
            not isinstance(sha, str)
            or len(sha) != 64
            or sha != sha.lower()
        ):
            return False, None

        try:
            int(sha, 16)
        except Exception:
            return False, None

        cleaned.append({
            "name": name,
            "bytes": size,
            "sha256": sha,
        })

    cleaned.sort(
        key=lambda x: u8(x["name"])
    )

    # Inventory itself must be correctly sorted.
    if cleaned != inventory:
        return False, None

    total = sum(
        item["bytes"]
        for item in cleaned
    )

    package = digest(
        canonical_json(cleaned)
    )

    # Never trust submitted totalBytes/packageDigest.
    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package:
        return False, None

    return True, total


# ------------------------------------------------------------
# Policy
# ------------------------------------------------------------

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")

    if not safe_integer(max_bytes):
        return False

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if (
        not finite_number(aggregate_floor)
        or float(aggregate_floor) < 0
        or float(aggregate_floor) > 1
    ):
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for slice_name, floor in required.items():

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            return False

        if (
            not finite_number(floor)
            or float(floor) < 0
            or float(floor) > 1
        ):
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if (
        not finite_number(max_latency)
        or float(max_latency) < 0
    ):
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        if name in seen:
            return False

        seen.add(name)

    return True


# ------------------------------------------------------------
# Latency
# ------------------------------------------------------------

def validated_latency(latencies, name):

    if not isinstance(latencies, dict):
        return None

    if name not in latencies:
        return None

    value = latencies[name]

    if (
        not finite_number(value)
        or float(value) < 0
    ):
        return None

    return value


# ------------------------------------------------------------
# Evaluate candidate
# ------------------------------------------------------------

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies,
):

    name = candidate.get("name", "")

    reasons = []

    # Frozen?
    if candidate.get("status") != "frozen":
        reasons.append("NOT_FROZEN")

    # Manifest.
    manifest_ok, total_bytes = \
        validate_manifest(candidate)

    if not manifest_ok:
        total_bytes = None
        reasons.append("INVALID_MANIFEST")

    # Prediction evaluation.
    predictions_valid = True

    total_correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_valid = False
            continue

        label = row.get("label")
        slice_name = row.get("slice")
        predictions = row.get("predictions")

        if not binary(label):
            predictions_valid = False
            continue

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            predictions_valid = False
            continue

        if not isinstance(predictions, dict):
            predictions_valid = False
            continue

        if name not in predictions:
            predictions_valid = False
            continue

        prediction = predictions[name]

        if not binary(prediction):
            predictions_valid = False
            continue

        slice_total[slice_name] = \
            slice_total.get(slice_name, 0) + 1

        if int(label) == int(prediction):

            total_correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    required = policy.get(
        "requiredSlices",
        {}
    )

    slices = {}

    if not predictions_valid or len(rows) == 0:

        aggregate = None

        for slice_name in required:
            slices[slice_name] = None

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        aggregate = round(
            total_correct / len(rows),
            12
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

                if accuracy < float(floor):
                    reasons.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        if (
            aggregate
            < float(policy["aggregateFloor"])
        ):
            reasons.append(
                "AGGREGATE_FLOOR"
            )

    # Size.
    if (
        total_bytes is not None
        and total_bytes
        > policy["maxBytes"]
    ):
        reasons.append("SIZE_LIMIT")

    # Latency.
    latency = validated_latency(
        latencies,
        name
    )

    if (
        latency is not None
        and float(latency)
        > float(policy["maxLatencyMs"])
    ):
        reasons.append("LATENCY_LIMIT")

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": sort_codes(reasons),
    }


# ------------------------------------------------------------
# Select
# ------------------------------------------------------------

def handle_select(body):

    freeze_id = body.get("freezeId")

    with LOCK:
        stored = STORE.get(freeze_id)

    # Unknown freeze.
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
            key=lambda x: u8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored_candidates = \
        stored["response"]["candidates"]

    supplied_candidates = body["candidates"]

    # Exact frozen candidate array equality.
    lineage_ok = (
        supplied_candidates
        == stored_candidates
    )

    policy = body["policy"]

    policy_ok = validate_policy(
        policy
    )

    supplied_names = []

    for candidate in supplied_candidates:

        if isinstance(candidate, dict):
            supplied_names.append(
                candidate.get("name")
            )
        else:
            supplied_names.append(None)

    order = (
        policy.get("candidateOrder")
        if policy_ok
        else []
    )

    order_ok = False

    if policy_ok:

        names_valid = all(
            isinstance(x, str) and x
            for x in supplied_names
        )

        unique_names = (
            len(set(supplied_names))
            == len(supplied_names)
        )

        unique_order = (
            len(set(order))
            == len(order)
        )

        same_set = (
            set(supplied_names)
            == set(order)
        )

        same_length = (
            len(supplied_names)
            == len(order)
        )

        order_ok = (
            names_valid
            and unique_names
            and unique_order
            and same_set
            and same_length
        )

    results = []

    for candidate in supplied_candidates:

        if not isinstance(candidate, dict):

            result = {
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE"
                ],
            }

            results.append(result)
            continue

        result = evaluate_candidate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies", {})
        )

        extra = []

        if not lineage_ok:
            extra.append(
                "INVALID_LINEAGE"
            )

        if not policy_ok or not order_ok:
            extra.append(
                "INVALID_POLICY"
            )

        result["reasonCodes"] = sort_codes(
            result["reasonCodes"] + extra
        )

        if extra:
            result["admitted"] = False

        results.append(result)

    # Results order.
    if order_ok:

        positions = {
            name: index
            for index, name in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                positions.get(
                    r["name"],
                    MAX_SAFE_INTEGER
                ),
                u8(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r: u8(r["name"])
        )

    # Winner.
    selected = None
    package_manifest = None

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    if (
        admitted
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        positions = {
            name: index
            for index, name in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                positions.get(
                    r["name"],
                    MAX_SAFE_INTEGER
                ),
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
        "packageManifest": package_manifest,
    }


# ------------------------------------------------------------
# POST /quantize
# ------------------------------------------------------------

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

        response, status = \
            handle_freeze(body)

        return JSONResponse(
            response,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # These are explicitly required by the task.
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

        response = handle_select(body)

        return JSONResponse(
            response,
            status_code=200
        )

    # Unknown or missing phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


# ------------------------------------------------------------
# Health
# ------------------------------------------------------------

@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}
