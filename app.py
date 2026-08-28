import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

FREEZES = {}
LOCK = threading.Lock()

MAX_SAFE = 9007199254740991


# ============================================================
# HELPERS
# ============================================================

def b(s):
    return s.encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=b)


def finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE
    )


def binary(x):
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

def inventory_from_files(files):

    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []

    for filename, content in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": digest(raw)
        })

    inventory.sort(key=lambda x: b(x["name"]))

    total = sum(x["bytes"] for x in inventory)

    package_digest = digest(
        json_bytes(inventory)
    )

    return inventory, total, package_digest, True


# ============================================================
# FREEZE GLOBAL BOUNDARY
# ============================================================

def freeze_input_valid(body):

    if not isinstance(body, dict):
        return False

    # Explicitly required by specification.
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

    if not isinstance(calibration, str) or not calibration:
        return False

    tokenizer = body.get("tokenizerDigest")

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    # Reason strings must be non-empty and unique.
    seen_reasons = set()

    for reason in allowed:

        if not isinstance(reason, str) or not reason:
            return False

        key = b(reason)

        if key in seen_reasons:
            return False

        seen_reasons.add(key)

    candidates = body.get("candidates")

    # These are explicitly globally invalid.
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate list must contain candidate objects with
    # valid unique names.
    seen_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return False

        key = b(name)

        if key in seen_names:
            return False

        seen_names.add(key)

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

    # --------------------------------------------------------
    # FILES
    # --------------------------------------------------------

    inventory, total, package, files_ok = \
        inventory_from_files(
            candidate.get("files")
        )

    if not files_ok:

        inventory = []
        total = None
        package = None

        reasons.append("INVALID_INPUT")

    # --------------------------------------------------------
    # UNSUPPORTED
    # --------------------------------------------------------

    if "unsupportedReason" in candidate:

        unsupported = candidate.get(
            "unsupportedReason"
        )

        if (
            isinstance(unsupported, str)
            and unsupported
            and unsupported in allowed_reasons
        ):

            status = "unsupported"

        else:

            status = "invalid"

            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

    else:

        status = "frozen"

        # ----------------------------------------------------
        # LOADABLE
        # ----------------------------------------------------

        if candidate.get("loadable") is not True:
            reasons.append("NOT_LOADABLE")

        # ----------------------------------------------------
        # CALIBRATION
        # ----------------------------------------------------

        if (
            candidate.get("calibrationDigest")
            != request_calibration
        ):
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        # ----------------------------------------------------
        # TOKENIZER
        # ----------------------------------------------------

        if (
            candidate.get("tokenizerDigest")
            != request_tokenizer
        ):
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

    # Any failure makes candidate invalid unless it is an
    # explicitly allowed unsupported candidate.
    if reasons and status != "unsupported":
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": sort_codes(reasons)
    }


# ============================================================
# FREEZE
# ============================================================

def freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # Replay / conflict.
        if freeze_id in FREEZES:

            saved = FREEZES[freeze_id]

            if saved["input"] == body:
                return saved["output"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        candidates = sorted(
            body["candidates"],
            key=lambda x: b(x["name"])
        )

        output_candidates = []

        for candidate in candidates:

            output_candidates.append(
                freeze_candidate(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    set(body["allowedUnsupportedReasons"])
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": output_candidates
        }

        FREEZES[freeze_id] = {
            "input": body,
            "output": response
        }

        return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    canonical = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        sha = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = b(name)

        if key in seen:
            return False, None

        seen.add(key)

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

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": sha
        })

    canonical.sort(key=lambda x: b(x["name"]))

    # Exact canonical inventory.
    if inventory != canonical:
        return False, None

    total = sum(
        item["bytes"]
        for item in canonical
    )

    package = digest(
        json_bytes(canonical)
    )

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package:
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def valid_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if (
        not finite_number(floor)
        or not 0 <= float(floor) <= 1
    ):
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for name, value in required.items():

        if not isinstance(name, str) or not name:
            return False

        if (
            not finite_number(value)
            or not 0 <= float(value) <= 1
        ):
            return False

    latency = policy.get(
        "maxLatencyMs"
    )

    if (
        not finite_number(latency)
        or float(latency) < 0
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

        key = b(name)

        if key in seen:
            return False

        seen.add(key)

    return True


# ============================================================
# EVALUATE
# ============================================================

def evaluate(
    candidate,
    rows,
    policy,
    latencies,
    frozen_names
):

    name = candidate.get(
        "name",
        ""
    )

    reasons = []

    # --------------------------------------------------------
    # FROZEN
    # --------------------------------------------------------

    if (
        name not in frozen_names
        or candidate.get("status") != "frozen"
    ):
        reasons.append("NOT_FROZEN")

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total_bytes = \
        validate_manifest(candidate)

    if not manifest_ok:
        reasons.append("INVALID_MANIFEST")
        output_bytes = None
    else:
        output_bytes = total_bytes

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    prediction_ok = True

    correct = 0
    row_count = len(rows)

    slice_counts = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            prediction_ok = False
            continue

        if "label" not in row:
            prediction_ok = False
            continue

        if "slice" not in row:
            prediction_ok = False
            continue

        label = row["label"]
        slice_name = row["slice"]

        if not binary(label):
            prediction_ok = False
            continue

        if not isinstance(slice_name, str):
            prediction_ok = False
            continue

        predictions = row.get(
            "predictions"
        )

        if not isinstance(predictions, dict):
            prediction_ok = False
            continue

        if name not in predictions:
            prediction_ok = False
            continue

        prediction = predictions[name]

        if not binary(prediction):
            prediction_ok = False
            continue

        slice_counts[slice_name] = \
            slice_counts.get(slice_name, 0) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    required = policy["requiredSlices"]

    if not prediction_ok:

        aggregate = None

        slices = {
            s: None
            for s in required
        }

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if row_count == 0:
            aggregate = None
        else:
            aggregate = round(
                correct / row_count,
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

                value = round(
                    slice_correct.get(
                        slice_name,
                        0
                    ) / count,
                    12
                )

                slices[slice_name] = value

                if value < float(floor):
                    reasons.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        if (
            aggregate is None
            or aggregate
            < float(policy["aggregateFloor"])
        ):
            reasons.append(
                "AGGREGATE_FLOOR"
            )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if (
        manifest_ok
        and total_bytes > policy["maxBytes"]
    ):
        reasons.append(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = None

    if isinstance(latencies, dict):

        if name in latencies:

            value = latencies[name]

            if (
                finite_number(value)
                and float(value) >= 0
            ):

                latency = value

                if (
                    isinstance(latency, float)
                    and latency.is_integer()
                ):
                    latency = int(latency)

    if (
        latency is not None
        and float(latency)
        > float(policy["maxLatencyMs"])
    ):
        reasons.append(
            "LATENCY_LIMIT"
        )

    reasons = sort_codes(reasons)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": output_bytes,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons
    }


# ============================================================
# SELECT
# ============================================================

def select(body):

    freeze_id = body["freezeId"]

    with LOCK:
        saved = FREEZES.get(freeze_id)

    # --------------------------------------------------------
    # UNKNOWN FREEZE
    # --------------------------------------------------------

    if saved is None:

        results = []

        for candidate in body["candidates"]:

            name = ""

            if isinstance(candidate, dict):
                if isinstance(
                    candidate.get("name"),
                    str
                ):
                    name = candidate["name"]

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
            key=lambda x: b(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    frozen_candidates = \
        saved["output"]["candidates"]

    frozen_names = {
        c["name"]
        for c in frozen_candidates
    }

    frozen_map = {
        c["name"]: c
        for c in frozen_candidates
    }

    submitted_candidates = \
        body["candidates"]

    # Exact array equality.
    lineage_ok = (
        submitted_candidates
        == frozen_candidates
    )

    policy = body["policy"]

    policy_ok = valid_policy(policy)

    # --------------------------------------------------------
    # CANDIDATE ORDER SET
    # --------------------------------------------------------

    order_ok = False
    order = []

    if policy_ok:

        order = policy["candidateOrder"]

        submitted_names = []

        valid_names = True

        for c in submitted_candidates:

            if not isinstance(c, dict):
                valid_names = False
                continue

            name = c.get("name")

            if not isinstance(name, str):
                valid_names = False
                continue

            submitted_names.append(name)

        submitted_set = {
            b(x)
            for x in submitted_names
        }

        order_set = {
            b(x)
            for x in order
        }

        order_ok = (
            valid_names
            and len(submitted_names)
            == len(submitted_candidates)
            and len(order)
            == len(submitted_names)
            and submitted_set == order_set
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for candidate in submitted_candidates:

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

        result = evaluate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies", {}),
            frozen_names
        )

        if not lineage_ok:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not policy_ok or not order_ok:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(result)

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if policy_ok:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda x: (
                rank.get(
                    x["name"],
                    10**9
                ),
                b(x["name"])
            )
        )

    else:

        results.sort(
            key=lambda x: b(x["name"])
        )

    # --------------------------------------------------------
    # SELECT WINNER
    # --------------------------------------------------------

    admitted = [
        r for r in results
        if r["admitted"]
    ]

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
                    10**9
                )
            )
        )

        selected = winner["name"]

        package_manifest = frozen_map[
            selected
        ]

    else:

        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }


# ============================================================
# POST /quantize
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

        if not freeze_input_valid(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response, status = freeze(body)

        return JSONResponse(
            response,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Explicit invalid-input boundary.
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

        response = select(body)

        return JSONResponse(
            response,
            status_code=200
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
