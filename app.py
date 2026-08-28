import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Persistent for the lifetime of the Render process.
# Render is configured with one worker, so this is sufficient
# for the stateful grader.
FREEZE_STORE = {}
LOCK = threading.Lock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# HELPERS
# ============================================================

def u8(value: str):
    return value.encode("utf-8")


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: u8(x)
    )


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


def binary_prediction(value):
    if isinstance(value, bool):
        return False

    if isinstance(value, int):
        return value in (0, 1)

    if isinstance(value, float):
        return (
            math.isfinite(value)
            and value in (0.0, 1.0)
        )

    return False


# ============================================================
# INVENTORY
# ============================================================

def make_inventory(files):
    """
    Returns:
        inventory,
        totalBytes,
        packageDigest,
        valid
    """

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    inventory = []
    seen_names = set()

    for filename, text in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if u8(filename) in seen_names:
            return [], None, None, False

        seen_names.add(u8(filename))

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    inventory.sort(
        key=lambda x: u8(x["name"])
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_bytes(
        compact_json(inventory)
    )

    return (
        inventory,
        total,
        package_digest,
        True
    )


# ============================================================
# GLOBAL FREEZE VALIDATION
# ============================================================

def valid_freeze_boundary(body):
    """
    Only conditions that make the entire freeze request
    INVALID_INPUT / HTTP 400.

    Candidate-specific errors are NOT rejected here.
    """

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or freeze_id == ""
        or len(freeze_id) > 128
    ):
        return False

    calibration = body.get(
        "calibrationDigest"
    )

    if (
        not isinstance(calibration, str)
        or calibration == ""
    ):
        return False

    tokenizer = body.get(
        "tokenizerDigest"
    )

    if (
        not isinstance(tokenizer, str)
        or tokenizer == ""
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    seen_allowed = set()

    for reason in allowed:

        if (
            not isinstance(reason, str)
            or reason == ""
        ):
            return False

        if reason in seen_allowed:
            return False

        seen_allowed.add(reason)

    candidates = body.get(
        "candidates"
    )

    # Explicit specification:
    # empty/non-array freeze candidate list => 400
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names must be non-empty and unique.
    # Other candidate errors are handled at candidate level.
    seen_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        if name in seen_names:
            return False

        seen_names.add(name)

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_one(
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

    inventory, total_bytes, package_digest, files_valid = \
        make_inventory(
            candidate.get("files")
        )

    if not files_valid:

        inventory = []
        total_bytes = None
        package_digest = None

        reasons.append(
            "INVALID_INPUT"
        )

    # --------------------------------------------------------
    # UNSUPPORTED REASON
    # --------------------------------------------------------

    has_reason = (
        "unsupportedReason" in candidate
    )

    if has_reason:

        reason = candidate.get(
            "unsupportedReason"
        )

        # Only an explicitly allowed reason makes the
        # candidate unsupported.
        if (
            isinstance(reason, str)
            and reason != ""
            and reason in allowed_reasons
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

            reasons.append(
                "NOT_LOADABLE"
            )

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

    # Any actual reason makes the candidate invalid.
    #
    # This is important for cases such as:
    # allowed unsupportedReason + invalid files.
    if reasons:
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

def freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # Replay / conflict
        if freeze_id in FREEZE_STORE:

            saved = FREEZE_STORE[freeze_id]

            if saved["request"] == body:
                return (
                    saved["response"],
                    200
                )

            return (
                {
                    "error":
                    "FREEZE_ID_CONFLICT"
                },
                409
            )

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = sorted(
            body["candidates"],
            key=lambda c: u8(c["name"])
        )

        output = []

        for candidate in candidates:

            output.append(
                freeze_one(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": output
        }

        # Reserve only after global freeze validation succeeds.
        FREEZE_STORE[freeze_id] = {
            "request": body,
            "response": response
        }

        return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(inventory, list):
        return False, None

    clean = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        # Exact key order.
        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256"
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False, None

        name_key = u8(name)

        if name_key in seen:
            return False, None

        seen.add(name_key)

        if not safe_integer(size):
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

        clean.append({
            "name": name,
            "bytes": size,
            "sha256": digest
        })

    ordered = sorted(
        clean,
        key=lambda x: u8(x["name"])
    )

    # Inventory must be canonical.
    if inventory != ordered:
        return False, None

    total = sum(
        x["bytes"]
        for x in ordered
    )

    digest = sha256_bytes(
        compact_json(ordered)
    )

    # Recompute. Never trust submitted total.
    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != digest:
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    # maxBytes
    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    # aggregateFloor
    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if (
        not finite_number(aggregate_floor)
        or float(aggregate_floor) < 0
        or float(aggregate_floor) > 1
    ):
        return False

    # requiredSlices
    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    seen_slices = set()

    for slice_name, floor in required.items():

        if (
            not isinstance(slice_name, str)
            or slice_name == ""
        ):
            return False

        if slice_name in seen_slices:
            return False

        seen_slices.add(slice_name)

        if (
            not finite_number(floor)
            or float(floor) < 0
            or float(floor) > 1
        ):
            return False

    # maxLatencyMs
    latency_limit = policy.get(
        "maxLatencyMs"
    )

    if (
        not finite_number(latency_limit)
        or float(latency_limit) < 0
    ):
        return False

    # candidateOrder
    order = policy.get(
        "candidateOrder"
    )

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        if name in seen:
            return False

        seen.add(name)

    return True


# ============================================================
# EVALUATE
# ============================================================

def evaluate_candidate(
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

        reasons.append(
            "NOT_FROZEN"
        )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_valid, total_bytes = \
        validate_manifest(
            candidate
        )

    if manifest_valid:

        output_total_bytes = total_bytes

    else:

        output_total_bytes = None

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

    for row in rows:

        if not isinstance(row, dict):

            prediction_valid = False
            continue

        if "label" not in row:

            prediction_valid = False
            continue

        if "slice" not in row:

            prediction_valid = False
            continue

        label = row["label"]
        slice_name = row["slice"]

        if not binary_prediction(label):

            prediction_valid = False
            continue

        if not isinstance(
            slice_name,
            str
        ):

            prediction_valid = False
            continue

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict
        ):

            prediction_valid = False
            continue

        if name not in predictions:

            prediction_valid = False
            continue

        prediction = predictions[name]

        if not binary_prediction(
            prediction
        ):

            prediction_valid = False
            continue

        slice_total[slice_name] = \
            slice_total.get(
                slice_name,
                0
            ) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(
                    slice_name,
                    0
                ) + 1

    required = policy[
        "requiredSlices"
    ]

    # Invalid predictions => ALL metrics null.
    if not prediction_valid:

        aggregate = None

        slices = {
            slice_name: None
            for slice_name in required
        }

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if len(rows) == 0:

            aggregate = None

        else:

            aggregate = round(
                correct / len(rows),
                12
            )

        slices = {}

        for slice_name, floor in required.items():

            count = slice_total.get(
                slice_name,
                0
            )

            if count == 0:

                slices[slice_name] = None

                reasons.append(
                    "MISSING_SLICE:"
                    + slice_name
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
                        "SLICE_FLOOR:"
                        + slice_name
                    )

        if (
            aggregate is None
            or aggregate
            < float(
                policy["aggregateFloor"]
            )
        ):

            reasons.append(
                "AGGREGATE_FLOOR"
            )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if (
        manifest_valid
        and total_bytes
        > policy["maxBytes"]
    ):

        reasons.append(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = None

    if isinstance(
        latencies,
        dict
    ):

        if name in latencies:

            value = latencies[name]

            if (
                finite_number(value)
                and float(value) >= 0
            ):

                latency = value

                if (
                    isinstance(
                        latency,
                        float
                    )
                    and latency.is_integer()
                ):
                    latency = int(latency)

    if (
        latency is not None
        and float(latency)
        > float(
            policy["maxLatencyMs"]
        )
    ):

        reasons.append(
            "LATENCY_LIMIT"
        )

    reasons = sorted_codes(
        reasons
    )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": output_total_bytes,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons
    }


# ============================================================
# SELECT
# ============================================================

def select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with LOCK:
        saved = FREEZE_STORE.get(
            freeze_id
        )

    # --------------------------------------------------------
    # UNKNOWN FREEZE
    # --------------------------------------------------------

    if saved is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            if isinstance(
                candidate,
                dict
            ):

                name = candidate.get(
                    "name",
                    ""
                )

                if not isinstance(
                    name,
                    str
                ):
                    name = ""

            else:

                name = ""

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
            key=lambda x:
                u8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    frozen_candidates = saved[
        "response"
    ]["candidates"]

    frozen_names = {
        c["name"]
        for c in frozen_candidates
    }

    frozen_map = {
        c["name"]: c
        for c in frozen_candidates
    }

    supplied_candidates = body[
        "candidates"
    ]

    # Exact stored response comparison.
    lineage_valid = (
        supplied_candidates
        == frozen_candidates
    )

    policy = body[
        "policy"
    ]

    policy_valid = validate_policy(
        policy
    )

    # --------------------------------------------------------
    # CANDIDATE ORDER
    # --------------------------------------------------------

    order_valid = False
    order = []

    if policy_valid:

        order = policy[
            "candidateOrder"
        ]

        supplied_names = []
        names_valid = True

        for candidate in supplied_candidates:

            if not isinstance(
                candidate,
                dict
            ):

                names_valid = False
                continue

            name = candidate.get(
                "name"
            )

            if not isinstance(
                name,
                str
            ):

                names_valid = False
                continue

            supplied_names.append(
                name
            )

        supplied_set = {
            u8(name)
            for name in supplied_names
        }

        order_set = {
            u8(name)
            for name in order
        }

        order_valid = (
            names_valid
            and len(supplied_names)
            == len(supplied_candidates)
            and len(order)
            == len(supplied_names)
            and supplied_set
            == order_set
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for candidate in supplied_candidates:

        if not isinstance(
            candidate,
            dict
        ):

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
            body["rows"],
            policy,
            body.get(
                "latencies",
                {}
            ),
            frozen_names
        )

        if not lineage_valid:

            result["admitted"] = False

            result["reasonCodes"] = \
                sorted_codes(
                    result["reasonCodes"]
                    + ["INVALID_LINEAGE"]
                )

        if (
            not policy_valid
            or not order_valid
        ):

            result["admitted"] = False

            result["reasonCodes"] = \
                sorted_codes(
                    result["reasonCodes"]
                    + ["INVALID_POLICY"]
                )

        results.append(
            result
        )

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if policy_valid:

        ranking = {
            name: index
            for index, name
            in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                ranking.get(
                    r["name"],
                    10**9
                ),
                u8(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r:
                u8(r["name"])
        )

    # --------------------------------------------------------
    # SELECT WINNER
    # --------------------------------------------------------

    admitted = [
        r
        for r in results
        if r["admitted"]
    ]

    selected = None
    package_manifest = None

    if (
        admitted
        and lineage_valid
        and policy_valid
        and order_valid
    ):

        ranking = {
            name: index
            for index, name
            in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                ranking.get(
                    r["name"],
                    10**9
                )
            )
        )

        selected = winner[
            "name"
        ]

        # Exactly the recorded frozen object.
        package_manifest = frozen_map[
            selected
        ]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest
    }


# ============================================================
# API
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    # JSON parsing
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    if not isinstance(
        body,
        dict
    ):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400
        )

    phase = body.get(
        "phase"
    )

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not valid_freeze_boundary(
            body
        ):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = freeze(
            body
        )

        return JSONResponse(
            result,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # ONLY the explicitly specified global select
        # boundary is rejected with HTTP 400.
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

        result = select(
            body
        )

        return JSONResponse(
            result,
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
        "status": "ok",
        "service": "quantize",
        "endpoint": "/quantize"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
