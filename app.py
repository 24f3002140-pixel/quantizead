import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful storage for frozen responses.
# Render uses one web process in your configuration.
FREEZES = {}
LOCK = threading.Lock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8(value):
    return value.encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=lambda x: utf8(x))


def is_finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def is_safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER
    )


def is_binary(value):
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


# ============================================================
# INVENTORY
# ============================================================

def create_inventory(files):
    """
    Returns:
        inventory, totalBytes, packageDigest, valid
    """

    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    # UTF-8 filename ordering.
    inventory.sort(
        key=lambda item: utf8(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    # Exact compact JSON representation.
    package_digest = sha256(
        compact_json(inventory)
    )

    return (
        inventory,
        total_bytes,
        package_digest,
        True,
    )


# ============================================================
# FREEZE GLOBAL VALIDATION
# ============================================================

def valid_freeze_request(body):
    """
    Only checks things that make the WHOLE freeze request
    globally invalid.

    Candidate-specific problems are handled later and become
    candidate status = invalid.
    """

    if not isinstance(body, dict):
        return False

    # Unknown/missing phase is invalid.
    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or not freeze_id
        or len(freeze_id) > 128
    ):
        return False

    calibration = body.get(
        "calibrationDigest"
    )

    if (
        not isinstance(calibration, str)
        or not calibration
    ):
        return False

    tokenizer = body.get(
        "tokenizerDigest"
    )

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

    seen_reasons = set()

    for reason in allowed:

        if (
            not isinstance(reason, str)
            or not reason
        ):
            return False

        key = utf8(reason)

        if key in seen_reasons:
            return False

        seen_reasons.add(key)

    candidates = body.get(
        "candidates"
    )

    # Explicitly required global invalid cases.
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names must be non-empty and unique.
    seen_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        key = utf8(name)

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
    allowed_reasons,
):
    name = candidate["name"]

    reasons = []

    # --------------------------------------------------------
    # FILES / ARTIFACT INTEGRITY
    # --------------------------------------------------------

    inventory, total_bytes, package_digest, files_valid = \
        create_inventory(
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

    if "unsupportedReason" in candidate:

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

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

    # Any reason makes candidate invalid except an
    # explicitly allowed unsupported candidate.
    if reasons and status != "unsupported":
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sort_codes(reasons),
    }


# ============================================================
# FREEZE OPERATION
# ============================================================

def perform_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # REPLAY / CONFLICT
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            saved = FREEZES[freeze_id]

            if saved["request"] == body:
                return saved["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        # Candidate response is sorted by UTF-8 name.
        candidates = sorted(
            body["candidates"],
            key=lambda c: utf8(c["name"])
        )

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        result = []

        for candidate in candidates:

            result.append(
                freeze_candidate(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed,
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": result,
        }

        # Persist complete response + original request.
        FREEZES[freeze_id] = {
            "request": body,
            "response": response,
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

    canonical = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        # Exact key order.
        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256",
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        file_digest = item.get("sha256")

        if (
            not isinstance(name, str)
            or not name
        ):
            return False, None

        key = utf8(name)

        if key in seen:
            return False, None

        seen.add(key)

        if not is_safe_integer(size):
            return False, None

        if (
            not isinstance(file_digest, str)
            or len(file_digest) != 64
            or file_digest != file_digest.lower()
        ):
            return False, None

        try:
            int(file_digest, 16)
        except Exception:
            return False, None

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": file_digest,
        })

    # Canonical UTF-8 ordering.
    ordered = sorted(
        canonical,
        key=lambda x: utf8(x["name"])
    )

    # Submitted inventory itself must already be canonical.
    if inventory != ordered:
        return False, None

    total_bytes = sum(
        item["bytes"]
        for item in ordered
    )

    package_digest = sha256(
        compact_json(ordered)
    )

    # Never trust submitted total/package digest.
    if candidate.get(
        "totalBytes"
    ) != total_bytes:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != package_digest:
        return False, None

    return True, total_bytes


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    # maxBytes
    max_bytes = policy.get(
        "maxBytes"
    )

    if not is_safe_integer(max_bytes):
        return False

    # aggregateFloor
    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if (
        not is_finite_number(aggregate_floor)
        or float(aggregate_floor) < 0
        or float(aggregate_floor) > 1
    ):
        return False

    # requiredSlices
    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(required_slices, dict):
        return False

    for slice_name, floor in required_slices.items():

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            return False

        if (
            not is_finite_number(floor)
            or float(floor) < 0
            or float(floor) > 1
        ):
            return False

    # maxLatencyMs
    max_latency = policy.get(
        "maxLatencyMs"
    )

    if (
        not is_finite_number(max_latency)
        or float(max_latency) < 0
    ):
        return False

    # candidateOrder
    candidate_order = policy.get(
        "candidateOrder"
    )

    if not isinstance(candidate_order, list):
        return False

    seen = set()

    for name in candidate_order:

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        key = utf8(name)

        if key in seen:
            return False

        seen.add(key)

    return True


# ============================================================
# CANDIDATE EVALUATION
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies,
    frozen_names,
):
    name = candidate.get(
        "name",
        ""
    )

    reasons = []

    # --------------------------------------------------------
    # FROZEN / LINEAGE
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
        validate_manifest(candidate)

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

    slice_counts = {}
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

        if not is_binary(label):
            prediction_valid = False
            continue

        if not isinstance(slice_name, str):
            prediction_valid = False
            continue

        predictions = row.get(
            "predictions"
        )

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

        slice_counts[slice_name] = \
            slice_counts.get(slice_name, 0) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    required_slices = policy[
        "requiredSlices"
    ]

    # Invalid predictions => null metrics.
    if not prediction_valid:

        aggregate = None

        slices = {
            slice_name: None
            for slice_name in required_slices
        }

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        # Aggregate accuracy.
        if len(rows) == 0:
            aggregate = None
        else:
            aggregate = round(
                correct / len(rows),
                12
            )

        slices = {}

        # Required slices.
        for slice_name, floor in \
                required_slices.items():

            count = slice_counts.get(
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

        # Aggregate floor.
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

    if isinstance(latencies, dict):

        if name in latencies:

            value = latencies[name]

            if (
                is_finite_number(value)
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
        > float(
            policy["maxLatencyMs"]
        )
    ):
        reasons.append(
            "LATENCY_LIMIT"
        )

    reasons = sort_codes(reasons)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": output_total_bytes,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons,
    }


# ============================================================
# SELECT
# ============================================================

def perform_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with LOCK:
        saved = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # NOT FROZEN
    # --------------------------------------------------------

    if saved is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            if isinstance(candidate, dict):

                name = candidate.get(
                    "name",
                    ""
                )

                if not isinstance(name, str):
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

    frozen_candidates = saved[
        "response"
    ]["candidates"]

    frozen_names = {
        candidate["name"]
        for candidate in frozen_candidates
    }

    frozen_map = {
        candidate["name"]: candidate
        for candidate in frozen_candidates
    }

    submitted_candidates = body[
        "candidates"
    ]

    # --------------------------------------------------------
    # EXACT LINEAGE
    # --------------------------------------------------------

    lineage_valid = (
        submitted_candidates
        == frozen_candidates
    )

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    policy = body["policy"]

    policy_valid = validate_policy(
        policy
    )

    # --------------------------------------------------------
    # CANDIDATE ORDER
    # --------------------------------------------------------

    order = []
    order_valid = False

    if policy_valid:

        order = policy[
            "candidateOrder"
        ]

        submitted_names = []
        names_valid = True

        for candidate in submitted_candidates:

            if not isinstance(candidate, dict):
                names_valid = False
                continue

            name = candidate.get(
                "name"
            )

            if not isinstance(name, str):
                names_valid = False
                continue

            submitted_names.append(name)

        submitted_set = {
            utf8(name)
            for name in submitted_names
        }

        order_set = {
            utf8(name)
            for name in order
        }

        order_valid = (
            names_valid
            and len(submitted_names)
            == len(submitted_candidates)
            and len(order)
            == len(submitted_names)
            and submitted_set
            == order_set
        )

    # --------------------------------------------------------
    # EVALUATE EACH CANDIDATE
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
                ],
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
            frozen_names,
        )

        if not lineage_valid:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if (
            not policy_valid
            or not order_valid
        ):

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(result)

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
            key=lambda result: (
                ranking.get(
                    result["name"],
                    10**9
                ),
                utf8(result["name"])
            )
        )

    else:

        results.sort(
            key=lambda result:
                utf8(result["name"])
        )

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
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

        # Smaller bytes,
        # then lower latency,
        # then candidateOrder.
        winner = min(
            admitted,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                ranking.get(
                    result["name"],
                    10**9
                )
            )
        )

        selected = winner["name"]

        package_manifest = frozen_map[
            selected
        ]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
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
            {
                "error":
                "INVALID_INPUT"
            },
            status_code=400,
        )

    if not isinstance(body, dict):

        return JSONResponse(
            {
                "error":
                "INVALID_INPUT"
            },
            status_code=400,
        )

    phase = body.get(
        "phase"
    )

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not valid_freeze_request(body):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = \
            perform_freeze(body)

        return JSONResponse(
            response,
            status_code=status,
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # The specification explicitly requires
        # candidates and rows to be arrays and
        # policy to be an object.
        if not isinstance(
            body.get("candidates"),
            list,
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        if not isinstance(
            body.get("rows"),
            list,
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        if not isinstance(
            body.get("policy"),
            dict,
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400,
            )

        # Everything else is evaluated as a selection result.
        response = perform_select(body)

        return JSONResponse(
            response,
            status_code=200,
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        {
            "error":
            "INVALID_INPUT"
        },
        status_code=400,
    )


# ============================================================
# HEALTH / ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "quantize-admission-api",
        "endpoint": "/quantize",
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
