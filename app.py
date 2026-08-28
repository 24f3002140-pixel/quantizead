import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful in-memory storage for frozen requests.
FREEZES = {}
LOCK = threading.Lock()

SAFE_MAX = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8(value):
    return value.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: utf8(x)
    )


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
        and 0 <= value <= SAFE_MAX
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
# FILE INVENTORY
# ============================================================

def build_inventory(files):
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

    for filename, content in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    # UTF-8 filename ordering.
    inventory.sort(
        key=lambda item: utf8(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    # Exact required inventory key order:
    # name, bytes, sha256
    package_digest = sha256_bytes(
        canonical_json(inventory)
    )

    return (
        inventory,
        total_bytes,
        package_digest,
        True
    )


# ============================================================
# FREEZE REQUEST BOUNDARY
# ============================================================

def valid_freeze_request(body):

    if not isinstance(body, dict):
        return False

    # phase
    if body.get("phase") != "freeze":
        return False

    # freezeId
    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if freeze_id == "":
        return False

    if len(freeze_id) > 128:
        return False

    # Request calibration digest.
    calibration_digest = body.get(
        "calibrationDigest"
    )

    if (
        not isinstance(
            calibration_digest,
            str
        )
        or calibration_digest == ""
    ):
        return False

    # Request tokenizer digest.
    tokenizer_digest = body.get(
        "tokenizerDigest"
    )

    if (
        not isinstance(
            tokenizer_digest,
            str
        )
        or tokenizer_digest == ""
    ):
        return False

    # Allowed unsupported reasons.
    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    allowed_seen = set()

    for reason in allowed:

        if (
            not isinstance(reason, str)
            or reason == ""
        ):
            return False

        key = utf8(reason)

        if key in allowed_seen:
            return False

        allowed_seen.add(key)

    # Candidates.
    candidates = body.get(
        "candidates"
    )

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    candidate_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        # Required candidate fields.
        required_fields = [
            "name",
            "files",
            "loadable",
            "calibrationDigest",
            "tokenizerDigest"
        ]

        for field in required_fields:
            if field not in candidate:
                return False

        # Name.
        name = candidate["name"]

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        name_key = utf8(name)

        if name_key in candidate_names:
            return False

        candidate_names.add(name_key)

        # Files must be an object.
        if not isinstance(
            candidate["files"],
            dict
        ):
            return False

        # loadable must be boolean.
        if not isinstance(
            candidate["loadable"],
            bool
        ):
            return False

        # Candidate calibration digest.
        if (
            not isinstance(
                candidate["calibrationDigest"],
                str
            )
            or candidate["calibrationDigest"] == ""
        ):
            return False

        # Candidate tokenizer digest.
        if (
            not isinstance(
                candidate["tokenizerDigest"],
                str
            )
            or candidate["tokenizerDigest"] == ""
        ):
            return False

        # If unsupportedReason exists, it must be a
        # non-empty string.
        if "unsupportedReason" in candidate:

            reason = candidate[
                "unsupportedReason"
            ]

            if (
                not isinstance(reason, str)
                or reason == ""
            ):
                return False

    return True


# ============================================================
# FREEZE
# ============================================================

def freeze_candidates(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:

        # ----------------------------------------------------
        # REPLAY / CONFLICT
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            old = FREEZES[
                freeze_id
            ]

            # Exact same input => exact same response.
            if old["input"] == body:
                return (
                    old["response"],
                    200
                )

            # Same ID with different input.
            return (
                {
                    "error":
                    "FREEZE_ID_CONFLICT"
                },
                409
            )

        request_calibration = body[
            "calibrationDigest"
        ]

        request_tokenizer = body[
            "tokenizerDigest"
        ]

        allowed_reasons = set(
            body[
                "allowedUnsupportedReasons"
            ]
        )

        # Response candidates sorted by UTF-8 name.
        candidates = sorted(
            body["candidates"],
            key=lambda c:
                utf8(c["name"])
        )

        output_candidates = []

        for candidate in candidates:

            name = candidate[
                "name"
            ]

            reason_codes = []

            # ------------------------------------------------
            # ARTIFACT INVENTORY
            # ------------------------------------------------

            (
                inventory,
                total_bytes,
                package_digest,
                files_valid
            ) = build_inventory(
                candidate["files"]
            )

            if not files_valid:

                inventory = []
                total_bytes = None
                package_digest = None

            # ------------------------------------------------
            # UNSUPPORTED CANDIDATE
            # ------------------------------------------------

            has_unsupported_reason = (
                "unsupportedReason"
                in candidate
            )

            if has_unsupported_reason:

                reason = candidate[
                    "unsupportedReason"
                ]

                if reason in allowed_reasons:

                    status = "unsupported"

                else:

                    status = "invalid"

                    reason_codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

            # ------------------------------------------------
            # NORMAL CANDIDATE
            # ------------------------------------------------

            else:

                status = "frozen"

                if candidate[
                    "loadable"
                ] is not True:

                    reason_codes.append(
                        "NOT_LOADABLE"
                    )

                if candidate[
                    "calibrationDigest"
                ] != request_calibration:

                    reason_codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if candidate[
                    "tokenizerDigest"
                ] != request_tokenizer:

                    reason_codes.append(
                        "TOKENIZER_MISMATCH"
                    )

                if reason_codes:
                    status = "invalid"

            output_candidates.append({
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes":
                    sorted_codes(reason_codes)
            })

        response = {
            "freezeId": freeze_id,
            "candidates": output_candidates
        }

        # Persist complete response.
        FREEZES[freeze_id] = {
            "input": body,
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

    if not isinstance(
        inventory,
        list
    ):
        return False, None

    canonical = []
    seen_names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        # Exact manifest object shape.
        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None

        name = item.get(
            "name"
        )

        byte_count = item.get(
            "bytes"
        )

        file_digest = item.get(
            "sha256"
        )

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False, None

        name_key = utf8(name)

        if name_key in seen_names:
            return False, None

        seen_names.add(name_key)

        if not is_safe_integer(
            byte_count
        ):
            return False, None

        if (
            not isinstance(
                file_digest,
                str
            )
            or len(file_digest) != 64
        ):
            return False, None

        try:
            int(file_digest, 16)
        except Exception:
            return False, None

        canonical.append({
            "name": name,
            "bytes": byte_count,
            "sha256": file_digest
        })

    canonical.sort(
        key=lambda x:
            utf8(x["name"])
    )

    # Submitted inventory must already be canonical.
    if canonical != inventory:
        return False, None

    total_bytes = sum(
        item["bytes"]
        for item in canonical
    )

    package_digest = sha256_bytes(
        canonical_json(canonical)
    )

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
    if not is_safe_integer(
        policy.get("maxBytes")
    ):
        return False

    # aggregateFloor
    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not is_finite_number(
        aggregate_floor
    ):
        return False

    if not (
        0 <= float(aggregate_floor) <= 1
    ):
        return False

    # requiredSlices
    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required_slices,
        dict
    ):
        return False

    for slice_name, floor in \
            required_slices.items():

        if (
            not isinstance(
                slice_name,
                str
            )
            or slice_name == ""
        ):
            return False

        if not is_finite_number(
            floor
        ):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    # maxLatencyMs
    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not is_finite_number(
        max_latency
    ):
        return False

    if float(max_latency) < 0:
        return False

    # candidateOrder
    candidate_order = policy.get(
        "candidateOrder"
    )

    if not isinstance(
        candidate_order,
        list
    ):
        return False

    order_seen = set()

    for name in candidate_order:

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False

        key = utf8(name)

        if key in order_seen:
            return False

        order_seen.add(key)

    return True


# ============================================================
# CANDIDATE EVALUATION
# ============================================================

def evaluate_candidate(
    candidate,
    body,
    frozen_names
):

    name = candidate.get(
        "name",
        ""
    )

    reason_codes = []

    # --------------------------------------------------------
    # LINEAGE / FROZEN STATUS
    # --------------------------------------------------------

    if name not in frozen_names:
        reason_codes.append(
            "NOT_FROZEN"
        )

    if candidate.get(
        "status"
    ) != "frozen":
        reason_codes.append(
            "NOT_FROZEN"
        )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_valid, total_bytes = \
        validate_manifest(
            candidate
        )

    if not manifest_valid:
        reason_codes.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    rows = body[
        "rows"
    ]

    required_slices = body[
        "policy"
    ][
        "requiredSlices"
    ]

    correct = 0

    slice_total = {}
    slice_correct = {}

    predictions_valid = True

    for row in rows:

        if not isinstance(
            row,
            dict
        ):
            predictions_valid = False
            continue

        if "label" not in row:
            predictions_valid = False
            continue

        if "slice" not in row:
            predictions_valid = False
            continue

        label = row[
            "label"
        ]

        slice_name = row[
            "slice"
        ]

        if not is_binary(label):
            predictions_valid = False
            continue

        if not isinstance(
            slice_name,
            str
        ):
            predictions_valid = False
            continue

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict
        ):
            predictions_valid = False
            continue

        if name not in predictions:
            predictions_valid = False
            continue

        prediction = predictions[
            name
        ]

        if not is_binary(
            prediction
        ):
            predictions_valid = False
            continue

        slice_total[
            slice_name
        ] = slice_total.get(
            slice_name,
            0
        ) + 1

        if int(label) == int(
            prediction
        ):

            correct += 1

            slice_correct[
                slice_name
            ] = slice_correct.get(
                slice_name,
                0
            ) + 1

    # --------------------------------------------------------
    # ACCURACY
    # --------------------------------------------------------

    if not predictions_valid:

        aggregate = None

        slices = {
            slice_name: None
            for slice_name
            in required_slices
        }

        reason_codes.append(
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

        # Required slices.
        for slice_name, floor in \
                required_slices.items():

            count = slice_total.get(
                slice_name,
                0
            )

            if count == 0:

                slices[
                    slice_name
                ] = None

                reason_codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

            else:

                value = round(
                    slice_correct.get(
                        slice_name,
                        0
                    ) / count,
                    12
                )

                slices[
                    slice_name
                ] = value

                if value < float(floor):

                    reason_codes.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

        # Aggregate floor.
        if (
            aggregate is None
            or aggregate
            < float(
                body["policy"][
                    "aggregateFloor"
                ]
            )
        ):

            reason_codes.append(
                "AGGREGATE_FLOOR"
            )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    output_total_bytes = (
        total_bytes
        if manifest_valid
        else None
    )

    if (
        manifest_valid
        and total_bytes
        > body["policy"]["maxBytes"]
    ):

        reason_codes.append(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency_ms = None

    latencies = body.get(
        "latencies"
    )

    if (
        isinstance(
            latencies,
            dict
        )
        and name in latencies
    ):

        latency_value = latencies[
            name
        ]

        if (
            is_finite_number(
                latency_value
            )
            and float(
                latency_value
            ) >= 0
        ):

            latency_ms = latency_value

            if (
                isinstance(
                    latency_ms,
                    float
                )
                and latency_ms.is_integer()
            ):
                latency_ms = int(
                    latency_ms
                )

    if (
        latency_ms is not None
        and float(latency_ms)
        > float(
            body["policy"][
                "maxLatencyMs"
            ]
        )
    ):

        reason_codes.append(
            "LATENCY_LIMIT"
        )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    reason_codes = sorted_codes(
        reason_codes
    )

    admitted = (
        len(reason_codes) == 0
    )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": output_total_bytes,
        "latencyMs": latency_ms,
        "admitted": admitted,
        "reasonCodes": reason_codes
    }


# ============================================================
# SELECT
# ============================================================

def select_candidate(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # FREEZE DOES NOT EXIST
    # --------------------------------------------------------

    if stored is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            name = ""

            if isinstance(
                candidate,
                dict
            ):
                if isinstance(
                    candidate.get("name"),
                    str
                ):
                    name = candidate[
                        "name"
                    ]

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
                utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    # --------------------------------------------------------
    # STORED FREEZE
    # --------------------------------------------------------

    frozen_candidates = stored[
        "response"
    ]["candidates"]

    frozen_names = {
        candidate["name"]
        for candidate in frozen_candidates
    }

    frozen_map = {
        candidate["name"]:
            candidate
        for candidate
        in frozen_candidates
    }

    submitted_candidates = body[
        "candidates"
    ]

    # Must exactly equal the stored response.
    lineage_valid = (
        submitted_candidates
        == frozen_candidates
    )

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    policy = body[
        "policy"
    ]

    policy_valid = validate_policy(
        policy
    )

    candidate_order = (
        policy["candidateOrder"]
        if policy_valid
        else []
    )

    # --------------------------------------------------------
    # CANDIDATE ORDER SET
    # --------------------------------------------------------

    submitted_names = []

    for candidate in submitted_candidates:

        if isinstance(
            candidate,
            dict
        ):

            name = candidate.get(
                "name"
            )

            if isinstance(
                name,
                str
            ):
                submitted_names.append(
                    name
                )

    if policy_valid:

        submitted_set = {
            utf8(name)
            for name
            in submitted_names
        }

        order_set = {
            utf8(name)
            for name
            in candidate_order
        }

        order_valid = (
            len(submitted_names)
            == len(submitted_candidates)
            and len(candidate_order)
            == len(submitted_names)
            and submitted_set
            == order_set
        )

    else:

        order_valid = False

    # --------------------------------------------------------
    # EVALUATE EACH CANDIDATE
    # --------------------------------------------------------

    results = []

    for candidate in submitted_candidates:

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
            body,
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

        results.append(result)

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if policy_valid:

        ranks = {
            name: index
            for index, name
            in enumerate(
                candidate_order
            )
        }

        results.sort(
            key=lambda result: (
                ranks.get(
                    result["name"],
                    999999999
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

    eligible = [
        result
        for result in results
        if result["admitted"]
    ]

    if (
        eligible
        and lineage_valid
        and policy_valid
        and order_valid
    ):

        ranks = {
            name: index
            for index, name
            in enumerate(
                candidate_order
            )
        }

        winner = min(
            eligible,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                ranks.get(
                    result["name"],
                    999999999
                )
            )
        )

        selected = winner[
            "name"
        ]

        package_manifest = \
            frozen_map[selected]

    else:

        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest":
            package_manifest
    }


# ============================================================
# HTTP ENDPOINT
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

        if not valid_freeze_request(
            body
        ):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response, status = \
            freeze_candidates(
                body
            )

        return JSONResponse(
            response,
            status_code=status
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Required request-level shape.
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

        if not isinstance(
            body.get("freezeId"),
            str
        ):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response = select_candidate(
            body
        )

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
# HEALTH / ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": "quantize",
        "status": "ok"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
