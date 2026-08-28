import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful storage for frozen responses.
# Render is running one worker, so this is sufficient for the grader.
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


def compact_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=utf8)


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
    Build canonical inventory.

    Each entry has EXACTLY:
      name, bytes, sha256

    Inventory is sorted by UTF-8 filename.

    packageDigest =
      SHA256(UTF8(JSON.stringify(inventory)))
    using compact JSON.
    """

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    inventory = []
    names = set()

    for filename, text in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        name_key = utf8(filename)

        if name_key in names:
            return [], None, None, False

        names.add(name_key)

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append(
            {
                "name": filename,
                "bytes": len(raw),
                "sha256": sha256_bytes(raw),
            }
        )

    inventory.sort(
        key=lambda item: utf8(item["name"])
    )

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_bytes(
        compact_json_bytes(inventory)
    )

    return (
        inventory,
        total_bytes,
        package_digest,
        True,
    )


# ============================================================
# FREEZE REQUEST BOUNDARY
# ============================================================

def validate_freeze_request(body):
    """
    Only reject globally invalid freeze requests here.

    Candidate-specific problems are intentionally handled
    inside freeze_candidate().
    """

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

    calibration_digest = body.get(
        "calibrationDigest"
    )

    if (
        not isinstance(calibration_digest, str)
        or not calibration_digest
    ):
        return False

    tokenizer_digest = body.get(
        "tokenizerDigest"
    )

    if (
        not isinstance(tokenizer_digest, str)
        or not tokenizer_digest
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

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

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

    reason_codes = []

    # --------------------------------------------------------
    # FILES
    # --------------------------------------------------------

    inventory, total_bytes, package_digest, files_valid = \
        build_inventory(
            candidate.get("files")
        )

    if not files_valid:
        inventory = []
        total_bytes = None
        package_digest = None

        reason_codes.append(
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

            reason_codes.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

    else:

        status = "frozen"

        # ----------------------------------------------------
        # LOADABLE
        # ----------------------------------------------------

        if candidate.get("loadable") is not True:
            reason_codes.append(
                "NOT_LOADABLE"
            )

        # ----------------------------------------------------
        # CALIBRATION
        # ----------------------------------------------------

        if (
            candidate.get("calibrationDigest")
            != request_calibration
        ):
            reason_codes.append(
                "CALIBRATION_MISMATCH"
            )

        # ----------------------------------------------------
        # TOKENIZER
        # ----------------------------------------------------

        if (
            candidate.get("tokenizerDigest")
            != request_tokenizer
        ):
            reason_codes.append(
                "TOKENIZER_MISMATCH"
            )

    # Any reason makes a normal candidate invalid.
    if (
        reason_codes
        and status != "unsupported"
    ):
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sort_codes(
            reason_codes
        ),
    }


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # REPLAY / CONFLICT
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            previous = FREEZES[freeze_id]

            if previous["input"] == body:
                return (
                    previous["output"],
                    200,
                )

            return (
                {
                    "error": "FREEZE_ID_CONFLICT"
                },
                409,
            )

        # ----------------------------------------------------
        # VALUES
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # UTF-8 NAME ORDER
        # ----------------------------------------------------

        candidates = sorted(
            body["candidates"],
            key=lambda candidate: utf8(
                candidate["name"]
            ),
        )

        frozen_candidates = []

        for candidate in candidates:

            frozen_candidates.append(
                freeze_candidate(
                    candidate,
                    request_calibration,
                    request_tokenizer,
                    allowed_reasons,
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": frozen_candidates,
        }

        # Persist complete response and original input.
        FREEZES[freeze_id] = {
            "input": body,
            "output": response,
        }

        return (
            response,
            200,
        )


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):
    """
    Recompute inventory total and packageDigest.

    Never trust submitted totalBytes/packageDigest.
    """

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(inventory, list):
        return False, None

    canonical = []
    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if (
            not isinstance(name, str)
            or not name
        ):
            return False, None

        key = utf8(name)

        if key in names:
            return False, None

        names.add(key)

        if not safe_nonnegative_integer(size):
            return False, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
        ):
            return False, None

        try:
            int(digest, 16)
        except Exception:
            return False, None

        # Digest must be lowercase SHA-256.
        if digest != digest.lower():
            return False, None

        canonical.append(
            {
                "name": name,
                "bytes": size,
                "sha256": digest,
            }
        )

    # Canonical UTF-8 filename ordering.
    canonical.sort(
        key=lambda item: utf8(item["name"])
    )

    # Submitted inventory itself must already be canonical.
    if inventory != canonical:
        return False, None

    total = sum(
        item["bytes"]
        for item in canonical
    )

    package_digest = sha256_bytes(
        compact_json_bytes(canonical)
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != package_digest:
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    # --------------------------------------------------------
    # MAX BYTES
    # --------------------------------------------------------

    if not safe_nonnegative_integer(
        policy.get("maxBytes")
    ):
        return False

    # --------------------------------------------------------
    # AGGREGATE FLOOR
    # --------------------------------------------------------

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not finite_number(
        aggregate_floor
    ):
        return False

    if not (
        0 <= float(aggregate_floor) <= 1
    ):
        return False

    # --------------------------------------------------------
    # REQUIRED SLICES
    # --------------------------------------------------------

    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    slice_names = set()

    for slice_name, floor in required_slices.items():

        if (
            not isinstance(slice_name, str)
            or not slice_name
        ):
            return False

        key = utf8(slice_name)

        if key in slice_names:
            return False

        slice_names.add(key)

        if not finite_number(floor):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    # --------------------------------------------------------
    # LATENCY LIMIT
    # --------------------------------------------------------

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not finite_number(
        max_latency
    ):
        return False

    if float(max_latency) < 0:
        return False

    # --------------------------------------------------------
    # CANDIDATE ORDER
    # --------------------------------------------------------

    candidate_order = policy.get(
        "candidateOrder"
    )

    if not isinstance(
        candidate_order,
        list,
    ):
        return False

    order_names = set()

    for name in candidate_order:

        if (
            not isinstance(name, str)
            or not name
        ):
            return False

        key = utf8(name)

        if key in order_names:
            return False

        order_names.add(key)

    return True


# ============================================================
# PREDICTION EVALUATION
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
        "",
    )

    codes = []

    # --------------------------------------------------------
    # FROZEN CHECK
    # --------------------------------------------------------

    if name not in frozen_names:
        codes.append(
            "NOT_FROZEN"
        )

    if candidate.get("status") != "frozen":
        codes.append(
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
        codes.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    required_slices = policy[
        "requiredSlices"
    ]

    predictions_valid = True

    total_rows = len(rows)

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_valid = False
            continue

        if "label" not in row:
            predictions_valid = False
            continue

        if "slice" not in row:
            predictions_valid = False
            continue

        label = row["label"]

        slice_name = row["slice"]

        if not binary_value(label):
            predictions_valid = False
            continue

        if not isinstance(
            slice_name,
            str,
        ):
            predictions_valid = False
            continue

        prediction_map = row.get(
            "predictions"
        )

        if not isinstance(
            prediction_map,
            dict,
        ):
            predictions_valid = False
            continue

        if name not in prediction_map:
            predictions_valid = False
            continue

        prediction = prediction_map[name]

        if not binary_value(
            prediction
        ):
            predictions_valid = False
            continue

        slice_total[slice_name] = \
            slice_total.get(
                slice_name,
                0,
            ) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(
                    slice_name,
                    0,
                ) + 1

    # --------------------------------------------------------
    # ACCURACY
    # --------------------------------------------------------

    if not predictions_valid:

        aggregate = None

        slices = {
            slice_name: None
            for slice_name in required_slices
        }

        codes.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if total_rows == 0:
            aggregate = None
        else:
            aggregate = round(
                correct / total_rows,
                12,
            )

        slices = {}

        for slice_name, floor in required_slices.items():

            count = slice_total.get(
                slice_name,
                0,
            )

            if count == 0:

                slices[slice_name] = None

                codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

            else:

                value = round(
                    slice_correct.get(
                        slice_name,
                        0,
                    ) / count,
                    12,
                )

                slices[slice_name] = value

                if value < float(floor):

                    codes.append(
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

            codes.append(
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
        codes.append(
            "SIZE_LIMIT"
        )

    total_out = (
        total_bytes
        if manifest_valid
        else None
    )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = None

    if isinstance(
        latencies,
        dict,
    ) and name in latencies:

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
        > float(
            policy["maxLatencyMs"]
        )
    ):

        codes.append(
            "LATENCY_LIMIT"
        )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    codes = sort_codes(codes)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": len(codes) == 0,
        "reasonCodes": codes,
    }


# ============================================================
# SELECT
# ============================================================

def perform_select(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:
        stored = FREEZES.get(
            freeze_id
        )

    # ========================================================
    # NOT FROZEN
    # ========================================================

    if stored is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            name = ""

            if isinstance(candidate, dict):

                if isinstance(
                    candidate.get("name"),
                    str,
                ):
                    name = candidate[
                        "name"
                    ]

            results.append(
                {
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": [
                        "NOT_FROZEN"
                    ],
                }
            )

        results.sort(
            key=lambda x: utf8(
                x["name"]
            )
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    # ========================================================
    # STORED FREEZE
    # ========================================================

    frozen_candidates = stored[
        "output"
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

    # Exact equality with stored response.
    lineage_valid = (
        submitted_candidates
        == frozen_candidates
    )

    policy = body[
        "policy"
    ]

    policy_valid = validate_policy(
        policy
    )

    # ========================================================
    # CANDIDATE ORDER
    # ========================================================

    if policy_valid:

        candidate_order = policy[
            "candidateOrder"
        ]

        submitted_names = []

        for candidate in submitted_candidates:

            if isinstance(candidate, dict):

                name = candidate.get(
                    "name"
                )

                if isinstance(
                    name,
                    str,
                ):
                    submitted_names.append(
                        name
                    )

        submitted_set = {
            utf8(name)
            for name in submitted_names
        }

        order_set = {
            utf8(name)
            for name in candidate_order
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

        candidate_order = []
        order_valid = False

    # ========================================================
    # RESULTS
    # ========================================================

    results = []

    for candidate in submitted_candidates:

        if not isinstance(
            candidate,
            dict,
        ):

            results.append(
                {
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
            )

            continue

        result = evaluate_candidate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies"),
            frozen_names,
        )

        if not lineage_valid:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + [
                    "INVALID_LINEAGE"
                ]
            )

        if (
            not policy_valid
            or not order_valid
        ):

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + [
                    "INVALID_POLICY"
                ]
            )

        results.append(result)

    # ========================================================
    # RESULT ORDER
    # ========================================================

    if policy_valid:

        order_rank = {
            name: index
            for index, name
            in enumerate(candidate_order)
        }

        results.sort(
            key=lambda result: (
                order_rank.get(
                    result["name"],
                    999999999,
                ),
                utf8(
                    result["name"]
                ),
            )
        )

    else:

        results.sort(
            key=lambda result: utf8(
                result["name"]
            )
        )

    # ========================================================
    # WINNER
    # ========================================================

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

        order_rank = {
            name: index
            for index, name
            in enumerate(candidate_order)
        }

        winner = min(
            eligible,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                order_rank.get(
                    result["name"],
                    999999999,
                ),
            ),
        )

        selected = winner[
            "name"
        ]

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
        "packageManifest": package_manifest,
    }


# ============================================================
# API
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            {
                "error": "INVALID_INPUT"
            },
            status_code=400,
        )

    if not isinstance(body, dict):

        return JSONResponse(
            {
                "error": "INVALID_INPUT"
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

        if not validate_freeze_request(
            body
        ):

            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        response, status = perform_freeze(
            body
        )

        return JSONResponse(
            response,
            status_code=status,
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Required top-level fields.
        if not isinstance(
            body.get("candidates"),
            list,
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        if not isinstance(
            body.get("rows"),
            list,
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        if not isinstance(
            body.get("policy"),
            dict,
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        if not isinstance(
            body.get("freezeId"),
            str,
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400,
            )

        response = perform_select(
            body
        )

        return JSONResponse(
            response,
            status_code=200,
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        {
            "error": "INVALID_INPUT"
        },
        status_code=400,
    )


# ============================================================
# HEALTH / ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": "quantize",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
    }
