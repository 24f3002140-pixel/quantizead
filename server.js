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


# ============================================================
# HELPERS
# ============================================================

def utf8(value):
    return value.encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(
        set(codes),
        key=utf8
    )


def finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
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


# ============================================================
# FILE INVENTORY
# ============================================================

def make_inventory(files):
    if not isinstance(files, dict) or len(files) == 0:
        return [], None, None, False

    inventory = []
    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        name_bytes = utf8(filename)

        if name_bytes in seen:
            return [], None, None, False

        seen.add(name_bytes)

        # File content is DATA.
        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw)
        })

    inventory.sort(
        key=lambda item: utf8(item["name"])
    )

    total = 0

    for item in inventory:
        total += item["bytes"]

        if total > SAFE_MAX:
            return [], None, None, False

    package_digest = sha256(
        compact_json(inventory)
    )

    return (
        inventory,
        total,
        package_digest,
        True
    )


# ============================================================
# FREEZE INPUT
# ============================================================

def valid_freeze(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if (
        not isinstance(freeze_id, str)
        or len(freeze_id) == 0
        or len(freeze_id) > 128
    ):
        return False

    calibration = body.get("calibrationDigest")

    if (
        not isinstance(calibration, str)
        or len(calibration) == 0
    ):
        return False

    tokenizer = body.get("tokenizerDigest")

    if (
        not isinstance(tokenizer, str)
        or len(tokenizer) == 0
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
            or len(reason) == 0
        ):
            return False

        key = utf8(reason)

        if key in allowed_seen:
            return False

        allowed_seen.add(key)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    candidate_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if (
            not isinstance(name, str)
            or len(name) == 0
        ):
            return False

        key = utf8(name)

        if key in candidate_names:
            return False

        candidate_names.add(key)

    return True


# ============================================================
# FREEZE
# ============================================================

def process_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # ----------------------------------------------------
        # REPLAY / CONFLICT
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            previous = FREEZES[freeze_id]

            if previous["input"] == body:
                return previous["output"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        request_calibration = body[
            "calibrationDigest"
        ]

        request_tokenizer = body[
            "tokenizerDigest"
        ]

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        # ----------------------------------------------------
        # CANDIDATE SORTING
        # ----------------------------------------------------

        candidates = sorted(
            body["candidates"],
            key=lambda c: utf8(c["name"])
        )

        output_candidates = []

        # ----------------------------------------------------
        # PROCESS EACH CANDIDATE
        # ----------------------------------------------------

        for candidate in candidates:

            name = candidate["name"]

            codes = []

            # =================================================
            # FILES
            # =================================================

            (
                inventory,
                total_bytes,
                package_digest,
                files_ok
            ) = make_inventory(
                candidate.get("files")
            )

            if not files_ok:
                inventory = []
                total_bytes = None
                package_digest = None

                codes.append(
                    "INVALID_INPUT"
                )

            # =================================================
            # UNSUPPORTED REASON
            # =================================================

            has_reason = (
                "unsupportedReason" in candidate
                and candidate.get(
                    "unsupportedReason"
                ) is not None
                and candidate.get(
                    "unsupportedReason"
                ) != ""
            )

            if has_reason:

                reason = candidate.get(
                    "unsupportedReason"
                )

                if (
                    isinstance(reason, str)
                    and reason in allowed
                ):
                    status = "unsupported"

                else:
                    status = "invalid"

                    codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

            else:

                status = "frozen"

                # =============================================
                # LOADABLE
                # =============================================

                if candidate.get("loadable") is not True:
                    codes.append(
                        "NOT_LOADABLE"
                    )

                # =============================================
                # CALIBRATION
                # =============================================

                if (
                    candidate.get(
                        "calibrationDigest"
                    )
                    != request_calibration
                ):
                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                # =============================================
                # TOKENIZER
                # =============================================

                if (
                    candidate.get(
                        "tokenizerDigest"
                    )
                    != request_tokenizer
                ):
                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

            # =================================================
            # ANY REASON => INVALID
            # =================================================

            if codes and status != "unsupported":
                status = "invalid"

            output_candidates.append({
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": sort_codes(codes)
            })

        # =====================================================
        # EXACT RESPONSE
        # =====================================================

        output = {
            "freezeId": freeze_id,
            "candidates": output_candidates
        }

        # =====================================================
        # PERSIST COMPLETE RESPONSE
        # =====================================================

        FREEZES[freeze_id] = {
            "input": json.loads(
                json.dumps(body, ensure_ascii=False)
            ),
            "output": json.loads(
                json.dumps(output, ensure_ascii=False)
            )
        }

        return output, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(inventory, list):
        return False, None

    canonical_inventory = []
    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        # Exact manifest keys.
        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if (
            not isinstance(name, str)
            or len(name) == 0
        ):
            return False, None

        name_key = utf8(name)

        if name_key in names:
            return False, None

        names.add(name_key)

        if not safe_integer(size):
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

        canonical_inventory.append({
            "name": name,
            "bytes": size,
            "sha256": digest
        })

    sorted_inventory = sorted(
        canonical_inventory,
        key=lambda item: utf8(item["name"])
    )

    if canonical_inventory != sorted_inventory:
        return False, None

    total = 0

    for item in canonical_inventory:
        total += item["bytes"]

        if total > SAFE_MAX:
            return False, None

    package_digest = sha256(
        compact_json(canonical_inventory)
    )

    # Never trust submitted total.
    if candidate.get("totalBytes") != total:
        return False, None

    # Never trust submitted package digest.
    if (
        candidate.get("packageDigest")
        != package_digest
    ):
        return False, None

    return True, total


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    # --------------------------------------------------------
    # AGGREGATE FLOOR
    # --------------------------------------------------------

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not finite(aggregate_floor):
        return False

    if not (
        0 <= float(aggregate_floor) <= 1
    ):
        return False

    # --------------------------------------------------------
    # REQUIRED SLICES
    # --------------------------------------------------------

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for slice_name, floor in required.items():

        if (
            not isinstance(slice_name, str)
            or len(slice_name) == 0
        ):
            return False

        if not finite(floor):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not finite(max_latency):
        return False

    if float(max_latency) < 0:
        return False

    # --------------------------------------------------------
    # CANDIDATE ORDER
    # --------------------------------------------------------

    order = policy.get(
        "candidateOrder"
    )

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if (
            not isinstance(name, str)
            or len(name) == 0
        ):
            return False

        key = utf8(name)

        if key in seen:
            return False

        seen.add(key)

    return True


# ============================================================
# PREDICTION EVALUATION
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    required_slices,
    aggregate_floor,
    max_bytes,
    max_latency,
    latencies
):

    name = candidate.get(
        "name",
        ""
    )

    codes = []

    # --------------------------------------------------------
    # FROZEN STATUS
    # --------------------------------------------------------

    if candidate.get("status") != "frozen":
        codes.append(
            "NOT_FROZEN"
        )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total_bytes = \
        validate_manifest(candidate)

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )
        total_out = None
    else:
        total_out = total_bytes

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    predictions_valid = True

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

        if not binary(label):
            predictions_valid = False
            continue

        if not isinstance(slice_name, str):
            predictions_valid = False
            continue

        predictions = row.get(
            "predictions"
        )

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

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    # --------------------------------------------------------
    # INVALID PREDICTIONS
    # --------------------------------------------------------

    if not predictions_valid:

        aggregate = None

        slices = {
            name: None
            for name in required_slices
        }

        codes.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if len(rows) == 0:
            aggregate = None

            # Empty rows cannot establish required slices.
            slices = {
                name: None
                for name in required_slices
            }

            for slice_name in required_slices:
                codes.append(
                    "MISSING_SLICE:" + slice_name
                )

            codes.append(
                "AGGREGATE_FLOOR"
            )

        else:

            aggregate = round(
                correct / len(rows),
                12
            )

            slices = {}

            # ===============================================
            # REQUIRED SLICES
            # ===============================================

            for slice_name, floor in required_slices.items():

                count = slice_total.get(
                    slice_name,
                    0
                )

                if count == 0:

                    slices[slice_name] = None

                    codes.append(
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
                        codes.append(
                            "SLICE_FLOOR:" + slice_name
                        )

            # ===============================================
            # AGGREGATE
            # ===============================================

            if (
                aggregate <
                float(aggregate_floor)
            ):
                codes.append(
                    "AGGREGATE_FLOOR"
                )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if (
        manifest_ok
        and total_bytes > max_bytes
    ):
        codes.append(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = None

    if (
        isinstance(latencies, dict)
        and name in latencies
    ):

        value = latencies[name]

        if (
            finite(value)
            and float(value) >= 0
        ):
            latency = value

            if (
                isinstance(latency, float)
                and latency.is_integer()
            ):
                latency = int(latency)

    if latency is None:
        # Value cannot be validated.
        # Do NOT add an invented error code.
        #
        # Instead, admission is prevented below.
        pass

    elif (
        float(latency)
        > float(max_latency)
    ):
        codes.append(
            "LATENCY_LIMIT"
        )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    reason_codes = sort_codes(codes)

    admitted = (
        len(reason_codes) == 0
        and candidate.get("status") == "frozen"
        and manifest_ok
        and predictions_valid
        and aggregate is not None
        and total_bytes is not None
        and latency is not None
    )

    /*
     * Python comment intentionally below.
     */

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": reason_codes
    }


# ============================================================
# SELECT
# ============================================================

def process_select(body):

    freeze_id = body["freezeId"]

    with LOCK:
        stored = FREEZES.get(freeze_id)

    # ========================================================
    # NO FROZEN ID
    # ========================================================

    if stored is None:

        results = []

        for candidate in body["candidates"]:

            if (
                isinstance(candidate, dict)
                and isinstance(
                    candidate.get("name"),
                    str
                )
            ):
                name = candidate["name"]
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
            key=lambda x: utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
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

    submitted = body["candidates"]

    # EXACT candidate array equality.
    lineage_ok = (
        submitted == frozen_candidates
    )

    policy = body["policy"]

    policy_ok = validate_policy(
        policy
    )

    if policy_ok:
        order = policy["candidateOrder"]
    else:
        order = []

    # ========================================================
    # CANDIDATE NAME SET VS ORDER
    # ========================================================

    submitted_names = []

    malformed_name = False

    for candidate in submitted:

        if not isinstance(candidate, dict):
            malformed_name = True
            continue

        name = candidate.get("name")

        if not isinstance(name, str):
            malformed_name = True
            continue

        submitted_names.append(name)

    if policy_ok:

        submitted_set = {
            utf8(name)
            for name in submitted_names
        }

        order_set = {
            utf8(name)
            for name in order
        }

        order_ok = (
            not malformed_name
            and len(submitted_names)
            == len(submitted)
            and len(order)
            == len(submitted_names)
            and len(submitted_set)
            == len(submitted_names)
            and submitted_set
            == order_set
        )

    else:
        order_ok = False

    # ========================================================
    # ROWS
    # ========================================================

    rows = body["rows"]

    rows_valid = isinstance(rows, list)

    # ========================================================
    # LATENCIES
    # ========================================================

    latencies = body.get(
        "latencies"
    )

    # ========================================================
    # RESULTS
    # ========================================================

    results = []

    for candidate in submitted:

        # ----------------------------------------------------
        # Completely malformed candidate.
        # ----------------------------------------------------

        if not isinstance(candidate, dict):

            results.append({
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_codes([
                    "INVALID_LINEAGE",
                    "INVALID_POLICY"
                ])
            })

            continue

        # ----------------------------------------------------
        # Base result
        # ----------------------------------------------------

        if policy_ok and rows_valid:

            result = evaluate_candidate(
                candidate,
                rows,
                policy["requiredSlices"],
                policy["aggregateFloor"],
                policy["maxBytes"],
                policy["maxLatencyMs"],
                latencies
            )

        else:

            result = {
                "name": candidate.get(
                    "name",
                    ""
                ),
                "aggregate": None,
                "slices": (
                    {
                        name: None
                        for name in policy.get(
                            "requiredSlices",
                            {}
                        )
                    }
                    if policy_ok
                    else {}
                ),
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": []
            }

            result["reasonCodes"].append(
                "INVALID_PREDICTIONS"
            )

        # ----------------------------------------------------
        # Lineage
        # ----------------------------------------------------

        if not lineage_ok:
            result["reasonCodes"].append(
                "INVALID_LINEAGE"
            )

        # ----------------------------------------------------
        # Policy
        # ----------------------------------------------------

        if not policy_ok or not order_ok:
            result["reasonCodes"].append(
                "INVALID_POLICY"
            )

        # ----------------------------------------------------
        # Finalize
        # ----------------------------------------------------

        result["reasonCodes"] = sort_codes(
            result["reasonCodes"]
        )

        result["admitted"] = (
            len(result["reasonCodes"]) == 0
        )

        results.append(result)

    # ========================================================
    # RESULT ORDER
    # ========================================================

    if policy_ok:

        rank = {
            name: index
            for index, name in enumerate(order)
        }

        results.sort(
            key=lambda result: (
                rank.get(
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

    # ========================================================
    # WINNER
    # ========================================================

    eligible = [
        result
        for result in results
        if result["admitted"]
    ]

    selected = None
    package_manifest = None

    if (
        eligible
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        rank = {
            name: index
            for index, name in enumerate(order)
        }

        winner = min(
            eligible,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                rank.get(
                    result["name"],
                    999999999
                ),
                utf8(result["name"])
            )
        )

        selected = winner["name"]

        # EXACT recorded winner object.
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
# POST /quantize
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
            status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {
                "error": "INVALID_INPUT"
            },
            status_code=400
        )

    phase = body.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not valid_freeze(body):

            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400
            )

        response, status = process_freeze(
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

        /*
         * Assignment explicitly says:
         * candidates + rows must be arrays
         * policy must be an object.
         */

        if not isinstance(
            body.get("candidates"),
            list
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("rows"),
            list
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("policy"),
            dict
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("freezeId"),
            str
        ):
            return JSONResponse(
                {
                    "error": "INVALID_INPUT"
                },
                status_code=400
            )

        # IMPORTANT:
        # process_select() returns the actual response body,
        # NOT {status, body}.
        response = process_select(
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
        {
            "error": "INVALID_INPUT"
        },
        status_code=400
    )


# ============================================================
# HEALTH
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
