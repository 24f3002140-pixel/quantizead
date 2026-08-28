import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

LOCK = threading.RLock()
FREEZES = {}

MAX_SAFE = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def utf8(x):
    return x.encode("utf-8")


def unique_strings(x):
    if not isinstance(x, list):
        return False
    if not all(isinstance(v, str) and len(v) > 0 for v in x):
        return False
    vals = [utf8(v) for v in x]
    return len(vals) == len(set(vals))


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
        return x in (0, 1)

    if isinstance(x, float):
        return math.isfinite(x) and x in (0.0, 1.0)

    return False


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def package_digest(inventory):
    return sha256(compact_json(inventory))


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8")
    )


def round12(x):
    return round(float(x), 12)


# ============================================================
# INVENTORY
# ============================================================

def create_inventory(files):

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

        data = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": sha256(data)
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    digest = package_digest(inventory)

    return inventory, total, digest, True


# ============================================================
# FREEZE REQUEST
# ============================================================

def freeze_request_valid(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if len(freeze_id) < 1 or len(freeze_id) > 128:
        return False

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not unique_strings(allowed):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

    encoded = [
        name.encode("utf-8")
        for name in names
    ]

    if len(encoded) != len(set(encoded)):
        return False

    return True


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id in FREEZES:

            old = FREEZES[freeze_id]

            if old["input"] == body:
                return old["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        request_cal = body[
            "calibrationDigest"
        ]

        request_tok = body[
            "tokenizerDigest"
        ]

        allowed = set(
            body[
                "allowedUnsupportedReasons"
            ]
        )

        output = []

        candidates = sorted(
            body["candidates"],
            key=lambda c:
                c["name"].encode("utf-8")
        )

        for candidate in candidates:

            name = candidate["name"]

            codes = []

            # ----------------------------------------
            # FILES
            # ----------------------------------------

            if "files" not in candidate:

                inventory = []
                total = None
                digest = None
                files_valid = False

                codes.append(
                    "INVALID_INPUT"
                )

            else:

                (
                    inventory,
                    total,
                    digest,
                    files_valid
                ) = create_inventory(
                    candidate.get("files")
                )

                if not files_valid:
                    codes.append(
                        "INVALID_INPUT"
                    )

            # ----------------------------------------
            # METADATA
            # ----------------------------------------

            loadable = candidate.get(
                "loadable"
            )

            candidate_cal = candidate.get(
                "calibrationDigest"
            )

            candidate_tok = candidate.get(
                "tokenizerDigest"
            )

            metadata_valid = True

            if not isinstance(loadable, bool):
                metadata_valid = False

            if not nonempty_string(candidate_cal):
                metadata_valid = False

            if not nonempty_string(candidate_tok):
                metadata_valid = False

            if not metadata_valid:
                codes.append(
                    "INVALID_INPUT"
                )

            # ----------------------------------------
            # UNSUPPORTED REASON
            # ----------------------------------------

            has_reason = (
                "unsupportedReason"
                in candidate
            )

            reason = candidate.get(
                "unsupportedReason"
            )

            if has_reason and not isinstance(
                reason, str
            ):
                codes.append(
                    "INVALID_INPUT"
                )
                has_reason = False

            status = "frozen"

            # ----------------------------------------
            # SUPPORTED CANDIDATE
            # ----------------------------------------

            if not has_reason:

                if metadata_valid:

                    if loadable is False:
                        codes.append(
                            "NOT_LOADABLE"
                        )

                    if candidate_cal != request_cal:
                        codes.append(
                            "CALIBRATION_MISMATCH"
                        )

                    if candidate_tok != request_tok:
                        codes.append(
                            "TOKENIZER_MISMATCH"
                        )

            # ----------------------------------------
            # EXPLICIT UNSUPPORTED REASON
            # ----------------------------------------

            else:

                if reason in allowed:

                    # Allowed reason => unsupported.
                    status = "unsupported"

                else:

                    codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

                    if metadata_valid:

                        if loadable is False:
                            codes.append(
                                "NOT_LOADABLE"
                            )

                        if candidate_cal != request_cal:
                            codes.append(
                                "CALIBRATION_MISMATCH"
                            )

                        if candidate_tok != request_tok:
                            codes.append(
                                "TOKENIZER_MISMATCH"
                            )

                    status = "invalid"

            # ----------------------------------------
            # ANY REASON => INVALID
            # except allowed unsupported
            # ----------------------------------------

            if codes:

                allowed_unsupported = (
                    has_reason
                    and reason in allowed
                    and files_valid
                    and metadata_valid
                    and all(
                        c == "INVALID_INPUT"
                        for c in codes
                    ) is False
                )

                # Structural INVALID_INPUT must always win.
                if "INVALID_INPUT" in codes:
                    status = "invalid"

                elif not allowed_unsupported:
                    status = "invalid"

            # ----------------------------------------
            # VALID ALLOWED UNSUPPORTED
            # ----------------------------------------

            if (
                has_reason
                and reason in allowed
                and files_valid
                and metadata_valid
                and "INVALID_INPUT" not in codes
            ):
                status = "unsupported"

            # ----------------------------------------
            # OUTPUT MANIFEST
            # ----------------------------------------

            if not files_valid:

                inventory_out = []
                total_out = None
                digest_out = None

            else:

                inventory_out = inventory
                total_out = total
                digest_out = digest

            output.append({
                "name": name,
                "status": status,
                "inventory": inventory_out,
                "totalBytes": total_out,
                "packageDigest": digest_out,
                "reasonCodes": sorted_codes(codes)
            })

        response = {
            "freezeId": freeze_id,
            "candidates": output
        }

        FREEZES[freeze_id] = {
            "input": body,
            "response": response
        }

        return response, 200


# ============================================================
# POLICY
# ============================================================

def policy_valid(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if not finite_number(floor):
        return False

    if not 0 <= float(floor) <= 1:
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for name, value in required.items():

        if not nonempty_string(name):
            return False

        if not finite_number(value):
            return False

        if not 0 <= float(value) <= 1:
            return False

    latency = policy.get(
        "maxLatencyMs"
    )

    if not finite_number(latency):
        return False

    if float(latency) < 0:
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_strings(order):
        return False

    return True


# ============================================================
# SELECT REQUEST
# ============================================================

def select_request_valid(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(
        body.get("freezeId")
    ):
        return False

    # Exact request-level requirements from problem.
    if not isinstance(
        body.get("candidates"),
        list
    ):
        return False

    if not isinstance(
        body.get("rows"),
        list
    ):
        return False

    if not isinstance(
        body.get("policy"),
        dict
    ):
        return False

    return True


# ============================================================
# VERIFY SUBMITTED MANIFEST
# ============================================================

def verify_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(inventory, list):
        return False, None, None

    normalized = []
    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None, None

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False, None, None

        key = name.encode("utf-8")

        if key in names:
            return False, None, None

        names.add(key)

        if not safe_integer(byte_count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
        ):
            return False, None, None

        try:
            int(digest, 16)
        except Exception:
            return False, None, None

        normalized.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest
        })

    canonical = sorted(
        normalized,
        key=lambda x:
            x["name"].encode("utf-8")
    )

    if inventory != canonical:
        return False, None, None

    total = sum(
        item["bytes"]
        for item in canonical
    )

    digest = package_digest(
        canonical
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, total, digest

    if candidate.get(
        "packageDigest"
    ) != digest:
        return False, total, digest

    return True, total, digest


# ============================================================
# CALCULATE CANDIDATE
# ============================================================

def calculate(candidate, body, frozen_names):

    name = candidate.get("name")

    codes = []

    # ----------------------------------------
    # LINEAGE
    # ----------------------------------------

    if name not in frozen_names:
        codes.append(
            "NOT_FROZEN"
        )

    if candidate.get("status") != "frozen":
        codes.append(
            "NOT_FROZEN"
        )

    # ----------------------------------------
    # MANIFEST
    # ----------------------------------------

    manifest_ok, total, digest = (
        verify_manifest(candidate)
    )

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )

    # ----------------------------------------
    # ROWS
    # ----------------------------------------

    rows = body["rows"]
    required = body[
        "policy"
    ]["requiredSlices"]

    predictions_ok = True

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_ok = False
            continue

        if "label" not in row:
            predictions_ok = False
            continue

        if "slice" not in row:
            predictions_ok = False
            continue

        label = row["label"]
        slice_name = row["slice"]

        if not binary(label):
            predictions_ok = False
            continue

        if not isinstance(
            slice_name,
            str
        ):
            predictions_ok = False
            continue

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict
        ):
            predictions_ok = False
            continue

        if name not in predictions:
            predictions_ok = False
            continue

        prediction = predictions[name]

        if not binary(prediction):
            predictions_ok = False
            continue

        prediction = int(prediction)
        label = int(label)

        if prediction == label:

            correct += 1

            slice_correct[
                slice_name
            ] = slice_correct.get(
                slice_name,
                0
            ) + 1

        slice_total[
            slice_name
        ] = slice_total.get(
            slice_name,
            0
        ) + 1

    # ----------------------------------------
    # ACCURACY
    # ----------------------------------------

    if not predictions_ok:

        aggregate = None

        slices = {
            name: None
            for name in required
        }

        codes.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if len(rows) == 0:

            aggregate = None

        else:

            aggregate = round12(
                correct / len(rows)
            )

        slices = {}

        for slice_name, floor in required.items():

            count = slice_total.get(
                slice_name,
                0
            )

            if count == 0:

                slices[slice_name] = None

                codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

            else:

                accuracy = round12(
                    slice_correct.get(
                        slice_name,
                        0
                    ) / count
                )

                slices[
                    slice_name
                ] = accuracy

                if accuracy < float(floor):

                    codes.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

        aggregate_floor = float(
            body["policy"][
                "aggregateFloor"
            ]
        )

        if (
            aggregate is None
            or aggregate < aggregate_floor
        ):

            codes.append(
                "AGGREGATE_FLOOR"
            )

    # ----------------------------------------
    # SIZE
    # ----------------------------------------

    total_out = (
        total
        if manifest_ok
        else None
    )

    if (
        manifest_ok
        and total > body["policy"]["maxBytes"]
    ):

        codes.append(
            "SIZE_LIMIT"
        )

    # ----------------------------------------
    # LATENCY
    # ----------------------------------------

    latencies = body.get(
        "latencies"
    )

    latency = None

    if (
        isinstance(latencies, dict)
        and name in latencies
        and finite_number(
            latencies[name]
        )
        and float(
            latencies[name]
        ) >= 0
    ):

        latency = float(
            latencies[name]
        )

        if latency.is_integer():
            latency = int(latency)

    else:

        latency = None

    if (
        latency is not None
        and latency
        > float(
            body["policy"][
                "maxLatencyMs"
            ]
        )
    ):

        codes.append(
            "LATENCY_LIMIT"
        )

    # ----------------------------------------
    # ADMISSION
    # ----------------------------------------

    slices_pass = True

    for slice_name, floor in required.items():

        value = slices.get(
            slice_name
        )

        if value is None:
            slices_pass = False
            break

        if value < float(floor):
            slices_pass = False
            break

    admitted = (
        name in frozen_names
        and candidate.get("status")
        == "frozen"
        and manifest_ok
        and predictions_ok
        and aggregate is not None
        and aggregate
        >= float(
            body["policy"][
                "aggregateFloor"
            ]
        )
        and slices_pass
        and total is not None
        and total
        <= body["policy"]["maxBytes"]
        and latency is not None
        and latency
        <= float(
            body["policy"][
                "maxLatencyMs"
            ]
        )
    )

    return {
        "name": (
            name
            if isinstance(name, str)
            else ""
        ),
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": sorted_codes(
            codes
        )
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:
        frozen = FREEZES.get(
            freeze_id
        )

    # ----------------------------------------
    # NOT FROZEN
    # ----------------------------------------

    if frozen is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            name = ""

            if isinstance(candidate, dict):
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
                x["name"].encode("utf-8")
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    # ----------------------------------------
    # STORED DATA
    # ----------------------------------------

    stored_candidates = frozen[
        "response"
    ]["candidates"]

    stored_names = {
        c["name"]
        for c in stored_candidates
    }

    stored_by_name = {
        c["name"]: c
        for c in stored_candidates
    }

    submitted = body[
        "candidates"
    ]

    # Exact equality.
    lineage_ok = (
        submitted
        == stored_candidates
    )

    # ----------------------------------------
    # POLICY
    # ----------------------------------------

    p_ok = policy_valid(
        body["policy"]
    )

    policy = body[
        "policy"
    ]

    submitted_names = []

    names_ok = True

    for c in submitted:

        if not isinstance(c, dict):

            names_ok = False
            continue

        name = c.get("name")

        if not nonempty_string(name):

            names_ok = False
            continue

        submitted_names.append(name)

    encoded_names = [
        x.encode("utf-8")
        for x in submitted_names
    ]

    if len(encoded_names) != len(
        set(encoded_names)
    ):
        names_ok = False

    # ----------------------------------------
    # ORDER
    # ----------------------------------------

    if p_ok:

        order = policy[
            "candidateOrder"
        ]

        order_set = {
            x.encode("utf-8")
            for x in order
        }

        names_set = {
            x.encode("utf-8")
            for x in submitted_names
        }

        order_ok = (
            len(order)
            == len(submitted_names)
            and order_set == names_set
        )

    else:

        order = []
        order_ok = False

    # ----------------------------------------
    # RESULTS
    # ----------------------------------------

    results = []

    for candidate in submitted:

        if not isinstance(
            candidate,
            dict
        ):

            result = {
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE",
                    "INVALID_POLICY"
                ]
            }

        else:

            result = calculate(
                candidate,
                body,
                stored_names
            )

            if not lineage_ok:

                result["admitted"] = False

                result["reasonCodes"] = sorted_codes(
                    result["reasonCodes"]
                    + ["INVALID_LINEAGE"]
                )

            if (
                not p_ok
                or not names_ok
                or not order_ok
            ):

                result["admitted"] = False

                result["reasonCodes"] = sorted_codes(
                    result["reasonCodes"]
                    + ["INVALID_POLICY"]
                )

        results.append(result)

    # ----------------------------------------
    # RESULT ORDER
    # ----------------------------------------

    if p_ok:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                rank.get(
                    r["name"],
                    999999999
                ),
                r["name"].encode(
                    "utf-8"
                )
            )
        )

    else:

        results.sort(
            key=lambda r:
                r["name"].encode(
                    "utf-8"
                )
        )

    # ----------------------------------------
    # WINNER
    # ----------------------------------------

    winners = [
        r
        for r in results
        if r["admitted"]
    ]

    globally_valid = (
        lineage_ok
        and p_ok
        and names_ok
        and order_ok
    )

    if winners and globally_valid:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        winner = min(
            winners,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                rank.get(
                    r["name"],
                    999999999
                )
            )
        )

        selected = winner[
            "name"
        ]

        manifest = stored_by_name[
            selected
        ]

    else:

        selected = None
        manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": manifest
    }, 200


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
            status_code=400
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {
                "error":
                "INVALID_INPUT"
            },
            status_code=400
        )

    phase = body.get(
        "phase"
    )

    # ----------------------------------------
    # FREEZE
    # ----------------------------------------

    if phase == "freeze":

        if not freeze_request_valid(
            body
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400
            )

        result, status = do_freeze(
            body
        )

        return JSONResponse(
            result,
            status_code=status
        )

    # ----------------------------------------
    # SELECT
    # ----------------------------------------

    if phase == "select":

        if not select_request_valid(
            body
        ):

            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400
            )

        result, status = do_select(
            body
        )

        return JSONResponse(
            result,
            status_code=status
        )

    # ----------------------------------------
    # UNKNOWN PHASE
    # ----------------------------------------

    return JSONResponse(
        {
            "error":
            "INVALID_INPUT"
        },
        status_code=400
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "ok": True
    }
