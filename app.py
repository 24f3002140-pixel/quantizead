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


def utf8(x):
    return x.encode("utf-8")


def sha256(x):
    return hashlib.sha256(x).hexdigest()


def compact_json(x):
    return json.dumps(
        x,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=utf8)


def finite(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= SAFE_MAX
    )


def binary(x):
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return x == 0 or x == 1
    if isinstance(x, float):
        return math.isfinite(x) and (
            x == 0.0 or x == 1.0
        )
    return False


# ============================================================
# FILE INVENTORY
# ============================================================

def make_inventory(files):

    if not isinstance(files, dict) or not files:
        return [], None, None, False

    result = []

    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if not filename:
            return [], None, None, False

        if utf8(filename) in seen:
            return [], None, None, False

        seen.add(utf8(filename))

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        result.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw)
        })

    result.sort(
        key=lambda x: utf8(x["name"])
    )

    total = sum(
        x["bytes"]
        for x in result
    )

    package = sha256(
        compact_json(result)
    )

    return result, total, package, True


# ============================================================
# ONLY GLOBAL FREEZE SHAPE VALIDATION
# ============================================================

def valid_freeze(body):

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

    calibration = body.get(
        "calibrationDigest"
    )

    tokenizer = body.get(
        "tokenizerDigest"
    )

    if not isinstance(calibration, str) or not calibration:
        return False

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    seen_allowed = set()

    for x in allowed:

        if not isinstance(x, str) or not x:
            return False

        key = utf8(x)

        if key in seen_allowed:
            return False

        seen_allowed.add(key)

    candidates = body.get(
        "candidates"
    )

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for c in candidates:

        if not isinstance(c, dict):
            return False

        # Only name is a global candidate requirement.
        name = c.get("name")

        if not isinstance(name, str) or not name:
            return False

        key = utf8(name)

        if key in names:
            return False

        names.add(key)

    return True


# ============================================================
# FREEZE
# ============================================================

def freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id in FREEZES:

            old = FREEZES[freeze_id]

            if old["input"] == body:
                return old["output"], 200

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
            body["allowedUnsupportedReasons"]
        )

        candidates = sorted(
            body["candidates"],
            key=lambda x: utf8(x["name"])
        )

        result = []

        for c in candidates:

            name = c["name"]

            codes = []

            # ------------------------------------------------
            # FILES
            # ------------------------------------------------

            files = c.get("files")

            inv, total, package, files_ok = \
                make_inventory(files)

            if not files_ok:

                inv = []
                total = None
                package = None

                codes.append(
                    "INVALID_INPUT"
                )

            # ------------------------------------------------
            # UNSUPPORTED REASON
            # ------------------------------------------------

            if "unsupportedReason" in c:

                reason = c.get(
                    "unsupportedReason"
                )

                if (
                    isinstance(reason, str)
                    and reason
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

                # Candidate semantic validation.
                if c.get("loadable") is not True:
                    codes.append(
                        "NOT_LOADABLE"
                    )

                if (
                    c.get("calibrationDigest")
                    != request_cal
                ):
                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if (
                    c.get("tokenizerDigest")
                    != request_tok
                ):
                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

            if codes and status != "unsupported":
                status = "invalid"

            result.append({
                "name": name,
                "status": status,
                "inventory": inv,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes": sort_codes(codes)
            })

        output = {
            "freezeId": freeze_id,
            "candidates": result
        }

        FREEZES[freeze_id] = {
            "input": body,
            "output": output
        }

        return output, 200


# ============================================================
# MANIFEST
# ============================================================

def validate_manifest(candidate):

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
            "sha256"
        }:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = utf8(name)

        if key in names:
            return False, None

        names.add(key)

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

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": digest
        })

    canonical.sort(
        key=lambda x: utf8(x["name"])
    )

    if canonical != inventory:
        return False, None

    total = sum(
        x["bytes"]
        for x in canonical
    )

    package = sha256(
        compact_json(canonical)
    )

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if not finite(floor):
        return False

    if not 0 <= float(floor) <= 1:
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    seen = set()

    for name, value in required.items():

        if not isinstance(name, str) or not name:
            return False

        key = utf8(name)

        if key in seen:
            return False

        seen.add(key)

        if not finite(value):
            return False

        if not 0 <= float(value) <= 1:
            return False

    latency = policy.get(
        "maxLatencyMs"
    )

    if not finite(latency):
        return False

    if float(latency) < 0:
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

        key = utf8(name)

        if key in seen:
            return False

        seen.add(key)

    return True


# ============================================================
# EVALUATION
# ============================================================

def evaluate(candidate, body, frozen_names):

    name = candidate.get(
        "name",
        ""
    )

    codes = []

    if name not in frozen_names:
        codes.append(
            "NOT_FROZEN"
        )

    if candidate.get(
        "status"
    ) != "frozen":
        codes.append(
            "NOT_FROZEN"
        )

    manifest_ok, total = \
        validate_manifest(candidate)

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )

    rows = body["rows"]

    required = body[
        "policy"
    ]["requiredSlices"]

    valid_predictions = True

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            valid_predictions = False
            continue

        if "label" not in row:
            valid_predictions = False
            continue

        if "slice" not in row:
            valid_predictions = False
            continue

        label = row["label"]
        slice_name = row["slice"]

        if not binary(label):
            valid_predictions = False
            continue

        if not isinstance(slice_name, str):
            valid_predictions = False
            continue

        predictions = row.get(
            "predictions"
        )

        if not isinstance(predictions, dict):
            valid_predictions = False
            continue

        if name not in predictions:
            valid_predictions = False
            continue

        prediction = predictions[name]

        if not binary(prediction):
            valid_predictions = False
            continue

        slice_total[slice_name] = \
            slice_total.get(slice_name, 0) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    if not valid_predictions:

        aggregate = None

        slices = {
            s: None
            for s in required
        }

        codes.append(
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

                codes.append(
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
                body["policy"][
                    "aggregateFloor"
                ]
            )
        ):
            codes.append(
                "AGGREGATE_FLOOR"
            )

    total_out = (
        total
        if manifest_ok
        else None
    )

    if (
        manifest_ok
        and total
        > body["policy"]["maxBytes"]
    ):
        codes.append(
            "SIZE_LIMIT"
        )

    latency = None

    latencies = body.get(
        "latencies"
    )

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

    if (
        latency is not None
        and float(latency)
        > float(
            body["policy"][
                "maxLatencyMs"
            ]
        )
    ):
        codes.append(
            "LATENCY_LIMIT"
        )

    codes = sort_codes(codes)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": len(codes) == 0,
        "reasonCodes": codes
    }


# ============================================================
# SELECT
# ============================================================

def select(body):

    freeze_id = body["freezeId"]

    with LOCK:
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # NO FREEZE
    # --------------------------------------------------------

    if stored is None:

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
            key=lambda x: utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    frozen = stored[
        "output"
    ]["candidates"]

    frozen_names = {
        x["name"]
        for x in frozen
    }

    frozen_map = {
        x["name"]: x
        for x in frozen
    }

    submitted = body["candidates"]

    lineage_ok = (
        submitted == frozen
    )

    policy = body["policy"]

    policy_ok = validate_policy(
        policy
    )

    order = (
        policy["candidateOrder"]
        if policy_ok
        else []
    )

    submitted_names = []

    for c in submitted:

        if isinstance(c, dict):

            name = c.get("name")

            if isinstance(name, str):
                submitted_names.append(name)

    if policy_ok:

        submitted_set = {
            utf8(x)
            for x in submitted_names
        }

        order_set = {
            utf8(x)
            for x in order
        }

        order_ok = (
            len(submitted_names)
            == len(submitted)
            and len(order)
            == len(submitted_names)
            and submitted_set
            == order_set
        )

    else:

        order_ok = False

    results = []

    for candidate in submitted:

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

        r = evaluate(
            candidate,
            body,
            frozen_names
        )

        if not lineage_ok:

            r["admitted"] = False

            r["reasonCodes"] = sort_codes(
                r["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not policy_ok or not order_ok:

            r["admitted"] = False

            r["reasonCodes"] = sort_codes(
                r["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(r)

    # Results ordered by candidateOrder.
    if policy_ok:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda x: (
                rank.get(
                    x["name"],
                    999999999
                ),
                utf8(x["name"])
            )
        )

    else:

        results.sort(
            key=lambda x: utf8(x["name"])
        )

    eligible = [
        x
        for x in results
        if x["admitted"]
    ]

    if (
        eligible
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        winner = min(
            eligible,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                rank.get(
                    x["name"],
                    999999999
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

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        if not valid_freeze(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response, status = freeze(body)

        return JSONResponse(
            response,
            status_code=status
        )

    # --------------------------------------------------------
    # SELECT
    # --------------------------------------------------------

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

        if not isinstance(
            body.get("freezeId"),
            str
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        return JSONResponse(
            select(body),
            status_code=200
        )

    return JSONResponse(
        {"error": "INVALID_INPUT"},
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
