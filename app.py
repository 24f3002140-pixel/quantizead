import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

DB = {}
LOCK = threading.Lock()

MAX_SAFE = 9007199254740991


def utf8(x):
    return x.encode("utf-8")


def sha256_bytes(x):
    return hashlib.sha256(x).hexdigest()


def canonical_json(x):
    return json.dumps(
        x,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sorted_codes(codes):
    return sorted(set(codes), key=utf8)


def finite(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_int(x):
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


# ============================================================
# INVENTORY
# ============================================================

def build_inventory(files):

    if not isinstance(files, dict) or not files:
        return [], None, None, False

    result = []

    for name, text in files.items():

        if not isinstance(name, str) or name == "":
            return [], None, None, False

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        result.append({
            "name": name,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw)
        })

    result.sort(key=lambda x: utf8(x["name"]))

    total = sum(x["bytes"] for x in result)

    package = sha256_bytes(
        canonical_json(result)
    )

    return result, total, package, True


# ============================================================
# FREEZE GLOBAL INPUT
# ============================================================

def valid_freeze_boundary(body):

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

    if not isinstance(calibration, str) or not calibration:
        return False

    tokenizer = body.get("tokenizerDigest")

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    seen = set()

    for x in allowed:

        if not isinstance(x, str) or not x:
            return False

        if x in seen:
            return False

        seen.add(x)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names are the only candidate-level properties
    # required for the global freeze boundary.
    seen_names = set()

    for c in candidates:

        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not isinstance(name, str) or not name:
            return False

        if name in seen_names:
            return False

        seen_names.add(name)

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(c, calibration, tokenizer, allowed):

    name = c["name"]
    reasons = []

    files = c.get("files")

    inventory, total, package, files_ok = \
        build_inventory(files)

    if not files_ok:
        inventory = []
        total = None
        package = None
        reasons.append("INVALID_INPUT")

    has_reason = (
        "unsupportedReason" in c
    )

    if has_reason:

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
            reasons.append(
                "UNALLOWED_UNSUPPORTED_REASON"
            )

    else:

        status = "frozen"

        if c.get("loadable") is not True:
            reasons.append(
                "NOT_LOADABLE"
            )

        if c.get(
            "calibrationDigest"
        ) != calibration:
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        if c.get(
            "tokenizerDigest"
        ) != tokenizer:
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

    if reasons and status != "unsupported":
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": sorted_codes(reasons)
    }


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id in DB:

            previous = DB[freeze_id]

            if previous["request"] == body:
                return previous["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        candidates = sorted(
            body["candidates"],
            key=lambda c: utf8(c["name"])
        )

        result = []

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        for c in candidates:

            result.append(
                freeze_candidate(
                    c,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": result
        }

        DB[freeze_id] = {
            "request": body,
            "response": response
        }

        return response, 200


# ============================================================
# MANIFEST
# ============================================================

def validate_manifest(c):

    inventory = c.get("inventory")

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
            "sha256"
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = utf8(name)

        if key in seen:
            return False, None

        seen.add(key)

        if not safe_int(size):
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
        key=lambda x: utf8(x["name"])
    )

    if inventory != ordered:
        return False, None

    total = sum(
        x["bytes"]
        for x in ordered
    )

    package = sha256_bytes(
        canonical_json(ordered)
    )

    if c.get("totalBytes") != total:
        return False, None

    if c.get("packageDigest") != package:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def valid_policy(p):

    if not isinstance(p, dict):
        return False

    if not safe_int(
        p.get("maxBytes")
    ):
        return False

    floor = p.get(
        "aggregateFloor"
    )

    if (
        not finite(floor)
        or float(floor) < 0
        or float(floor) > 1
    ):
        return False

    slices = p.get(
        "requiredSlices"
    )

    if not isinstance(slices, dict):
        return False

    for name, value in slices.items():

        if not isinstance(name, str) or not name:
            return False

        if (
            not finite(value)
            or float(value) < 0
            or float(value) > 1
        ):
            return False

    latency = p.get(
        "maxLatencyMs"
    )

    if (
        not finite(latency)
        or float(latency) < 0
    ):
        return False

    order = p.get(
        "candidateOrder"
    )

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
# EVALUATION
# ============================================================

def evaluate(c, rows, policy, latencies, frozen_names):

    name = c.get("name", "")
    reasons = []

    if (
        name not in frozen_names
        or c.get("status") != "frozen"
    ):
        reasons.append(
            "NOT_FROZEN"
        )

    manifest_ok, total_bytes = \
        validate_manifest(c)

    if manifest_ok:
        output_bytes = total_bytes
    else:
        output_bytes = None
        reasons.append(
            "INVALID_MANIFEST"
        )

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

        if not isinstance(slice_name, str):
            predictions_ok = False
            continue

        preds = row.get(
            "predictions"
        )

        if not isinstance(preds, dict):
            predictions_ok = False
            continue

        if name not in preds:
            predictions_ok = False
            continue

        prediction = preds[name]

        if not binary(prediction):
            predictions_ok = False
            continue

        slice_total[slice_name] = \
            slice_total.get(slice_name, 0) + 1

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(slice_name, 0) + 1

    required = policy["requiredSlices"]

    if not predictions_ok:

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
            or aggregate
            < float(policy["aggregateFloor"])
        ):

            reasons.append(
                "AGGREGATE_FLOOR"
            )

    if (
        manifest_ok
        and total_bytes
        > policy["maxBytes"]
    ):
        reasons.append(
            "SIZE_LIMIT"
        )

    latency = None

    if isinstance(latencies, dict):

        if name in latencies:

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
        > float(policy["maxLatencyMs"])
    ):
        reasons.append(
            "LATENCY_LIMIT"
        )

    reasons = sorted_codes(reasons)

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

def perform_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with LOCK:
        saved = DB.get(freeze_id)

    # Unknown freeze is a selection failure,
    # not an HTTP 400.
    if saved is None:

        results = []

        for c in body["candidates"]:

            name = ""

            if isinstance(c, dict):
                if isinstance(
                    c.get("name"),
                    str
                ):
                    name = c["name"]

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

    frozen = saved["response"]["candidates"]

    frozen_names = {
        c["name"]
        for c in frozen
    }

    frozen_map = {
        c["name"]: c
        for c in frozen
    }

    submitted = body["candidates"]

    lineage_ok = (
        submitted == frozen
    )

    policy = body["policy"]

    policy_ok = valid_policy(policy)

    order = []

    order_ok = False

    if policy_ok:

        order = policy["candidateOrder"]

        names = []

        valid_names = True

        for c in submitted:

            if not isinstance(c, dict):
                valid_names = False
                continue

            n = c.get("name")

            if not isinstance(n, str):
                valid_names = False
                continue

            names.append(n)

        order_ok = (
            valid_names
            and len(names) == len(submitted)
            and len(order) == len(names)
            and {utf8(x) for x in names}
            == {utf8(x) for x in order}
        )

    results = []

    for c in submitted:

        if not isinstance(c, dict):

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
            c,
            body["rows"],
            policy,
            body.get("latencies", {}),
            frozen_names
        )

        if not lineage_ok:

            r["admitted"] = False

            r["reasonCodes"] = sorted_codes(
                r["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not policy_ok or not order_ok:

            r["admitted"] = False

            r["reasonCodes"] = sorted_codes(
                r["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(r)

    if policy_ok:

        ranking = {
            n: i
            for i, n in enumerate(order)
        }

        results.sort(
            key=lambda x: (
                ranking.get(
                    x["name"],
                    10**9
                ),
                utf8(x["name"])
            )
        )

    else:

        results.sort(
            key=lambda x: utf8(x["name"])
        )

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

        ranking = {
            n: i
            for i, n in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                ranking.get(
                    x["name"],
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
        "packageManifest": package_manifest
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

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        if not valid_freeze_boundary(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = \
            perform_freeze(body)

        return JSONResponse(
            result,
            status_code=status
        )

    # --------------------------------------------------------
    # SELECT
    # --------------------------------------------------------

    if phase == "select":

        # The specification explicitly says these three
        # fields must have these top-level types.
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

        result = perform_select(body)

        return JSONResponse(
            result,
            status_code=200
        )

    # Unknown or missing phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


@app.get("/")
def home():
    return {
        "status": "ok",
        "endpoint": "/quantize"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
