import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

STORE = {}
LOCK = threading.Lock()

SAFE_MAX = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def utf8(s):
    return s.encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def code_sort(codes):
    return sorted(set(codes), key=lambda x: utf8(x))


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
# INVENTORY
# ============================================================

def build_inventory(files):
    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    items = []
    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        key = utf8(filename)

        if key in seen:
            return [], None, None, False

        seen.add(key)

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        items.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw)
        })

    items.sort(
        key=lambda x: utf8(x["name"])
    )

    total = sum(
        x["bytes"] for x in items
    )

    digest = sha256(
        compact_json(items)
    )

    return items, total, digest, True


# ============================================================
# FREEZE GLOBAL VALIDATION
# ============================================================

def freeze_global_valid(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if len(freeze_id) == 0:
        return False

    if len(freeze_id) > 128:
        return False

    calibration = body.get(
        "calibrationDigest"
    )

    if not isinstance(calibration, str):
        return False

    if calibration == "":
        return False

    tokenizer = body.get(
        "tokenizerDigest"
    )

    if not isinstance(tokenizer, str):
        return False

    if tokenizer == "":
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    seen_allowed = set()

    for x in allowed:

        if not isinstance(x, str):
            return False

        if x == "":
            return False

        if x in seen_allowed:
            return False

        seen_allowed.add(x)

    candidates = body.get(
        "candidates"
    )

    # REQUIRED BY SPEC
    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names are part of the freeze boundary.
    names = set()

    for c in candidates:

        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not isinstance(name, str):
            return False

        if name == "":
            return False

        if name in names:
            return False

        names.add(name)

    return True


# ============================================================
# FREEZE ONE CANDIDATE
# ============================================================

def freeze_candidate(
    c,
    request_calibration,
    request_tokenizer,
    allowed
):

    name = c["name"]

    reasons = []

    inventory, total, digest, valid_files = \
        build_inventory(
            c.get("files")
        )

    if not valid_files:
        inventory = []
        total = None
        digest = None

        reasons.append(
            "INVALID_INPUT"
        )

    has_reason = (
        "unsupportedReason" in c
    )

    if has_reason:

        reason = c.get(
            "unsupportedReason"
        )

        # A reason is only unsupported if its code is allowed.
        if (
            isinstance(reason, str)
            and reason != ""
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
        ) != request_calibration:
            reasons.append(
                "CALIBRATION_MISMATCH"
            )

        if c.get(
            "tokenizerDigest"
        ) != request_tokenizer:
            reasons.append(
                "TOKENIZER_MISMATCH"
            )

    if reasons:
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": digest,
        "reasonCodes": code_sort(reasons)
    }


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id in STORE:

            old = STORE[freeze_id]

            if old["request"] == body:
                return old["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = sorted(
            body["candidates"],
            key=lambda c: utf8(c["name"])
        )

        result_candidates = []

        for c in candidates:

            result_candidates.append(
                freeze_candidate(
                    c,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": result_candidates
        }

        STORE[freeze_id] = {
            "request": body,
            "response": response
        }

        return response, 200


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(c):

    inventory = c.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    cleaned = []
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
        digest = item.get("sha256")

        if not isinstance(name, str):
            return False, None

        if name == "":
            return False, None

        key = utf8(name)

        if key in seen:
            return False, None

        seen.add(key)

        if not safe_int(size):
            return False, None

        if not isinstance(digest, str):
            return False, None

        if len(digest) != 64:
            return False, None

        if digest != digest.lower():
            return False, None

        try:
            int(digest, 16)
        except Exception:
            return False, None

        cleaned.append({
            "name": name,
            "bytes": size,
            "sha256": digest
        })

    ordered = sorted(
        cleaned,
        key=lambda x: utf8(x["name"])
    )

    if ordered != inventory:
        return False, None

    total = sum(
        x["bytes"] for x in ordered
    )

    digest = sha256(
        compact_json(ordered)
    )

    if c.get("totalBytes") != total:
        return False, None

    if c.get("packageDigest") != digest:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def valid_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_int(
        policy.get("maxBytes")
    ):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if (
        not finite(floor)
        or float(floor) < 0
        or float(floor) > 1
    ):
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for name, value in required.items():

        if not isinstance(name, str):
            return False

        if name == "":
            return False

        if (
            not finite(value)
            or float(value) < 0
            or float(value) > 1
        ):
            return False

    latency = policy.get(
        "maxLatencyMs"
    )

    if (
        not finite(latency)
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

        if not isinstance(name, str):
            return False

        if name == "":
            return False

        if name in seen:
            return False

        seen.add(name)

    return True


# ============================================================
# EVALUATION
# ============================================================

def evaluate(c, rows, policy, latencies, frozen):

    name = c.get("name", "")

    reasons = []

    # --------------------------------------------------------
    # FROZEN
    # --------------------------------------------------------

    if (
        name not in frozen
        or c.get("status") != "frozen"
    ):
        reasons.append(
            "NOT_FROZEN"
        )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total = \
        validate_manifest(c)

    if manifest_ok:
        output_total = total
    else:
        output_total = None
        reasons.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    prediction_ok = True

    correct = 0

    slice_total = {}
    slice_correct = {}

    if not isinstance(rows, list):
        prediction_ok = False
        rows = []

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

        preds = row.get("predictions")

        if not isinstance(preds, dict):
            prediction_ok = False
            continue

        if name not in preds:
            prediction_ok = False
            continue

        pred = preds[name]

        if not binary(pred):
            prediction_ok = False
            continue

        slice_total[slice_name] = \
            slice_total.get(
                slice_name,
                0
            ) + 1

        if int(label) == int(pred):

            correct += 1

            slice_correct[slice_name] = \
                slice_correct.get(
                    slice_name,
                    0
                ) + 1

    required = policy.get(
        "requiredSlices",
        {}
    )

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

        if len(rows) == 0:
            aggregate = None
        else:
            aggregate = round(
                correct / len(rows),
                12
            )

        slices = {}

        for s, floor in required.items():

            count = slice_total.get(
                s,
                0
            )

            if count == 0:

                slices[s] = None

                reasons.append(
                    "MISSING_SLICE:" + s
                )

            else:

                value = round(
                    slice_correct.get(
                        s,
                        0
                    ) / count,
                    12
                )

                slices[s] = value

                if value < float(floor):

                    reasons.append(
                        "SLICE_FLOOR:" + s
                    )

        if (
            aggregate is None
            or aggregate <
            float(
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
        manifest_ok
        and total >
        policy["maxBytes"]
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
                finite(value)
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
        and float(latency) >
        float(policy["maxLatencyMs"])
    ):
        reasons.append(
            "LATENCY_LIMIT"
        )

    reasons = code_sort(reasons)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": output_total,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with LOCK:
        stored = STORE.get(
            freeze_id
        )

    # --------------------------------------------------------
    # UNKNOWN FREEZE
    # --------------------------------------------------------

    if stored is None:

        results = []

        for c in body["candidates"]:

            name = (
                c.get("name", "")
                if isinstance(c, dict)
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

    frozen_candidates = stored[
        "response"
    ]["candidates"]

    frozen_names = {
        c["name"]
        for c in frozen_candidates
    }

    frozen_by_name = {
        c["name"]: c
        for c in frozen_candidates
    }

    supplied = body["candidates"]

    # Exact array comparison.
    lineage_ok = (
        supplied == frozen_candidates
    )

    policy = body["policy"]

    policy_ok = valid_policy(
        policy
    )

    order_ok = False
    order = []

    if policy_ok:

        order = policy[
            "candidateOrder"
        ]

        supplied_names = []

        good = True

        for c in supplied:

            if not isinstance(c, dict):
                good = False
                continue

            name = c.get("name")

            if not isinstance(name, str):
                good = False
                continue

            supplied_names.append(name)

        if (
            good
            and len(supplied_names)
            == len(supplied)
            and len(order)
            == len(supplied_names)
            and set(supplied_names)
            == set(order)
            and len(set(supplied_names))
            == len(supplied_names)
        ):
            order_ok = True

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for c in supplied:

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

        result = evaluate(
            c,
            body["rows"],
            policy,
            body.get("latencies", {}),
            frozen_names
        )

        if not lineage_ok:

            result["admitted"] = False

            result["reasonCodes"] = code_sort(
                result["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not policy_ok or not order_ok:

            result["admitted"] = False

            result["reasonCodes"] = code_sort(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(result)

    # --------------------------------------------------------
    # ORDER RESULTS
    # --------------------------------------------------------

    if order_ok:

        rank = {
            name: i
            for i, name in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                rank.get(
                    r["name"],
                    10**9
                ),
                utf8(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r: utf8(r["name"])
        )

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    admitted = [
        r for r in results
        if r["admitted"]
    ]

    selected = None
    manifest = None

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

        manifest = frozen_by_name[
            selected
        ]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": manifest
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

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not freeze_global_valid(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = do_freeze(
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

        # Exact global select requirements.
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

        result = do_select(
            body
        )

        return JSONResponse(
            result,
            status_code=200
        )

    # Unknown or missing phase.
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
        "status": "ok"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
