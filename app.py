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


def b(s):
    return s.encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cjson(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=b)


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
        return x in (0, 1)
    if isinstance(x, float):
        return math.isfinite(x) and x in (0.0, 1.0)
    return False


# ============================================================
# INVENTORY
# ============================================================

def make_inventory(files):

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    items = []

    for filename, text in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        items.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha(raw)
        })

    items.sort(
        key=lambda x: b(x["name"])
    )

    total = sum(
        x["bytes"]
        for x in items
    )

    package = sha(
        cjson(items)
    )

    return items, total, package, True


# ============================================================
# GLOBAL FREEZE VALIDATION
# ============================================================

def valid_freeze_request(body):

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

    cal = body.get("calibrationDigest")
    tok = body.get("tokenizerDigest")

    if not isinstance(cal, str) or not cal:
        return False

    if not isinstance(tok, str) or not tok:
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    allowed_seen = set()

    for reason in allowed:

        if not isinstance(reason, str) or not reason:
            return False

        key = b(reason)

        if key in allowed_seen:
            return False

        allowed_seen.add(key)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        # name is globally required
        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return False

        key = b(name)

        if key in names:
            return False

        names.add(key)

        # Files must be an object.
        if "files" not in candidate:
            return False

        if not isinstance(candidate["files"], dict):
            return False

        # loadable is required and boolean.
        if "loadable" not in candidate:
            return False

        if not isinstance(candidate["loadable"], bool):
            return False

        # Digests are required and non-empty.
        if "calibrationDigest" not in candidate:
            return False

        if "tokenizerDigest" not in candidate:
            return False

        if (
            not isinstance(
                candidate["calibrationDigest"],
                str
            )
            or not candidate["calibrationDigest"]
        ):
            return False

        if (
            not isinstance(
                candidate["tokenizerDigest"],
                str
            )
            or not candidate["tokenizerDigest"]
        ):
            return False

        # unsupportedReason, when supplied, must be string.
        if "unsupportedReason" in candidate:

            reason = candidate["unsupportedReason"]

            if not isinstance(reason, str):
                return False

    return True


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        if freeze_id in FREEZES:

            previous = FREEZES[freeze_id]

            if previous["input"] == body:
                return previous["output"], 200

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

        candidates = sorted(
            body["candidates"],
            key=lambda x: b(x["name"])
        )

        output = []

        for candidate in candidates:

            codes = []

            name = candidate["name"]

            # --------------------------------------------
            # FILES
            # --------------------------------------------

            (
                inventory,
                total,
                package,
                files_ok
            ) = make_inventory(
                candidate["files"]
            )

            if not files_ok:

                inventory = []
                total = None
                package = None

                # File problems invalidate candidate,
                # but NOT the entire freeze request.
                codes.append(
                    "INVALID_INPUT"
                )

            # --------------------------------------------
            # UNSUPPORTED
            # --------------------------------------------

            if "unsupportedReason" in candidate:

                reason = candidate[
                    "unsupportedReason"
                ]

                if reason in allowed:

                    status = "unsupported"

                else:

                    status = "invalid"

                    codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

            # --------------------------------------------
            # NORMAL
            # --------------------------------------------

            else:

                status = "frozen"

                if candidate["loadable"] is not True:

                    codes.append(
                        "NOT_LOADABLE"
                    )

                if (
                    candidate["calibrationDigest"]
                    != request_cal
                ):

                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if (
                    candidate["tokenizerDigest"]
                    != request_tok
                ):

                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

            # Any reason makes candidate invalid,
            # except allowed unsupported reason.
            if codes and status != "unsupported":
                status = "invalid"

            output.append({
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes": sort_codes(codes)
            })

        response = {
            "freezeId": freeze_id,
            "candidates": output
        }

        FREEZES[freeze_id] = {
            "input": body,
            "output": response
        }

        return response, 200


# ============================================================
# MANIFEST
# ============================================================

def check_manifest(candidate):

    inv = candidate.get("inventory")

    if not isinstance(inv, list):
        return False, None

    canonical = []
    seen = set()

    for item in inv:

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
        digest_value = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = b(name)

        if key in seen:
            return False, None

        seen.add(key)

        if not safe_int(size):
            return False, None

        if (
            not isinstance(digest_value, str)
            or len(digest_value) != 64
        ):
            return False, None

        try:
            int(digest_value, 16)
        except Exception:
            return False, None

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": digest_value
        })

    canonical.sort(
        key=lambda x: b(x["name"])
    )

    if canonical != inv:
        return False, None

    total = sum(
        x["bytes"]
        for x in canonical
    )

    package = sha(
        cjson(canonical)
    )

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != package:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def check_policy(policy):

    if not isinstance(policy, dict):
        return False

    if not safe_int(
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

    slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(slices, dict):
        return False

    seen = set()

    for name, value in slices.items():

        if not isinstance(name, str) or not name:
            return False

        key = b(name)

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

    order_seen = set()

    for name in order:

        if not isinstance(name, str) or not name:
            return False

        key = b(name)

        if key in order_seen:
            return False

        order_seen.add(key)

    return True


# ============================================================
# EVALUATE
# ============================================================

def evaluate(candidate, body, frozen_names):

    name = candidate.get(
        "name",
        ""
    )

    codes = []

    # --------------------------------------------------------
    # FROZEN
    # --------------------------------------------------------

    if name not in frozen_names:
        codes.append("NOT_FROZEN")

    if candidate.get("status") != "frozen":
        codes.append("NOT_FROZEN")

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total = check_manifest(
        candidate
    )

    if not manifest_ok:
        codes.append("INVALID_MANIFEST")

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

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

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    # --------------------------------------------------------
    # ACCURACY
    # --------------------------------------------------------

    if not valid_predictions:

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

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

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

def do_select(body):

    freeze_id = body["freezeId"]

    with LOCK:
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # NOT FROZEN
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
            key=lambda x: b(x["name"])
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

    # Exact stored response comparison.
    lineage_ok = (
        submitted == frozen
    )

    policy = body["policy"]

    policy_ok = check_policy(
        policy
    )

    order = (
        policy["candidateOrder"]
        if policy_ok
        else []
    )

    submitted_names = []

    for candidate in submitted:

        if isinstance(candidate, dict):

            name = candidate.get(
                "name"
            )

            if isinstance(name, str):
                submitted_names.append(name)

    if policy_ok:

        submitted_set = {
            b(x)
            for x in submitted_names
        }

        order_set = {
            b(x)
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

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

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

        result = evaluate(
            candidate,
            body,
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
                    999999999
                ),
                b(x["name"])
            )
        )

    else:

        results.sort(
            key=lambda x: b(x["name"])
        )

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    eligible = [
        x for x in results
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
# API
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

        if not valid_freeze_request(body):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        response, status = do_freeze(
            body
        )

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
            do_select(body),
            status_code=200
        )

    # --------------------------------------------------------
    # UNKNOWN PHASE
    # --------------------------------------------------------

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


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
