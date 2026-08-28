import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful freeze store
STORE = {}
LOCK = threading.Lock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# HELPERS
# ============================================================

def u8(s):
    return s.encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def code_sort(codes):
    return sorted(set(codes), key=lambda x: u8(x))


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
        and 0 <= x <= MAX_SAFE_INTEGER
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
    if not isinstance(files, dict) or not files:
        return [], None, None, False

    entries = []
    names = set()

    for filename, content in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if u8(filename) in names:
            return [], None, None, False

        names.add(u8(filename))

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        entries.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    entries.sort(key=lambda x: u8(x["name"]))

    total = sum(x["bytes"] for x in entries)

    package = sha256(compact_json(entries))

    return entries, total, package, True


# ============================================================
# GLOBAL FREEZE VALIDATION
# ============================================================

def valid_freeze_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if not freeze_id or len(freeze_id) > 128:
        return False

    calibration = body.get("calibrationDigest")

    if not isinstance(calibration, str) or not calibration:
        return False

    tokenizer = body.get("tokenizerDigest")

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    seen = set()

    for reason in allowed:
        if not isinstance(reason, str) or not reason:
            return False

        key = u8(reason)

        if key in seen:
            return False

        seen.add(key)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    seen_names = set()

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return False

        key = u8(name)

        if key in seen_names:
            return False

        seen_names.add(key)

    return True


# ============================================================
# FREEZE ONE CANDIDATE
# ============================================================

def freeze_one(candidate, calibration, tokenizer, allowed):

    name = candidate["name"]

    inventory, total, package, files_ok = make_inventory(
        candidate.get("files")
    )

    reasons = []

    if not files_ok:
        inventory = []
        total = None
        package = None
        reasons.append("INVALID_INPUT")

    # Unsupported candidates are allowed only when the
    # supplied reason is explicitly permitted.
    if "unsupportedReason" in candidate:

        reason = candidate.get("unsupportedReason")

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

        if candidate.get("loadable") is not True:
            reasons.append("NOT_LOADABLE")

        if candidate.get("calibrationDigest") != calibration:
            reasons.append("CALIBRATION_MISMATCH")

        if candidate.get("tokenizerDigest") != tokenizer:
            reasons.append("TOKENIZER_MISMATCH")

    # Any failure makes the candidate invalid, except an
    # explicitly allowed unsupported reason.
    if reasons and status != "unsupported":
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": code_sort(reasons),
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

        calibration = body["calibrationDigest"]
        tokenizer = body["tokenizerDigest"]

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = sorted(
            body["candidates"],
            key=lambda c: u8(c["name"])
        )

        output_candidates = []

        for candidate in candidates:

            output_candidates.append(
                freeze_one(
                    candidate,
                    calibration,
                    tokenizer,
                    allowed,
                )
            )

        response = {
            "freezeId": freeze_id,
            "candidates": output_candidates,
        }

        STORE[freeze_id] = {
            "request": body,
            "response": response,
        }

        return response, 200


# ============================================================
# MANIFEST CHECK
# ============================================================

def check_manifest(candidate):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    canonical = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None

        if list(item.keys()) != [
            "name",
            "bytes",
            "sha256",
        ]:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = u8(name)

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

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": digest,
        })

    canonical.sort(key=lambda x: u8(x["name"]))

    # Inventory must already be in canonical order.
    if inventory != canonical:
        return False, None

    total = sum(x["bytes"] for x in canonical)

    digest = sha256(compact_json(canonical))

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != digest:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def check_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")

    if not safe_int(max_bytes):
        return False

    aggregate_floor = policy.get("aggregateFloor")

    if (
        not finite(aggregate_floor)
        or not 0 <= float(aggregate_floor) <= 1
    ):
        return False

    required = policy.get("requiredSlices")

    if not isinstance(required, dict):
        return False

    seen = set()

    for name, floor in required.items():

        if not isinstance(name, str) or not name:
            return False

        if u8(name) in seen:
            return False

        seen.add(u8(name))

        if (
            not finite(floor)
            or not 0 <= float(floor) <= 1
        ):
            return False

    max_latency = policy.get("maxLatencyMs")

    if (
        not finite(max_latency)
        or float(max_latency) < 0
    ):
        return False

    order = policy.get("candidateOrder")

    if not isinstance(order, list):
        return False

    seen = set()

    for name in order:

        if not isinstance(name, str) or not name:
            return False

        if u8(name) in seen:
            return False

        seen.add(u8(name))

    return True


# ============================================================
# EVALUATE CANDIDATE
# ============================================================

def evaluate(candidate, rows, policy, latencies, frozen_names):

    name = candidate.get("name", "")
    reasons = []

    # --------------------------------------------------------
    # LINEAGE / FROZEN
    # --------------------------------------------------------

    if name not in frozen_names:
        reasons.append("NOT_FROZEN")

    if candidate.get("status") != "frozen":
        reasons.append("NOT_FROZEN")

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total_bytes = check_manifest(candidate)

    if not manifest_ok:
        reasons.append("INVALID_MANIFEST")
        total_bytes_out = None
    else:
        total_bytes_out = total_bytes

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    required = policy["requiredSlices"]

    predictions_ok = True

    total = len(rows)
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

        prediction_map = row.get("predictions")

        if not isinstance(prediction_map, dict):
            predictions_ok = False
            continue

        if name not in prediction_map:
            predictions_ok = False
            continue

        prediction = prediction_map[name]

        if not binary(prediction):
            predictions_ok = False
            continue

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if int(label) == int(prediction):

            correct += 1

            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    if not predictions_ok:

        aggregate = None

        slices = {
            name: None
            for name in required
        }

        reasons.append("INVALID_PREDICTIONS")

    else:

        if total == 0:
            aggregate = None
        else:
            aggregate = round(
                correct / total,
                12,
            )

        slices = {}

        for slice_name, floor in required.items():

            count = slice_total.get(
                slice_name,
                0,
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
                        0,
                    ) / count,
                    12,
                )

                slices[slice_name] = accuracy

                if accuracy < float(floor):
                    reasons.append(
                        "SLICE_FLOOR:" + slice_name
                    )

        if (
            aggregate is None
            or aggregate < float(
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
        and total_bytes > policy["maxBytes"]
    ):
        reasons.append("SIZE_LIMIT")

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    latency = None

    if isinstance(latencies, dict) and name in latencies:

        value = latencies[name]

        if finite(value) and float(value) >= 0:

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
        reasons.append("LATENCY_LIMIT")

    reasons = code_sort(reasons)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes_out,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons,
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body["freezeId"]

    with LOCK:
        frozen = STORE.get(freeze_id)

    # --------------------------------------------------------
    # UNKNOWN FREEZE
    # --------------------------------------------------------

    if frozen is None:

        results = []

        for candidate in body["candidates"]:

            name = ""

            if isinstance(candidate, dict):
                if isinstance(
                    candidate.get("name"),
                    str,
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
                ],
            })

        results.sort(
            key=lambda x: u8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored_candidates = frozen["response"]["candidates"]

    frozen_names = {
        c["name"]
        for c in stored_candidates
    }

    frozen_map = {
        c["name"]: c
        for c in stored_candidates
    }

    submitted = body["candidates"]

    # Exact stored response comparison.
    lineage_ok = (
        submitted == stored_candidates
    )

    policy = body["policy"]

    policy_ok = check_policy(policy)

    # --------------------------------------------------------
    # ORDER SET
    # --------------------------------------------------------

    order_ok = False
    order = []

    if policy_ok:

        order = policy["candidateOrder"]

        submitted_names = []

        valid_names = True

        for c in submitted:

            if not isinstance(c, dict):
                valid_names = False
                continue

            name = c.get("name")

            if not isinstance(name, str):
                valid_names = False
                continue

            submitted_names.append(name)

        submitted_set = {
            u8(x)
            for x in submitted_names
        }

        order_set = {
            u8(x)
            for x in order
        }

        order_ok = (
            valid_names
            and len(submitted_names)
            == len(submitted)
            and len(order)
            == len(submitted_names)
            and submitted_set == order_set
        )

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
                ],
            })

            continue

        result = evaluate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies"),
            frozen_names,
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
                    10**9,
                ),
                u8(x["name"]),
            )
        )

    else:

        results.sort(
            key=lambda x: u8(x["name"])
        )

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    admitted = [
        x for x in results
        if x["admitted"]
    ]

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
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                rank.get(
                    x["name"],
                    10**9,
                ),
            ),
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
        "packageManifest": package_manifest,
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
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = body.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not valid_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        response, status = do_freeze(body)

        return JSONResponse(
            response,
            status_code=status,
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # The contract explicitly requires:
        # candidates = array
        # rows = array
        # policy = object

        if not isinstance(
            body.get("candidates"),
            list,
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("rows"),
            list,
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("policy"),
            dict,
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("freezeId"),
            str,
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        response = do_select(body)

        return JSONResponse(
            response,
            status_code=200,
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": "quantize-admission-api",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
    }
