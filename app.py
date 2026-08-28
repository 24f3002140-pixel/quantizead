import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

LOCK = threading.Lock()
FREEZES = {}

SAFE_MAX = 9007199254740991


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_json(obj) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def utf8_key(value):
    return value.encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=utf8_key)


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
        and 0 <= x <= SAFE_MAX
    )


def is_binary(x):
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

    inventory = []

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if not isinstance(text, str):
            return [], None, None, False

        raw = text.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw)
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        item["bytes"]
        for item in inventory
    )

    digest = sha256(
        compact_json(inventory)
    )

    return inventory, total, digest, True


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
        or len(freeze_id) == 0
        or len(freeze_id) > 128
    ):
        return False

    if not isinstance(
        body.get("calibrationDigest"),
        str
    ) or body["calibrationDigest"] == "":
        return False

    if not isinstance(
        body.get("tokenizerDigest"),
        str
    ) or body["tokenizerDigest"] == "":
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        return False

    # Non-empty + unique strings.
    allowed_bytes = []

    for x in allowed:

        if not isinstance(x, str):
            return False

        if x == "":
            return False

        allowed_bytes.append(
            x.encode("utf-8")
        )

    if len(allowed_bytes) != len(
        set(allowed_bytes)
    ):
        return False

    candidates = body.get(
        "candidates"
    )

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names are the only candidate-level condition
    # that makes the WHOLE freeze request structurally invalid.
    names = []

    for c in candidates:

        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not isinstance(name, str):
            return False

        if name == "":
            return False

        names.append(
            name.encode("utf-8")
        )

    if len(names) != len(set(names)):
        return False

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
            body["allowedUnsupportedReasons"]
        )

        output = []

        candidates = sorted(
            body["candidates"],
            key=lambda c:
                c["name"].encode("utf-8")
        )

        for c in candidates:

            name = c["name"]

            codes = []

            # ------------------------------------------------
            # FILES
            # ------------------------------------------------

            inventory, total, digest, files_ok = \
                make_inventory(
                    c.get("files")
                )

            # If files are malformed, inventory must be empty
            # and totals/digest must be null.
            if not files_ok:

                inventory = []
                total = None
                digest = None

            # ------------------------------------------------
            # CANDIDATE RULES
            # ------------------------------------------------

            loadable = c.get(
                "loadable"
            )

            candidate_cal = c.get(
                "calibrationDigest"
            )

            candidate_tok = c.get(
                "tokenizerDigest"
            )

            reason_present = (
                "unsupportedReason" in c
            )

            reason = c.get(
                "unsupportedReason"
            )

            # Candidate has an unsupported reason.
            if reason_present:

                if (
                    isinstance(reason, str)
                    and reason != ""
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

                if loadable is not True:
                    codes.append(
                        "NOT_LOADABLE"
                    )

                if (
                    not isinstance(
                        candidate_cal,
                        str
                    )
                    or candidate_cal == ""
                    or candidate_cal != request_cal
                ):
                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if (
                    not isinstance(
                        candidate_tok,
                        str
                    )
                    or candidate_tok == ""
                    or candidate_tok != request_tok
                ):
                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

                if codes:
                    status = "invalid"

            # An unsupported candidate is allowed to remain
            # unsupported even if its loadability/lineage is
            # otherwise irrelevant.
            output.append({
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": digest,
                "reasonCodes": sort_codes(codes)
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
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if (
            not isinstance(name, str)
            or name == ""
        ):
            return False, None

        key = name.encode("utf-8")

        if key in names:
            return False, None

        names.add(key)

        if not safe_integer(byte_count):
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
            "bytes": byte_count,
            "sha256": digest
        })

    canonical.sort(
        key=lambda x:
            x["name"].encode("utf-8")
    )

    if canonical != inventory:
        return False, None

    total = sum(
        x["bytes"]
        for x in canonical
    )

    digest = sha256(
        compact_json(canonical)
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != digest:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def valid_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get(
        "maxBytes"
    )

    if not safe_integer(max_bytes):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if not finite_number(floor):
        return False

    if not 0 <= float(floor) <= 1:
        return False

    slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(slices, dict):
        return False

    for name, value in slices.items():

        if not isinstance(name, str):
            return False

        if name == "":
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

    if not isinstance(order, list):
        return False

    seen = set()

    for x in order:

        if not isinstance(x, str):
            return False

        if x == "":
            return False

        key = x.encode("utf-8")

        if key in seen:
            return False

        seen.add(key)

    return True


# ============================================================
# EVALUATE
# ============================================================

def evaluate(candidate, body, frozen_names):

    name = candidate.get(
        "name"
    )

    codes = []

    if name not in frozen_names:
        codes.append(
            "NOT_FROZEN"
        )

    # Only exactly frozen candidates can be admitted.
    if candidate.get(
        "status"
    ) != "frozen":
        codes.append(
            "NOT_FROZEN"
        )

    manifest_ok, total = \
        validate_manifest(
            candidate
        )

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )

    rows = body["rows"]
    policy = body["policy"]

    required = policy[
        "requiredSlices"
    ]

    correct = 0

    slice_total = {}
    slice_correct = {}

    predictions_ok = True

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

        if not is_binary(label):
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

        prediction = predictions[
            name
        ]

        if not is_binary(
            prediction
        ):
            predictions_ok = False
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
    # METRICS
    # --------------------------------------------------------

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

                slices[
                    slice_name
                ] = None

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

                slices[
                    slice_name
                ] = value

                if value < float(floor):

                    codes.append(
                        "SLICE_FLOOR:"
                        + slice_name
                    )

        aggregate_floor = float(
            policy["aggregateFloor"]
        )

        if (
            aggregate is None
            or aggregate
            < aggregate_floor
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
        and total
        > policy["maxBytes"]
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
        isinstance(
            latencies,
            dict
        )
        and name in latencies
    ):

        value = latencies[name]

        if (
            finite_number(value)
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
        and float(latency)
        > float(
            policy["maxLatencyMs"]
        )
    ):
        codes.append(
            "LATENCY_LIMIT"
        )

    # --------------------------------------------------------
    # ADMITTED
    # --------------------------------------------------------

    admitted = (
        len(codes) == 0
    )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": sort_codes(codes)
    }


# ============================================================
# SELECT
# ============================================================

def select(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # NOT FROZEN
    # --------------------------------------------------------

    if stored is None:

        results = []

        for c in body[
            "candidates"
        ]:

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
            key=lambda x:
                x["name"].encode("utf-8")
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }

    frozen = stored[
        "response"
    ]["candidates"]

    frozen_names = {
        c["name"]
        for c in frozen
    }

    frozen_map = {
        c["name"]: c
        for c in frozen
    }

    submitted = body[
        "candidates"
    ]

    lineage_ok = (
        submitted == frozen
    )

    policy = body[
        "policy"
    ]

    policy_ok = valid_policy(
        policy
    )

    # --------------------------------------------------------
    # ORDER SET
    # --------------------------------------------------------

    order_ok = False

    if policy_ok:

        order = policy[
            "candidateOrder"
        ]

        submitted_names = []

        for c in submitted:

            if isinstance(
                c,
                dict
            ) and isinstance(
                c.get("name"),
                str
            ):
                submitted_names.append(
                    c["name"]
                )

        a = {
            x.encode("utf-8")
            for x in submitted_names
        }

        b = {
            x.encode("utf-8")
            for x in order
        }

        order_ok = (
            len(submitted_names)
            == len(submitted)
            and len(order)
            == len(submitted_names)
            and a == b
        )

    else:

        order = []

    # --------------------------------------------------------
    # EVALUATE
    # --------------------------------------------------------

    results = []

    for c in submitted:

        if not isinstance(
            c,
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

        result = evaluate(
            c,
            body,
            frozen_names
        )

        if not lineage_ok:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if (
            not policy_ok
            or not order_ok
        ):

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(
            result
        )

    # --------------------------------------------------------
    # ORDER RESULTS
    # --------------------------------------------------------

    if policy_ok:

        rank = {
            name: i
            for i, name in enumerate(
                order
            )
        }

        results.sort(
            key=lambda r: (
                rank.get(
                    r["name"],
                    999999999
                ),
                r["name"].encode("utf-8")
            )
        )

    else:

        results.sort(
            key=lambda r:
                r["name"].encode("utf-8")
        )

    # --------------------------------------------------------
    # SELECT WINNER
    # --------------------------------------------------------

    eligible = [
        r for r in results
        if r["admitted"]
    ]

    if (
        eligible
        and lineage_ok
        and policy_ok
        and order_ok
    ):

        rank = {
            name: i
            for i, name in enumerate(
                order
            )
        }

        winner = min(
            eligible,
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

        package_manifest = (
            frozen_map[selected]
        )

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

    phase = body.get(
        "phase"
    )

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        # GLOBAL validation happens BEFORE touching storage.
        if not valid_freeze_request(
            body
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = freeze(
            body
        )

        return JSONResponse(
            result,
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

        result = select(body)

        return JSONResponse(
            result,
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
        "ok": True
    }
