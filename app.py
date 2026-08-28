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


def enc(s):
    return s.encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def code_sort(codes):
    return sorted(set(codes), key=enc)


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

def inventory(files):
    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    result = []

    for filename, content in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        result.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": digest(raw)
        })

    result.sort(
        key=lambda x: enc(x["name"])
    )

    total = sum(
        x["bytes"]
        for x in result
    )

    package = digest(
        canonical_json(result)
    )

    return result, total, package, True


# ============================================================
# FREEZE GLOBAL VALIDATION
#
# ONLY the actual request shape is checked here.
# Candidate semantic errors are handled inside freeze().
# ============================================================

def freeze_shape(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if not freeze_id:
        return False

    if len(freeze_id) > 128:
        return False

    calibration = body.get(
        "calibrationDigest"
    )

    tokenizer = body.get(
        "tokenizerDigest"
    )

    if not isinstance(
        calibration,
        str
    ) or not calibration:
        return False

    if not isinstance(
        tokenizer,
        str
    ) or not tokenizer:
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(
        allowed,
        list
    ):
        return False

    for reason in allowed:
        if not isinstance(
            reason,
            str
        ):
            return False
        if not reason:
            return False

    # uniqueness by UTF-8
    encoded = [
        enc(x)
        for x in allowed
    ]

    if len(encoded) != len(
        set(encoded)
    ):
        return False

    candidates = body.get(
        "candidates"
    )

    if not isinstance(
        candidates,
        list
    ):
        return False

    if len(candidates) == 0:
        return False

    # Candidate list itself must have unique names.
    names = []

    for c in candidates:

        if not isinstance(
            c,
            dict
        ):
            return False

        name = c.get("name")

        if not isinstance(
            name,
            str
        ):
            return False

        if not name:
            return False

        names.append(
            enc(name)
        )

    if len(names) != len(
        set(names)
    ):
        return False

    return True


# ============================================================
# FREEZE
# ============================================================

def freeze(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:

        # Replay / conflict.
        if freeze_id in STORE:

            old = STORE[
                freeze_id
            ]

            if old["input"] == body:
                return old["output"], 200

            return {
                "error":
                "FREEZE_ID_CONFLICT"
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
            key=lambda x:
                enc(x["name"])
        )

        result = []

        for c in candidates:

            name = c["name"]

            codes = []

            # -------------------------------
            # Artifact inventory
            # -------------------------------

            inv, total, package, ok = \
                inventory(
                    c.get("files")
                )

            if not ok:
                inv = []
                total = None
                package = None

            # -------------------------------
            # Candidate status
            # -------------------------------

            has_reason = (
                "unsupportedReason"
                in c
            )

            reason = c.get(
                "unsupportedReason"
            )

            if has_reason:

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

                if c.get(
                    "loadable"
                ) is not True:
                    codes.append(
                        "NOT_LOADABLE"
                    )

                if c.get(
                    "calibrationDigest"
                ) != request_cal:
                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if c.get(
                    "tokenizerDigest"
                ) != request_tok:
                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

                if codes:
                    status = "invalid"

            result.append({
                "name": name,
                "status": status,
                "inventory": inv,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes":
                    code_sort(codes)
            })

        output = {
            "freezeId": freeze_id,
            "candidates": result
        }

        STORE[freeze_id] = {
            "input": body,
            "output": output
        }

        return output, 200


# ============================================================
# MANIFEST
# ============================================================

def manifest(candidate):

    inv = candidate.get(
        "inventory"
    )

    if not isinstance(
        inv,
        list
    ):
        return False, None

    canonical = []
    seen = set()

    for item in inv:

        if not isinstance(
            item,
            dict
        ):
            return False, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256"
        }:
            return False, None

        name = item.get(
            "name"
        )

        size = item.get(
            "bytes"
        )

        sha = item.get(
            "sha256"
        )

        if (
            not isinstance(
                name,
                str
            )
            or not name
        ):
            return False, None

        k = enc(name)

        if k in seen:
            return False, None

        seen.add(k)

        if not safe_int(size):
            return False, None

        if (
            not isinstance(
                sha,
                str
            )
            or len(sha) != 64
        ):
            return False, None

        try:
            int(sha, 16)
        except Exception:
            return False, None

        canonical.append({
            "name": name,
            "bytes": size,
            "sha256": sha
        })

    canonical.sort(
        key=lambda x:
            enc(x["name"])
    )

    if canonical != inv:
        return False, None

    total = sum(
        x["bytes"]
        for x in canonical
    )

    package = digest(
        canonical_json(canonical)
    )

    if candidate.get(
        "totalBytes"
    ) != total:
        return False, None

    if candidate.get(
        "packageDigest"
    ) != package:
        return False, None

    return True, total


# ============================================================
# POLICY
# ============================================================

def policy_valid(p):

    if not isinstance(p, dict):
        return False

    if not safe_int(
        p.get("maxBytes")
    ):
        return False

    if not finite(
        p.get("aggregateFloor")
    ):
        return False

    if not (
        0 <= float(
            p["aggregateFloor"]
        ) <= 1
    ):
        return False

    required = p.get(
        "requiredSlices"
    )

    if not isinstance(
        required,
        dict
    ):
        return False

    for name, floor in required.items():

        if not isinstance(
            name,
            str
        ) or not name:
            return False

        if not finite(floor):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    if not finite(
        p.get("maxLatencyMs")
    ):
        return False

    if float(
        p["maxLatencyMs"]
    ) < 0:
        return False

    order = p.get(
        "candidateOrder"
    )

    if not isinstance(
        order,
        list
    ):
        return False

    seen = set()

    for x in order:

        if not isinstance(
            x,
            str
        ) or not x:
            return False

        k = enc(x)

        if k in seen:
            return False

        seen.add(k)

    return True


# ============================================================
# EVALUATION
# ============================================================

def evaluate(c, body, frozen_names):

    name = c.get(
        "name",
        ""
    )

    codes = []

    if name not in frozen_names:
        codes.append(
            "NOT_FROZEN"
        )

    if c.get(
        "status"
    ) != "frozen":
        codes.append(
            "NOT_FROZEN"
        )

    valid_manifest, total = \
        manifest(c)

    if not valid_manifest:
        codes.append(
            "INVALID_MANIFEST"
        )

    rows = body[
        "rows"
    ]

    required = body[
        "policy"
    ]["requiredSlices"]

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

        if not binary(label):
            predictions_valid = False
            continue

        if not isinstance(
            slice_name,
            str
        ):
            predictions_valid = False
            continue

        preds = row.get(
            "predictions"
        )

        if not isinstance(
            preds,
            dict
        ):
            predictions_valid = False
            continue

        if name not in preds:
            predictions_valid = False
            continue

        prediction = preds[
            name
        ]

        if not binary(
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

    if not predictions_valid:

        aggregate = None

        slices = {
            x: None
            for x in required
        }

        codes.append(
            "INVALID_PREDICTIONS"
        )

    else:

        if len(rows):
            aggregate = round(
                correct / len(rows),
                12
            )
        else:
            aggregate = None

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

    # Size.
    total_out = (
        total
        if valid_manifest
        else None
    )

    if (
        valid_manifest
        and total
        > body["policy"]["maxBytes"]
    ):
        codes.append(
            "SIZE_LIMIT"
        )

    # Latency.
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
        and finite(
            latencies[name]
        )
        and float(
            latencies[name]
        ) >= 0
    ):
        latency = latencies[name]

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
            body["policy"][
                "maxLatencyMs"
            ]
        )
    ):
        codes.append(
            "LATENCY_LIMIT"
        )

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
        "reasonCodes":
            code_sort(codes)
    }


# ============================================================
# SELECT
# ============================================================

def select(body):

    freeze_id = body[
        "freezeId"
    ]

    with LOCK:
        frozen_record = STORE.get(
            freeze_id
        )

    if frozen_record is None:

        result = []

        for c in body[
            "candidates"
        ]:

            name = ""

            if isinstance(c, dict):
                if isinstance(
                    c.get("name"),
                    str
                ):
                    name = c["name"]

            result.append({
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

        result.sort(
            key=lambda x:
                enc(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": result,
            "packageManifest": None
        }

    frozen = frozen_record[
        "output"
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

    p = body[
        "policy"
    ]

    p_ok = policy_valid(p)

    order = (
        p["candidateOrder"]
        if p_ok
        else []
    )

    submitted_names = [
        c.get("name")
        for c in submitted
        if isinstance(c, dict)
    ]

    order_ok = False

    if p_ok:

        a = {
            enc(x)
            for x in submitted_names
            if isinstance(x, str)
        }

        b = {
            enc(x)
            for x in order
        }

        order_ok = (
            len(submitted_names)
            == len(submitted)
            and len(order)
            == len(submitted_names)
            and a == b
        )

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

        r = evaluate(
            c,
            body,
            frozen_names
        )

        if not lineage_ok:

            r["admitted"] = False

            r["reasonCodes"] = code_sort(
                r["reasonCodes"]
                + ["INVALID_LINEAGE"]
            )

        if not p_ok or not order_ok:

            r["admitted"] = False

            r["reasonCodes"] = code_sort(
                r["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(r)

    if p_ok:

        rank = {
            x: i
            for i, x in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                rank.get(
                    r["name"],
                    999999999
                ),
                enc(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r:
                enc(r["name"])
        )

    eligible = [
        r for r in results
        if r["admitted"]
    ]

    if (
        eligible
        and lineage_ok
        and p_ok
        and order_ok
    ):

        rank = {
            x: i
            for i, x in enumerate(order)
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

    phase = body.get(
        "phase"
    )

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not freeze_shape(body):
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

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Explicit request-level requirements.
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

    # Unknown / missing phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


@app.get("/")
def home():
    return {
        "service": "quantize",
        "status": "ok"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
