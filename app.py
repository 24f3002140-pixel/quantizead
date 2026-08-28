from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hashlib
import json
import math
import threading

app = FastAPI()

DB = {}
LOCK = threading.Lock()

MAX_SAFE = 9007199254740991


def b(s):
    return s.encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def js_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def codes(xs):
    return sorted(set(xs), key=b)


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
    return (
        not isinstance(x, bool)
        and (
            x == 0 or x == 1
        )
    )


# ---------------------------------------------------------
# INVENTORY
# ---------------------------------------------------------

def inventory(files):
    if not isinstance(files, dict) or not files:
        return None

    out = []

    for name, text in files.items():
        if not isinstance(name, str) or not name:
            return None
        if not isinstance(text, str):
            return None

        raw = text.encode("utf-8")

        out.append({
            "name": name,
            "bytes": len(raw),
            "sha256": sha(raw),
        })

    out.sort(key=lambda x: b(x["name"]))

    total = sum(x["bytes"] for x in out)

    package = sha(js_json(out))

    return out, total, package


# ---------------------------------------------------------
# FREEZE REQUEST VALIDATION
# ---------------------------------------------------------

def valid_freeze(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    fid = body.get("freezeId")
    if not isinstance(fid, str) or not fid or len(fid) > 128:
        return False

    cd = body.get("calibrationDigest")
    td = body.get("tokenizerDigest")

    if not isinstance(cd, str) or not cd:
        return False

    if not isinstance(td, str) or not td:
        return False

    allowed = body.get("allowedUnsupportedReasons")
    if not isinstance(allowed, list):
        return False

    seen_allowed = set()

    for x in allowed:
        if not isinstance(x, str) or not x:
            return False
        if x in seen_allowed:
            return False
        seen_allowed.add(x)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = set()

    for c in candidates:
        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not isinstance(name, str) or not name:
            return False

        if name in names:
            return False

        names.add(name)

    return True


# ---------------------------------------------------------
# FREEZE
# ---------------------------------------------------------

def make_frozen_candidate(c, req_cd, req_td, allowed):

    name = c["name"]

    reason = c.get("unsupportedReason")
    reasons = []

    inv = inventory(c.get("files"))

    if inv is None:
        inventory_out = []
        total = None
        package = None
        manifest_valid = False
    else:
        inventory_out, total, package = inv
        manifest_valid = True

    # Unsupported candidate
    if reason is not None:

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
            status = "invalid"
            reasons.append("NOT_LOADABLE")

        if c.get("calibrationDigest") != req_cd:
            status = "invalid"
            reasons.append("CALIBRATION_MISMATCH")

        if c.get("tokenizerDigest") != req_td:
            status = "invalid"
            reasons.append("TOKENIZER_MISMATCH")

    if not manifest_valid:
        status = "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory_out,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": codes(reasons),
    }


def freeze(body):

    fid = body["freezeId"]

    with LOCK:

        old = DB.get(fid)

        if old is not None:

            if old["input"] == body:
                return old["output"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        result = []

        for c in body["candidates"]:
            result.append(
                make_frozen_candidate(
                    c,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed,
                )
            )

        result.sort(
            key=lambda x: b(x["name"])
        )

        output = {
            "freezeId": fid,
            "candidates": result,
        }

        DB[fid] = {
            "input": body,
            "output": output,
        }

        return output, 200


# ---------------------------------------------------------
# MANIFEST VALIDATION
# ---------------------------------------------------------

def check_manifest(c):

    inv = c.get("inventory")

    if not isinstance(inv, list):
        return False, None

    names = set()

    for x in inv:

        if not isinstance(x, dict):
            return False, None

        if list(x.keys()) != [
            "name",
            "bytes",
            "sha256"
        ]:
            return False, None

        name = x.get("name")
        size = x.get("bytes")
        digest_value = x.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        if name in names:
            return False, None

        names.add(name)

        if not safe_int(size):
            return False, None

        if (
            not isinstance(digest_value, str)
            or len(digest_value) != 64
            or digest_value.lower() != digest_value
        ):
            return False, None

        try:
            int(digest_value, 16)
        except Exception:
            return False, None

    expected = sorted(
        inv,
        key=lambda x: b(x["name"])
    )

    if expected != inv:
        return False, None

    total = sum(
        x["bytes"]
        for x in inv
    )

    package = sha(js_json(inv))

    if c.get("totalBytes") != total:
        return False, None

    if c.get("packageDigest") != package:
        return False, None

    return True, total


# ---------------------------------------------------------
# POLICY
# ---------------------------------------------------------

def check_policy(p):

    if not isinstance(p, dict):
        return False

    if not safe_int(p.get("maxBytes")):
        return False

    af = p.get("aggregateFloor")

    if (
        not finite(af)
        or af < 0
        or af > 1
    ):
        return False

    rs = p.get("requiredSlices")

    if not isinstance(rs, dict):
        return False

    for name, floor in rs.items():

        if not isinstance(name, str) or not name:
            return False

        if (
            not finite(floor)
            or floor < 0
            or floor > 1
        ):
            return False

    ml = p.get("maxLatencyMs")

    if (
        not finite(ml)
        or ml < 0
    ):
        return False

    order = p.get("candidateOrder")

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


# ---------------------------------------------------------
# LATENCY
# ---------------------------------------------------------

def get_latency(latencies, name):

    if not isinstance(latencies, dict):
        return None

    if name not in latencies:
        return None

    x = latencies[name]

    if not finite(x) or x < 0:
        return None

    return x


# ---------------------------------------------------------
# SELECT CANDIDATE
# ---------------------------------------------------------

def evaluate(c, rows, policy, latencies):

    name = c.get("name", "")
    reasons = []

    if c.get("status") != "frozen":
        reasons.append("NOT_FROZEN")

    manifest_ok, total = check_manifest(c)

    if not manifest_ok:
        total = None
        reasons.append("INVALID_MANIFEST")

    # Predictions
    prediction_ok = True
    correct = 0

    slice_total = {}
    slice_correct = {}

    if not isinstance(rows, list):
        prediction_ok = False
        rows_iter = []
    else:
        rows_iter = rows

    for row in rows_iter:

        if not isinstance(row, dict):
            prediction_ok = False
            continue

        label = row.get("label")
        sl = row.get("slice")
        preds = row.get("predictions")

        if not binary(label):
            prediction_ok = False
            continue

        if not isinstance(sl, str) or not sl:
            prediction_ok = False
            continue

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

        slice_total[sl] = slice_total.get(sl, 0) + 1

        if int(pred) == int(label):
            correct += 1
            slice_correct[sl] = (
                slice_correct.get(sl, 0) + 1
            )

    required = policy.get(
        "requiredSlices",
        {}
    )

    slices = {}

    if not prediction_ok or len(rows_iter) == 0:

        aggregate = None

        for sl in required:
            slices[sl] = None

        reasons.append(
            "INVALID_PREDICTIONS"
        )

    else:

        aggregate = round(
            correct / len(rows_iter),
            12
        )

        if aggregate < policy["aggregateFloor"]:
            reasons.append(
                "AGGREGATE_FLOOR"
            )

        for sl, floor in required.items():

            n = slice_total.get(sl, 0)

            if n == 0:

                slices[sl] = None

                reasons.append(
                    "MISSING_SLICE:" + sl
                )

            else:

                acc = round(
                    slice_correct.get(sl, 0) / n,
                    12
                )

                slices[sl] = acc

                if acc < floor:
                    reasons.append(
                        "SLICE_FLOOR:" + sl
                    )

    # Size
    if (
        total is not None
        and total > policy["maxBytes"]
    ):
        reasons.append("SIZE_LIMIT")

    # Latency
    latency = get_latency(
        latencies,
        name
    )

    if latency is None:
        # There is no separate invalid-latency code in
        # the specification. Such a candidate simply
        # cannot satisfy the latency constraint.
        reasons.append("LATENCY_LIMIT")

    elif latency > policy["maxLatencyMs"]:
        reasons.append("LATENCY_LIMIT")

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total,
        "latencyMs": latency,
        "admitted": len(reasons) == 0,
        "reasonCodes": codes(reasons),
    }


# ---------------------------------------------------------
# SELECT
# ---------------------------------------------------------

def select(body):

    fid = body.get("freezeId")

    with LOCK:
        saved = DB.get(fid)

    supplied = body["candidates"]
    rows = body["rows"]
    policy = body["policy"]
    latencies = body.get("latencies", {})

    if saved is None:

        results = []

        for c in supplied:

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
                "reasonCodes": ["NOT_FROZEN"],
            })

        results.sort(
            key=lambda x: b(x["name"])
        )

        return {
            "freezeId": fid,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored = saved["output"]["candidates"]

    lineage_ok = (
        supplied == stored
    )

    policy_ok = check_policy(policy)

    names = []

    for c in supplied:
        if isinstance(c, dict):
            names.append(c.get("name"))
        else:
            names.append(None)

    order = (
        policy.get("candidateOrder", [])
        if policy_ok
        else []
    )

    order_ok = False

    if policy_ok:

        order_ok = (
            len(names) == len(order)
            and len(set(names)) == len(names)
            and len(set(order)) == len(order)
            and all(
                isinstance(x, str) and x
                for x in names
            )
            and set(names) == set(order)
        )

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
                ],
            })

            continue

        r = evaluate(
            c,
            rows,
            policy,
            latencies
        )

        extra = []

        if not lineage_ok:
            extra.append(
                "INVALID_LINEAGE"
            )

        if not policy_ok or not order_ok:
            extra.append(
                "INVALID_POLICY"
            )

        r["reasonCodes"] = codes(
            r["reasonCodes"] + extra
        )

        if extra:
            r["admitted"] = False

        results.append(r)

    if order_ok:

        pos = {
            x: i
            for i, x in enumerate(order)
        }

        results.sort(
            key=lambda r: (
                pos.get(
                    r["name"],
                    MAX_SAFE
                ),
                b(r["name"])
            )
        )

    else:

        results.sort(
            key=lambda r: b(r["name"])
        )

    selected = None
    manifest = None

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

        pos = {
            x: i
            for i, x in enumerate(order)
        }

        winner = min(
            eligible,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                pos[r["name"]],
            )
        )

        selected = winner["name"]

        for c in stored:
            if c["name"] == selected:
                manifest = c
                break

    return {
        "freezeId": fid,
        "selected": selected,
        "results": results,
        "packageManifest": manifest,
    }


# ---------------------------------------------------------
# API
# ---------------------------------------------------------

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

    # ---------------- FREEZE ----------------

    if phase == "freeze":

        if not valid_freeze(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        result, status = freeze(body)

        return JSONResponse(
            result,
            status_code=status
        )

    # ---------------- SELECT ----------------

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

        return JSONResponse(
            select(body),
            status_code=200
        )

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400
    )


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}
