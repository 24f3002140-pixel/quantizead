import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

LOCK = threading.Lock()
FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def u8(s):
    return s.encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def compact_json(obj):
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def package_digest(inventory):
    return sha256_bytes(compact_json(inventory))


def sort_utf8(items):
    return sorted(items, key=lambda x: x.encode("utf-8"))


def sort_codes(codes):
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))


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
        and 0 <= x <= 9007199254740991
    )


def binary(x):
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return x == 0 or x == 1
    if isinstance(x, float):
        return math.isfinite(x) and (x == 0.0 or x == 1.0)
    return False


def unique_nonempty_strings(x):
    if not isinstance(x, list):
        return False

    if not all(
        isinstance(v, str) and len(v) > 0
        for v in x
    ):
        return False

    encoded = [u8(v) for v in x]
    return len(encoded) == len(set(encoded))


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    inventory = []

    names = set()

    for filename, content in files.items():

        if not isinstance(filename, str):
            return [], None, None, False

        if filename == "":
            return [], None, None, False

        if u8(filename) in names:
            return [], None, None, False

        names.add(u8(filename))

        if not isinstance(content, str):
            return [], None, None, False

        data = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": sha256_bytes(data)
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
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body.get("freezeId")

    with LOCK:

        if freeze_id in FREEZES:

            old = FREEZES[freeze_id]

            if old["input"] == body:
                return old["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        request_cal = body.get(
            "calibrationDigest"
        )

        request_tok = body.get(
            "tokenizerDigest"
        )

        allowed = body.get(
            "allowedUnsupportedReasons",
            []
        )

        if not isinstance(allowed, list):
            allowed = []

        allowed_set = set(
            x for x in allowed
            if isinstance(x, str)
        )

        candidates = body.get(
            "candidates"
        )

        output = []

        # Canonical candidate ordering.
        candidates_sorted = sorted(
            candidates,
            key=lambda c:
                str(c.get("name", "")).encode("utf-8")
        )

        for c in candidates_sorted:

            name = c.get("name", "")

            codes = []

            # ------------------------------------------------
            # FILES
            # ------------------------------------------------

            inventory, total, digest, files_ok = \
                build_inventory(
                    c.get("files")
                )

            if not files_ok:
                codes.append(
                    "INVALID_INPUT"
                )

            # ------------------------------------------------
            # BASIC CANDIDATE DATA
            # ------------------------------------------------

            loadable = c.get(
                "loadable"
            )

            cal = c.get(
                "calibrationDigest"
            )

            tok = c.get(
                "tokenizerDigest"
            )

            if not isinstance(loadable, bool):
                codes.append(
                    "INVALID_INPUT"
                )

            if not isinstance(cal, str) or cal == "":
                codes.append(
                    "INVALID_INPUT"
                )

            if not isinstance(tok, str) or tok == "":
                codes.append(
                    "INVALID_INPUT"
                )

            # ------------------------------------------------
            # UNSUPPORTED REASON
            # ------------------------------------------------

            has_reason = (
                "unsupportedReason" in c
            )

            reason = c.get(
                "unsupportedReason"
            )

            if has_reason:

                if not isinstance(reason, str):
                    codes.append(
                        "INVALID_INPUT"
                    )

                elif reason == "":
                    codes.append(
                        "INVALID_INPUT"
                    )

            # ------------------------------------------------
            # STATUS
            # ------------------------------------------------

            if (
                has_reason
                and isinstance(reason, str)
                and reason in allowed_set
                and "INVALID_INPUT" not in codes
            ):

                status = "unsupported"

            else:

                status = "frozen"

                if has_reason:

                    if (
                        not isinstance(reason, str)
                        or reason not in allowed_set
                    ):
                        codes.append(
                            "UNALLOWED_UNSUPPORTED_REASON"
                        )

                if loadable is False:
                    codes.append(
                        "NOT_LOADABLE"
                    )

                if (
                    isinstance(cal, str)
                    and isinstance(
                        request_cal,
                        str
                    )
                    and cal != request_cal
                ):
                    codes.append(
                        "CALIBRATION_MISMATCH"
                    )

                if (
                    isinstance(tok, str)
                    and isinstance(
                        request_tok,
                        str
                    )
                    and tok != request_tok
                ):
                    codes.append(
                        "TOKENIZER_MISMATCH"
                    )

            # Any reason means invalid except allowed
            # unsupported candidate.
            allowed_unsupported = (
                has_reason
                and isinstance(reason, str)
                and reason in allowed_set
                and "INVALID_INPUT" not in codes
            )

            if codes and not allowed_unsupported:
                status = "invalid"

            # Invalid files => empty/null manifest.
            if not files_ok:

                inv_out = []
                total_out = None
                digest_out = None

            else:

                inv_out = inventory
                total_out = total
                digest_out = digest

            output.append({
                "name": name,
                "status": status,
                "inventory": inv_out,
                "totalBytes": total_out,
                "packageDigest": digest_out,
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
# MANIFEST VALIDATION
# ============================================================

def validate_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(inventory, list):
        return False, None

    names = set()
    canonical = []

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

        if not isinstance(name, str) or name == "":
            return False, None

        key = u8(name)

        if key in names:
            return False, None

        names.add(key)

        if not safe_int(byte_count):
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

    if inventory != canonical:
        return False, None

    total = sum(
        x["bytes"]
        for x in canonical
    )

    digest = package_digest(
        canonical
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

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get(
        "maxBytes"
    )

    if not safe_int(max_bytes):
        return False

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not finite(aggregate_floor):
        return False

    if not 0 <= float(
        aggregate_floor
    ) <= 1:
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(required, dict):
        return False

    for name, floor in required.items():

        if not isinstance(name, str) or name == "":
            return False

        if not finite(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not finite(max_latency):
        return False

    if float(max_latency) < 0:
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(order):
        return False

    return True


# ============================================================
# METRICS
# ============================================================

def calculate_candidate(
    candidate,
    body,
    frozen_names
):

    name = candidate.get(
        "name",
        ""
    )

    codes = []

    # --------------------------------------------------------
    # LINEAGE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_ok, total = \
        validate_manifest(candidate)

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # ROWS
    # --------------------------------------------------------

    rows = body.get(
        "rows",
        []
    )

    required = body[
        "policy"
    ].get(
        "requiredSlices",
        {}
    )

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

        label = row.get(
            "label"
        )

        slice_name = row.get(
            "slice"
        )

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

        prediction = predictions[
            name
        ]

        if not binary(prediction):
            predictions_ok = False
            continue

        label_i = int(label)
        prediction_i = int(prediction)

        slice_total[
            slice_name
        ] = slice_total.get(
            slice_name,
            0
        ) + 1

        if label_i == prediction_i:

            correct += 1

            slice_correct[
                slice_name
            ] = slice_correct.get(
                slice_name,
                0
            ) + 1

    # --------------------------------------------------------
    # ACCURACY
    # --------------------------------------------------------

    if not predictions_ok:

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

        floor = float(
            body["policy"][
                "aggregateFloor"
            ]
        )

        if (
            aggregate is None
            or aggregate < floor
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

    if isinstance(latencies, dict):

        value = latencies.get(
            name
        )

        if (
            finite(value)
            and float(value) >= 0
        ):

            latency = value

            if isinstance(
                latency,
                float
            ) and latency.is_integer():

                latency = int(
                    latency
                )

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

    # --------------------------------------------------------
    # ADMISSION
    # --------------------------------------------------------

    admitted = True

    if name not in frozen_names:
        admitted = False

    if candidate.get(
        "status"
    ) != "frozen":
        admitted = False

    if not manifest_ok:
        admitted = False

    if not predictions_ok:
        admitted = False

    if aggregate is None:
        admitted = False

    if (
        aggregate is not None
        and aggregate
        < float(
            body["policy"][
                "aggregateFloor"
            ]
        )
    ):
        admitted = False

    for slice_name, floor in required.items():

        value = slices.get(
            slice_name
        )

        if value is None:
            admitted = False

        elif value < float(floor):
            admitted = False

    if (
        total is None
        or total > body["policy"]["maxBytes"]
    ):
        admitted = False

    if latency is None:
        admitted = False

    elif (
        float(latency)
        > float(
            body["policy"][
                "maxLatencyMs"
            ]
        )
    ):
        admitted = False

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": sort_codes(
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
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # UNKNOWN FREEZE
    # --------------------------------------------------------

    if stored is None:

        results = []

        for c in body[
            "candidates"
        ]:

            name = ""

            if isinstance(c, dict):
                if isinstance(
                    c.get("name"),
                    str
                ):
                    name = c[
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

    stored_candidates = stored[
        "response"
    ]["candidates"]

    frozen_names = {
        c["name"]
        for c in stored_candidates
    }

    frozen_by_name = {
        c["name"]: c
        for c in stored_candidates
    }

    submitted = body[
        "candidates"
    ]

    # --------------------------------------------------------
    # EXACT LINEAGE
    # --------------------------------------------------------

    lineage_ok = (
        submitted
        == stored_candidates
    )

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    policy_ok = validate_policy(
        body.get("policy")
    )

    policy = body[
        "policy"
    ]

    submitted_names = []

    for c in submitted:

        if isinstance(c, dict):

            name = c.get(
                "name"
            )

            if isinstance(
                name,
                str
            ):
                submitted_names.append(
                    name
                )

    if policy_ok:

        order = policy[
            "candidateOrder"
        ]

        order_set = {
            u8(x)
            for x in order
        }

        name_set = {
            u8(x)
            for x in submitted_names
        }

        order_ok = (
            order_set == name_set
            and len(order)
            == len(submitted_names)
        )

    else:

        order = []
        order_ok = False

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

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
                    "INVALID_LINEAGE",
                    "INVALID_MANIFEST",
                    "INVALID_PREDICTIONS"
                ]
            })

            continue

        result = calculate_candidate(
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

        if not policy_ok or not order_ok:

            result["admitted"] = False

            result["reasonCodes"] = sort_codes(
                result["reasonCodes"]
                + ["INVALID_POLICY"]
            )

        results.append(
            result
        )

    # --------------------------------------------------------
    # RESULT ORDER
    # --------------------------------------------------------

    if policy_ok:

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

    # --------------------------------------------------------
    # WINNER
    # --------------------------------------------------------

    eligible = [
        r
        for r in results
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
            for i, name in enumerate(order)
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

        manifest = frozen_by_name[
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

        candidates = body.get(
            "candidates"
        )

        # The problem explicitly requires 400 only for
        # missing/non-array/empty freeze candidate list.
        if (
            not isinstance(
                candidates,
                list
            )
            or len(candidates) == 0
        ):

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400
            )

        # freezeId is required by the contract.
        freeze_id = body.get(
            "freezeId"
        )

        if (
            not isinstance(
                freeze_id,
                str
            )
            or len(freeze_id) == 0
            or len(freeze_id) > 128
        ):

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

        candidates = body.get(
            "candidates"
        )

        rows = body.get(
            "rows"
        )

        policy = body.get(
            "policy"
        )

        # EXACT request-level condition from question.
        if (
            not isinstance(
                candidates,
                list
            )
            or not isinstance(
                rows,
                list
            )
            or not isinstance(
                policy,
                dict
            )
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

        result, status = do_select(
            body
        )

        return JSONResponse(
            result,
            status_code=status
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

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
        "ok": True
    }
