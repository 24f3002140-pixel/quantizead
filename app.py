import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

LOCK = threading.RLock()
FREEZES = {}

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# HELPERS
# ============================================================

def is_string(x):
    return isinstance(x, str)


def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def utf8(x):
    return x.encode("utf-8")


def finite_number(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_nonnegative_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE_INTEGER
    )


def binary_value(x):
    if isinstance(x, bool):
        return False

    if isinstance(x, int):
        return x == 0 or x == 1

    if isinstance(x, float):
        return math.isfinite(x) and (
            x == 0.0 or x == 1.0
        )

    return False


def unique_nonempty_strings(value):
    if not isinstance(value, list):
        return False

    if not all(
        isinstance(x, str) and len(x) > 0
        for x in value
    ):
        return False

    encoded = [utf8(x) for x in value]

    return len(encoded) == len(set(encoded))


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def compact_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False
    ).encode("utf-8")


def make_package_digest(inventory):
    return sha256_bytes(
        compact_json_bytes(inventory)
    )


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=lambda x: x.encode("utf-8")
    )


# ============================================================
# STRICT GLOBAL FREEZE VALIDATION
# ============================================================

def globally_valid_freeze(body):
    """
    Only request-level structural validity belongs here.

    Invalid global freeze input MUST:
      * return HTTP 400
      * return exactly {"error":"INVALID_INPUT"}
      * NOT reserve freezeId
    """

    if not isinstance(body, dict):
        return False

    # Exact phase.
    if body.get("phase") != "freeze":
        return False

    # freezeId: non-empty, <= 128 chars.
    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if len(freeze_id) == 0:
        return False

    if len(freeze_id) > 128:
        return False

    # Request lineage digests.
    calibration = body.get(
        "calibrationDigest"
    )

    tokenizer = body.get(
        "tokenizerDigest"
    )

    if not nonempty_string(calibration):
        return False

    if not nonempty_string(tokenizer):
        return False

    # Allowed unsupported reasons:
    # array, non-empty strings, unique.
    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not unique_nonempty_strings(
        allowed
    ):
        return False

    # Candidate list must be non-empty array.
    candidates = body.get(
        "candidates"
    )

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # Candidate names must be non-empty and unique.
    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

    encoded_names = [
        utf8(x)
        for x in names
    ]

    if len(encoded_names) != len(
        set(encoded_names)
    ):
        return False

    # Candidate-level structure is part of the freeze boundary.
    for candidate in candidates:

        # Files must be a non-empty object.
        files = candidate.get("files")

        if not isinstance(files, dict):
            return False

        if len(files) == 0:
            return False

        filenames = []

        for filename, content in files.items():

            # Filename must be a non-empty string.
            if not isinstance(
                filename,
                str
            ):
                return False

            if len(filename) == 0:
                return False

            # File text is data and must be UTF-8 string.
            if not isinstance(
                content,
                str
            ):
                return False

            filenames.append(filename)

        # Python dict already prevents exact duplicate keys,
        # but retain the explicit UTF-8 uniqueness check.
        encoded_files = [
            utf8(x)
            for x in filenames
        ]

        if len(encoded_files) != len(
            set(encoded_files)
        ):
            return False

        # Required candidate metadata.
        if "loadable" not in candidate:
            return False

        if not isinstance(
            candidate["loadable"],
            bool
        ):
            return False

        candidate_cal = candidate.get(
            "calibrationDigest"
        )

        candidate_tok = candidate.get(
            "tokenizerDigest"
        )

        if not nonempty_string(
            candidate_cal
        ):
            return False

        if not nonempty_string(
            candidate_tok
        ):
            return False

        # unsupportedReason, if supplied, must be
        # a non-empty string.
        if "unsupportedReason" in candidate:

            reason = candidate[
                "unsupportedReason"
            ]

            if not nonempty_string(
                reason
            ):
                return False

    return True


# ============================================================
# INVENTORY
# ============================================================

def build_inventory(files):

    inventory = []

    for filename, content in files.items():

        data = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": sha256_bytes(data)
        })

    inventory.sort(
        key=lambda x:
            x["name"].encode("utf-8")
    )

    total = sum(
        x["bytes"]
        for x in inventory
    )

    digest = make_package_digest(
        inventory
    )

    return inventory, total, digest


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    with LOCK:

        # Replay.
        if freeze_id in FREEZES:

            stored = FREEZES[
                freeze_id
            ]

            if stored["input"] == body:
                return (
                    stored["response"],
                    200
                )

            return (
                {
                    "error":
                    "FREEZE_ID_CONFLICT"
                },
                409
            )

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

        results = []

        candidates = sorted(
            body["candidates"],
            key=lambda c:
                c["name"].encode("utf-8")
        )

        for candidate in candidates:

            name = candidate[
                "name"
            ]

            codes = []

            files = candidate[
                "files"
            ]

            inventory, total, digest = \
                build_inventory(files)

            loadable = candidate[
                "loadable"
            ]

            candidate_cal = candidate[
                "calibrationDigest"
            ]

            candidate_tok = candidate[
                "tokenizerDigest"
            ]

            has_reason = (
                "unsupportedReason"
                in candidate
            )

            reason = candidate.get(
                "unsupportedReason"
            )

            # ------------------------------------------------
            # UNSUPPORTED
            # ------------------------------------------------

            if has_reason:

                if reason in allowed:

                    status = "unsupported"

                else:

                    status = "invalid"

                    codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

                    # For an unallowed reason, the normal
                    # candidate constraints are also checked.
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

            # ------------------------------------------------
            # NORMAL FROZEN CANDIDATE
            # ------------------------------------------------

            else:

                status = "frozen"

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

                if codes:
                    status = "invalid"

            results.append({
                "name": name,
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": digest,
                "reasonCodes": sorted_codes(
                    codes
                )
            })

        response = {
            "freezeId": freeze_id,
            "candidates": results
        }

        # IMPORTANT:
        # Only globally-valid requests reach this point,
        # therefore invalid global requests never reserve IDs.
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

    if not isinstance(
        inventory,
        list
    ):
        return False, None

    canonical = []
    names = set()

    for item in inventory:

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

        byte_count = item.get(
            "bytes"
        )

        digest = item.get(
            "sha256"
        )

        if not nonempty_string(
            name
        ):
            return False, None

        key = utf8(name)

        if key in names:
            return False, None

        names.add(key)

        if not safe_nonnegative_integer(
            byte_count
        ):
            return False, None

        if (
            not isinstance(
                digest,
                str
            )
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

    digest = make_package_digest(
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
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(
        policy,
        dict
    ):
        return False

    max_bytes = policy.get(
        "maxBytes"
    )

    if not safe_nonnegative_integer(
        max_bytes
    ):
        return False

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not finite_number(
        aggregate_floor
    ):
        return False

    if not (
        0 <= float(
            aggregate_floor
        ) <= 1
    ):
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required,
        dict
    ):
        return False

    seen = set()

    for slice_name, floor in required.items():

        if not nonempty_string(
            slice_name
        ):
            return False

        key = utf8(slice_name)

        if key in seen:
            return False

        seen.add(key)

        if not finite_number(
            floor
        ):
            return False

        if not (
            0 <= float(floor) <= 1
        ):
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not finite_number(
        max_latency
    ):
        return False

    if float(max_latency) < 0:
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(
        order
    ):
        return False

    return True


# ============================================================
# CANDIDATE METRICS
# ============================================================

def evaluate_candidate(
    candidate,
    body,
    frozen_names
):

    name = candidate.get(
        "name"
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
        validate_manifest(
            candidate
        )

    if not manifest_ok:
        codes.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # PREDICTIONS
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

    predictions_ok = True

    correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(
            row,
            dict
        ):
            predictions_ok = False
            continue

        if "label" not in row:
            predictions_ok = False
            continue

        if "slice" not in row:
            predictions_ok = False
            continue

        label = row[
            "label"
        ]

        slice_name = row[
            "slice"
        ]

        if not binary_value(
            label
        ):
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

        if not binary_value(
            prediction
        ):
            predictions_ok = False
            continue

        label_i = int(label)
        prediction_i = int(
            prediction
        )

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

                if value < float(
                    floor
                ):
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
        and total
        > body["policy"]["maxBytes"]
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
        and finite_number(
            latencies[name]
        )
        and float(
            latencies[name]
        ) >= 0
    ):

        latency = latencies[
            name
        ]

        if (
            isinstance(
                latency,
                float
            )
            and latency.is_integer()
        ):
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

    elif aggregate < float(
        body["policy"][
            "aggregateFloor"
        ]
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
        or total
        > body["policy"]["maxBytes"]
    ):
        admitted = False

    if latency is None:
        admitted = False

    elif float(latency) > float(
        body["policy"][
            "maxLatencyMs"
        ]
    ):
        admitted = False

    return {
        "name": name,
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
        stored = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # NOT FROZEN
    # --------------------------------------------------------

    if stored is None:

        results = []

        for candidate in body[
            "candidates"
        ]:

            name = ""

            if isinstance(
                candidate,
                dict
            ):
                if isinstance(
                    candidate.get(
                        "name"
                    ),
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
                x["name"].encode(
                    "utf-8"
                )
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None
        }, 200

    # --------------------------------------------------------
    # STORED CANDIDATES
    # --------------------------------------------------------

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

    # Exact equality.
    lineage_ok = (
        submitted
        == stored_candidates
    )

    # --------------------------------------------------------
    # POLICY
    # --------------------------------------------------------

    policy = body[
        "policy"
    ]

    policy_ok = validate_policy(
        policy
    )

    if policy_ok:

        order = policy[
            "candidateOrder"
        ]

        submitted_names = [
            c.get("name")
            for c in submitted
            if isinstance(
                c,
                dict
            )
        ]

        name_set = {
            utf8(x)
            for x in submitted_names
            if isinstance(x, str)
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
            and name_set
            == order_set
        )

    else:

        order = []
        order_ok = False

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for candidate in submitted:

        if not isinstance(
            candidate,
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

        result = evaluate_candidate(
            candidate,
            body,
            frozen_names
        )

        if not lineage_ok:

            result["admitted"] = False

            result[
                "reasonCodes"
            ] = sorted_codes(
                result[
                    "reasonCodes"
                ]
                + [
                    "INVALID_LINEAGE"
                ]
            )

        if (
            not policy_ok
            or not order_ok
        ):

            result["admitted"] = False

            result[
                "reasonCodes"
            ] = sorted_codes(
                result[
                    "reasonCodes"
                ]
                + [
                    "INVALID_POLICY"
                ]
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
            frozen_by_name[
                selected
            ]
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
    }, 200


# ============================================================
# ENDPOINT
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

    if not isinstance(
        body,
        dict
    ):
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

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        # IMPORTANT:
        # Perform COMPLETE global validation BEFORE
        # looking at/reserving freezeId.
        if not globally_valid_freeze(
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

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Exact request-level requirement.
        if not isinstance(
            body.get("candidates"),
            list
        ):
            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("rows"),
            list
        ):
            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("policy"),
            dict
        ):
            return JSONResponse(
                {
                    "error":
                    "INVALID_INPUT"
                },
                status_code=400
            )

        if not isinstance(
            body.get("freezeId"),
            str
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

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

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
