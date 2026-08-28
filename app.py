from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

LOCK = threading.RLock()
FREEZES: dict[str, dict[str, Any]] = {}

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# Helpers
# ============================================================

def nonempty_string(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def finite_number(x: Any) -> bool:
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
    )


def safe_nonnegative_integer(x: Any) -> bool:
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE_INTEGER
    )


def utf8_sort_key(x: str) -> bytes:
    return x.encode("utf-8")


def sort_codes(codes: list[str]) -> list[str]:
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def make_package_digest(inventory: list[dict[str, Any]]) -> str:
    return sha256(compact_json_bytes(inventory))


def round12(x: float) -> float:
    return round(float(x), 12)


def binary_value(x: Any) -> bool:
    if isinstance(x, bool):
        return False

    if isinstance(x, int):
        return x == 0 or x == 1

    if isinstance(x, float):
        return math.isfinite(x) and (x == 0.0 or x == 1.0)

    return False


def unique_strings(values: Any) -> bool:
    if not isinstance(values, list):
        return False

    if not all(nonempty_string(x) for x in values):
        return False

    encoded = [x.encode("utf-8") for x in values]
    return len(encoded) == len(set(encoded))


# ============================================================
# Freeze inventory
# ============================================================

def make_inventory(files: Any):
    """
    Returns:
        inventory
        totalBytes
        packageDigest
        valid
    """

    if not isinstance(files, dict):
        return [], None, None, False

    if len(files) == 0:
        return [], None, None, False

    inventory = []
    seen = set()

    for filename, text in files.items():

        if not isinstance(filename, str) or filename == "":
            return [], None, None, False

        if filename.encode("utf-8") in seen:
            return [], None, None, False

        seen.add(filename.encode("utf-8"))

        # File text is data. It must be a UTF-8 string.
        if not isinstance(text, str):
            return [], None, None, False

        data = text.encode("utf-8")

        inventory.append(
            {
                "name": filename,
                "bytes": len(data),
                "sha256": sha256(data),
            }
        )

    inventory.sort(key=lambda x: x["name"].encode("utf-8"))

    total_bytes = sum(x["bytes"] for x in inventory)

    digest = make_package_digest(inventory)

    return inventory, total_bytes, digest, True


# ============================================================
# Freeze request validation
# ============================================================

def valid_freeze_request(body: Any) -> bool:

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not isinstance(freeze_id, str):
        return False

    if len(freeze_id) == 0 or len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not unique_strings(allowed):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

    encoded_names = [x.encode("utf-8") for x in names]

    if len(encoded_names) != len(set(encoded_names)):
        return False

    return True


# ============================================================
# Freeze
# ============================================================

def freeze(body: dict[str, Any]):

    freeze_id = body["freezeId"]

    with LOCK:

        # Existing ID
        if freeze_id in FREEZES:

            existing = FREEZES[freeze_id]

            if existing["input"] == body:
                return existing["response"], 200

            return {
                "error": "FREEZE_ID_CONFLICT"
            }, 409

        request_calibration = body["calibrationDigest"]
        request_tokenizer = body["tokenizerDigest"]

        allowed_reasons = set(
            body["allowedUnsupportedReasons"]
        )

        result_candidates = []

        candidates = sorted(
            body["candidates"],
            key=lambda c: c["name"].encode("utf-8"),
        )

        for candidate in candidates:

            name = candidate["name"]

            reason_codes = []

            # ----------------------------
            # Files
            # ----------------------------

            if "files" not in candidate:

                inventory = []
                total_bytes = None
                package_digest = None
                files_valid = False

                reason_codes.append("INVALID_INPUT")

            else:

                (
                    inventory,
                    total_bytes,
                    package_digest,
                    files_valid,
                ) = make_inventory(candidate.get("files"))

                if not files_valid:
                    reason_codes.append("INVALID_INPUT")

            # ----------------------------
            # Candidate metadata
            # ----------------------------

            loadable = candidate.get("loadable")
            candidate_calibration = candidate.get(
                "calibrationDigest"
            )
            candidate_tokenizer = candidate.get(
                "tokenizerDigest"
            )

            metadata_valid = True

            if not isinstance(loadable, bool):
                metadata_valid = False

            if not nonempty_string(candidate_calibration):
                metadata_valid = False

            if not nonempty_string(candidate_tokenizer):
                metadata_valid = False

            if not metadata_valid:
                reason_codes.append("INVALID_INPUT")

            # ----------------------------
            # Unsupported reason
            # ----------------------------

            has_reason = "unsupportedReason" in candidate
            unsupported_reason = candidate.get(
                "unsupportedReason"
            )

            if has_reason and not isinstance(
                unsupported_reason, str
            ):
                reason_codes.append("INVALID_INPUT")
                has_reason = False

            # ----------------------------
            # Determine status
            # ----------------------------

            status = "frozen"

            if has_reason:

                if unsupported_reason in allowed_reasons:

                    # Allowed unsupported reason means the
                    # candidate is explicitly unsupported.
                    status = "unsupported"

                else:

                    reason_codes.append(
                        "UNALLOWED_UNSUPPORTED_REASON"
                    )

                    # It must otherwise satisfy the normal
                    # loadability and lineage requirements.
                    if metadata_valid:

                        if loadable is False:
                            reason_codes.append(
                                "NOT_LOADABLE"
                            )

                        if (
                            candidate_calibration
                            != request_calibration
                        ):
                            reason_codes.append(
                                "CALIBRATION_MISMATCH"
                            )

                        if (
                            candidate_tokenizer
                            != request_tokenizer
                        ):
                            reason_codes.append(
                                "TOKENIZER_MISMATCH"
                            )

                    status = "invalid"

            else:

                if metadata_valid:

                    if loadable is False:
                        reason_codes.append(
                            "NOT_LOADABLE"
                        )

                    if (
                        candidate_calibration
                        != request_calibration
                    ):
                        reason_codes.append(
                            "CALIBRATION_MISMATCH"
                        )

                    if (
                        candidate_tokenizer
                        != request_tokenizer
                    ):
                        reason_codes.append(
                            "TOKENIZER_MISMATCH"
                        )

            # Any reason makes the candidate invalid,
            # except an explicitly allowed unsupported reason.
            if reason_codes:

                if not (
                    has_reason
                    and unsupported_reason in allowed_reasons
                    and reason_codes == []
                ):
                    status = "invalid"

            # Allowed unsupported candidate stays unsupported
            # unless its own structure/files are invalid.
            if (
                has_reason
                and unsupported_reason in allowed_reasons
                and files_valid
                and metadata_valid
            ):
                status = "unsupported"

            # Invalid files always have empty/null inventory.
            if not files_valid:

                inventory_out = []
                total_out = None
                digest_out = None

            else:

                inventory_out = inventory
                total_out = total_bytes
                digest_out = package_digest

            result_candidates.append(
                {
                    "name": name,
                    "status": status,
                    "inventory": inventory_out,
                    "totalBytes": total_out,
                    "packageDigest": digest_out,
                    "reasonCodes": sort_codes(reason_codes),
                }
            )

        response = {
            "freezeId": freeze_id,
            "candidates": result_candidates,
        }

        FREEZES[freeze_id] = {
            "input": body,
            "response": response,
        }

        return response, 200


# ============================================================
# Policy validation
# ============================================================

def valid_policy(policy: Any) -> bool:

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")

    if not safe_nonnegative_integer(max_bytes):
        return False

    aggregate_floor = policy.get("aggregateFloor")

    if not finite_number(aggregate_floor):
        return False

    if not 0 <= float(aggregate_floor) <= 1:
        return False

    required_slices = policy.get("requiredSlices")

    if not isinstance(required_slices, dict):
        return False

    seen_slices = set()

    for slice_name, floor in required_slices.items():

        if not nonempty_string(slice_name):
            return False

        key = slice_name.encode("utf-8")

        if key in seen_slices:
            return False

        seen_slices.add(key)

        if not finite_number(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    max_latency = policy.get("maxLatencyMs")

    if not finite_number(max_latency):
        return False

    if float(max_latency) < 0:
        return False

    order = policy.get("candidateOrder")

    if not unique_strings(order):
        return False

    return True


# ============================================================
# Select request validation
# ============================================================

def valid_select_request(body: Any) -> bool:

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    rows = body.get("rows")

    if not isinstance(rows, list):
        return False

    policy = body.get("policy")

    if not isinstance(policy, dict):
        return False

    return True


# ============================================================
# Manifest verification
# ============================================================

def verify_manifest(candidate: dict[str, Any]):

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return None, None, None, False

    normalized = []

    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return None, None, None, False

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return None, None, None, False

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return None, None, None, False

        name_key = name.encode("utf-8")

        if name_key in seen:
            return None, None, None, False

        seen.add(name_key)

        if not safe_nonnegative_integer(byte_count):
            return None, None, None, False

        if (
            not isinstance(digest, str)
            or len(digest) != 64
        ):
            return None, None, None, False

        try:
            int(digest, 16)
        except Exception:
            return None, None, None, False

        normalized.append(
            {
                "name": name,
                "bytes": byte_count,
                "sha256": digest,
            }
        )

    normalized.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    # The submitted inventory itself must already be in canonical order.
    submitted_inventory = inventory

    if submitted_inventory != normalized:
        return (
            normalized,
            None,
            None,
            False,
        )

    total_bytes = sum(
        x["bytes"] for x in normalized
    )

    calculated_digest = make_package_digest(
        normalized
    )

    if candidate.get("totalBytes") != total_bytes:
        return (
            normalized,
            total_bytes,
            calculated_digest,
            False,
        )

    if candidate.get("packageDigest") != calculated_digest:
        return (
            normalized,
            total_bytes,
            calculated_digest,
            False,
        )

    return (
        normalized,
        total_bytes,
        calculated_digest,
        True,
    )


# ============================================================
# Candidate metrics
# ============================================================

def calculate_candidate(
    candidate: dict[str, Any],
    stored_names: set[str],
    body: dict[str, Any],
):

    name = candidate.get("name")

    codes = []

    # ----------------------------
    # Frozen lineage
    # ----------------------------

    if name not in stored_names:
        codes.append("NOT_FROZEN")

    if candidate.get("status") != "frozen":
        codes.append("NOT_FROZEN")

    # ----------------------------
    # Manifest
    # ----------------------------

    (
        inventory,
        total_bytes,
        calculated_digest,
        manifest_valid,
    ) = verify_manifest(candidate)

    if not manifest_valid:
        codes.append("INVALID_MANIFEST")

    # ----------------------------
    # Predictions
    # ----------------------------

    rows = body["rows"]
    policy = body["policy"]
    required_slices = policy["requiredSlices"]

    predictions_valid = True

    correct = 0

    slice_correct: dict[str, int] = {}
    slice_total: dict[str, int] = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_valid = False
            continue

        if "label" not in row:
            predictions_valid = False
            continue

        if "slice" not in row:
            predictions_valid = False
            continue

        label = row["label"]
        slice_name = row["slice"]

        if not binary_value(label):
            predictions_valid = False
            continue

        if not isinstance(slice_name, str):
            predictions_valid = False
            continue

        predictions = row.get("predictions")

        if not isinstance(predictions, dict):
            predictions_valid = False
            continue

        if name not in predictions:
            predictions_valid = False
            continue

        prediction = predictions[name]

        if not binary_value(prediction):
            predictions_valid = False
            continue

        prediction_int = int(prediction)
        label_int = int(label)

        is_correct = prediction_int == label_int

        if is_correct:
            correct += 1

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if is_correct:
            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    # ----------------------------
    # Accuracy
    # ----------------------------

    if not predictions_valid:

        aggregate = None

        slices = {
            slice_name: None
            for slice_name in required_slices
        }

        codes.append("INVALID_PREDICTIONS")

    else:

        if len(rows) == 0:
            aggregate = None
            codes.append("AGGREGATE_FLOOR")
        else:
            aggregate = round12(
                correct / len(rows)
            )

        slices = {}

        for slice_name in required_slices:

            count = slice_total.get(
                slice_name,
                0,
            )

            if count == 0:

                slices[slice_name] = None

                codes.append(
                    f"MISSING_SLICE:{slice_name}"
                )

            else:

                accuracy = round12(
                    slice_correct.get(
                        slice_name,
                        0,
                    )
                    / count
                )

                slices[slice_name] = accuracy

                floor = float(
                    required_slices[slice_name]
                )

                if accuracy < floor:
                    codes.append(
                        f"SLICE_FLOOR:{slice_name}"
                    )

        if (
            aggregate is None
            or aggregate
            < float(policy["aggregateFloor"])
        ):
            codes.append("AGGREGATE_FLOOR")

    # ----------------------------
    # Size
    # ----------------------------

    result_total = (
        total_bytes
        if manifest_valid
        else None
    )

    if (
        manifest_valid
        and total_bytes is not None
        and total_bytes > policy["maxBytes"]
    ):
        codes.append("SIZE_LIMIT")

    # ----------------------------
    # Latency
    # ----------------------------

    latencies = body.get("latencies")

    latency = None

    if (
        isinstance(latencies, dict)
        and name in latencies
        and finite_number(latencies[name])
        and float(latencies[name]) >= 0
    ):

        latency = float(latencies[name])

        if latency.is_integer():
            latency = int(latency)

    else:

        # There is no separate INVALID_LATENCY code in the
        # contract. An unverifiable latency prevents admission.
        codes.append("INVALID_POLICY")

    if (
        latency is not None
        and latency > float(
            policy["maxLatencyMs"]
        )
    ):
        codes.append("LATENCY_LIMIT")

    # ----------------------------
    # Admission
    # ----------------------------

    all_slices_pass = True

    for slice_name, floor in required_slices.items():

        value = slices.get(slice_name)

        if value is None:
            all_slices_pass = False
            break

        if value < float(floor):
            all_slices_pass = False
            break

    admitted = (
        name in stored_names
        and candidate.get("status") == "frozen"
        and manifest_valid
        and predictions_valid
        and aggregate is not None
        and aggregate >= float(
            policy["aggregateFloor"]
        )
        and all_slices_pass
        and total_bytes is not None
        and total_bytes <= policy["maxBytes"]
        and latency is not None
        and latency <= float(
            policy["maxLatencyMs"]
        )
    )

    return {
        "name": name if isinstance(name, str) else "",
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": result_total,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": sort_codes(codes),
    }


# ============================================================
# Select
# ============================================================

def select(body: dict[str, Any]):

    freeze_id = body["freezeId"]

    with LOCK:
        frozen = FREEZES.get(freeze_id)

    # --------------------------------------------------------
    # Unknown freeze
    # --------------------------------------------------------

    if frozen is None:

        results = []

        for candidate in body["candidates"]:

            if isinstance(candidate, dict):
                name = candidate.get("name")
            else:
                name = ""

            if not isinstance(name, str):
                name = ""

            results.append(
                {
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": [
                        "NOT_FROZEN"
                    ],
                }
            )

        results.sort(
            key=lambda x: x["name"].encode("utf-8")
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }, 200

    # --------------------------------------------------------
    # Stored freeze
    # --------------------------------------------------------

    stored_candidates = frozen["response"]["candidates"]

    stored_names = {
        c["name"]
        for c in stored_candidates
    }

    stored_by_name = {
        c["name"]: c
        for c in stored_candidates
    }

    submitted_candidates = body["candidates"]

    # Candidate array must exactly equal the frozen response.
    lineage_valid = (
        submitted_candidates
        == stored_candidates
    )

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy_valid = valid_policy(
        body["policy"]
    )

    policy = body["policy"]

    submitted_names = []

    names_valid = True

    for candidate in submitted_candidates:

        if not isinstance(candidate, dict):
            names_valid = False
            continue

        name = candidate.get("name")

        if not nonempty_string(name):
            names_valid = False
            continue

        submitted_names.append(name)

    encoded_names = [
        x.encode("utf-8")
        for x in submitted_names
    ]

    if len(encoded_names) != len(
        set(encoded_names)
    ):
        names_valid = False

    # --------------------------------------------------------
    # Candidate order
    # --------------------------------------------------------

    if policy_valid:

        candidate_order = policy[
            "candidateOrder"
        ]

        order_set = {
            x.encode("utf-8")
            for x in candidate_order
        }

        names_set = {
            x.encode("utf-8")
            for x in submitted_names
        }

        order_valid = (
            len(candidate_order)
            == len(submitted_names)
            and order_set == names_set
        )

    else:

        candidate_order = []
        order_valid = False

    globally_invalid = (
        not lineage_valid
        or not policy_valid
        or not names_valid
        or not order_valid
    )

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    results = []

    for candidate in submitted_candidates:

        if not isinstance(candidate, dict):

            result = {
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE",
                    "INVALID_POLICY",
                    "INVALID_PREDICTIONS",
                    "INVALID_MANIFEST",
                ],
            }

        else:

            result = calculate_candidate(
                candidate,
                stored_names,
                body,
            )

            if not lineage_valid:
                result["admitted"] = False
                result["reasonCodes"] = sort_codes(
                    result["reasonCodes"]
                    + ["INVALID_LINEAGE"]
                )

            if (
                not policy_valid
                or not names_valid
                or not order_valid
            ):
                result["admitted"] = False
                result["reasonCodes"] = sort_codes(
                    result["reasonCodes"]
                    + ["INVALID_POLICY"]
                )

        results.append(result)

    # --------------------------------------------------------
    # Result ordering
    # --------------------------------------------------------

    if policy_valid:

        order_rank = {
            name: index
            for index, name in enumerate(
                candidate_order
            )
        }

        results.sort(
            key=lambda r: (
                order_rank.get(
                    r["name"],
                    10**9,
                ),
                r["name"].encode("utf-8"),
            )
        )

    else:

        results.sort(
            key=lambda r:
            r["name"].encode("utf-8")
        )

    # --------------------------------------------------------
    # Winner
    # --------------------------------------------------------

    winners = [
        r
        for r in results
        if r["admitted"]
    ]

    if winners and not globally_invalid:

        order_rank = {
            name: index
            for index, name in enumerate(
                candidate_order
            )
        }

        winner = min(
            winners,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                order_rank.get(
                    r["name"],
                    10**9,
                ),
            ),
        )

        selected = winner["name"]

        package_manifest = (
            stored_by_name[selected]
        )

    else:

        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, 200


# ============================================================
# HTTP endpoint
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

    # --------------------------------------------------------
    # Freeze
    # --------------------------------------------------------

    if phase == "freeze":

        if not valid_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        result, status = freeze(body)

        return JSONResponse(
            result,
            status_code=status,
        )

    # --------------------------------------------------------
    # Select
    # --------------------------------------------------------

    if phase == "select":

        if not valid_select_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        result, status = select(body)

        return JSONResponse(
            result,
            status_code=status,
        )

    # Unknown / missing phase
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


# ============================================================
# Health check
# ============================================================

@app.get("/health")
def health():
    return {"ok": True}
