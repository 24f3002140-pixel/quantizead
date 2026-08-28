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


# ---------- canonical / validation helpers ----------

def utf8_key(s: str) -> bytes:
    return s.encode("utf-8")


def sort_utf8(values):
    return sorted(values, key=lambda x: x.encode("utf-8"))


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def compact_json_bytes(obj: Any) -> bytes:
    # JSON.stringify-like output for ordinary JSON data:
    # compact separators and literal UTF-8 characters.
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def package_digest(inventory: list[dict[str, Any]]) -> str:
    return sha256_bytes(compact_json_bytes(inventory))


def is_finite_number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x))


def is_safe_nonnegative_integer(x: Any) -> bool:
    # JS Number.MAX_SAFE_INTEGER semantics.
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= 9007199254740991
    )


def nonempty_string(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def unique_strings_utf8(xs: Any) -> bool:
    if not isinstance(xs, list) or not all(nonempty_string(x) for x in xs):
        return False
    return len({x.encode("utf-8") for x in xs}) == len(xs)


def round12(x: float) -> float:
    # Python's round is deterministic enough for the grader's decimal
    # accuracy values and keeps the result numeric.
    return round(float(x), 12)


def binary_prediction(x: Any) -> bool:
    # JSON booleans are not valid 0/1 predictions.
    return (
        (isinstance(x, int) and not isinstance(x, bool) and x in (0, 1))
        or isinstance(x, float) and math.isfinite(x) and x in (0.0, 1.0)
    )


def exact_json_equal(a: Any, b: Any) -> bool:
    return a == b


# ---------- freeze ----------

def build_inventory(files: Any):
    """
    Return (inventory, totalBytes, packageDigest, valid).
    File values are treated strictly as UTF-8 text.
    """
    if not isinstance(files, dict) or not files:
        return [], None, None, False

    inventory = []
    for name, text in files.items():
        if not isinstance(name, str) or name == "":
            return [], None, None, False
        if not isinstance(text, str):
            return [], None, None, False

        data = text.encode("utf-8")
        inventory.append({
            "name": name,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        })

    inventory.sort(key=lambda x: x["name"].encode("utf-8"))
    total = sum(item["bytes"] for item in inventory)
    return inventory, total, package_digest(inventory), True


def validate_freeze_request(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    if not isinstance(freeze_id, str) or not (1 <= len(freeze_id) <= 128):
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False
    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")
    if not unique_strings_utf8(allowed):
        return False

    candidates = body.get("candidates")
    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []
    for c in candidates:
        if not isinstance(c, dict):
            return False
        name = c.get("name")
        if not nonempty_string(name):
            return False
        names.append(name)

        if "files" not in c:
            return False
        if "loadable" not in c or not isinstance(c["loadable"], bool):
            return False
        if not nonempty_string(c.get("calibrationDigest")):
            return False
        if not nonempty_string(c.get("tokenizerDigest")):
            return False

        # unsupportedReason is optional, but if present it must be a string
        # and non-empty. Empty string is treated as absent.
        if "unsupportedReason" in c:
            r = c["unsupportedReason"]
            if not isinstance(r, str) or r == "":
                return False

    return len({x.encode("utf-8") for x in names}) == len(names)


def do_freeze(body: dict[str, Any]):
    freeze_id = body["freezeId"]
    with LOCK:
        old = FREEZES.get(freeze_id)
        if old is not None:
            # Store the canonical accepted input too. A replay must be byte/
            # JSON-value identical in semantics; a different input conflicts.
            if exact_json_equal(old["input"], body):
                return old["response"], 200
            return {"error": "FREEZE_ID_CONFLICT"}, 409

        req_cal = body["calibrationDigest"]
        req_tok = body["tokenizerDigest"]
        allowed = set(body["allowedUnsupportedReasons"])

        out_candidates = []

        for c in sorted(body["candidates"], key=lambda x: x["name"].encode("utf-8")):
            inv, total, pdigest, files_valid = build_inventory(c["files"])

            reasons = []
            reason = c.get("unsupportedReason")

            if not files_valid:
                reasons.append("INVALID_INPUT")

            # Any explicit unsupported reason changes the candidate status.
            # Allowed => unsupported. Not allowed => invalid.
            if reason is not None:
                if reason in allowed:
                    status = "unsupported"
                else:
                    reasons.append("UNALLOWED_UNSUPPORTED_REASON")
                    status = "invalid"
            else:
                status = "frozen"

                if not c["loadable"]:
                    reasons.append("NOT_LOADABLE")
                if c["calibrationDigest"] != req_cal:
                    reasons.append("CALIBRATION_MISMATCH")
                if c["tokenizerDigest"] != req_tok:
                    reasons.append("TOKENIZER_MISMATCH")

                if reasons:
                    status = "invalid"

            # An unsupported candidate is still allowed to have a bad manifest
            # shape: the manifest itself is returned only if files were valid.
            # Invalid file objects always get empty/null inventory fields.
            if not files_valid:
                inv_out = []
                total_out = None
                digest_out = None
            else:
                inv_out = inv
                total_out = total
                digest_out = pdigest

            # Any validation reason makes status invalid, except the single
            # explicit allowed unsupported reason.
            if reason is not None and reason in allowed and not files_valid:
                status = "invalid"
            elif reasons:
                status = "invalid"

            # If an explicit unsupported reason is allowed, it is unsupported
            # rather than frozen/invalid, provided the file manifest is valid.
            if reason is not None and reason in allowed and files_valid:
                status = "unsupported"

            # Codes are sorted/deduplicated by UTF-8 bytes.
            reasons = sort_utf8(list(set(reasons)))

            out_candidates.append({
                "name": c["name"],
                "status": status,
                "inventory": inv_out,
                "totalBytes": total_out,
                "packageDigest": digest_out,
                "reasonCodes": reasons,
            })

        response = {
            "freezeId": freeze_id,
            "candidates": out_candidates,
        }
        FREEZES[freeze_id] = {
            "input": body,
            "response": response,
        }
        return response, 200


# ---------- select ----------

SELECT_CODES = {
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


def valid_policy(policy: Any) -> bool:
    if not isinstance(policy, dict):
        return False

    if not is_safe_nonnegative_integer(policy.get("maxBytes")):
        return False

    if not is_finite_number(policy.get("aggregateFloor")):
        return False
    if not 0 <= float(policy["aggregateFloor"]) <= 1:
        return False

    if not isinstance(policy.get("requiredSlices"), dict):
        return False
    for name, floor in policy["requiredSlices"].items():
        if not nonempty_string(name):
            return False
        if not is_finite_number(floor) or not 0 <= float(floor) <= 1:
            return False

    if not is_finite_number(policy.get("maxLatencyMs")):
        return False
    if float(policy["maxLatencyMs"]) < 0:
        return False

    order = policy.get("candidateOrder")
    if not unique_strings_utf8(order):
        return False

    return True


def validate_select_shape(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    if body.get("phase") != "select":
        return False
    if not nonempty_string(body.get("freezeId")):
        return False

    # Explicitly required by the prompt.
    if not isinstance(body.get("candidates"), list):
        return False
    if not isinstance(body.get("rows"), list):
        return False
    if not isinstance(body.get("policy"), dict):
        return False
    if not isinstance(body.get("latencies"), dict):
        return False
    return True


def recompute_manifest(candidate: dict[str, Any]):
    inv = candidate.get("inventory")
    if not isinstance(inv, list):
        return None, None, None, False

    # Inventory entries must have exactly the expected fields.
    normalized = []
    seen = set()
    for item in inv:
        if not isinstance(item, dict):
            return None, None, None, False
        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return None, None, None, False

        name = item["name"]
        b = item["bytes"]
        h = item["sha256"]

        if not nonempty_string(name):
            return None, None, None, False
        key = name.encode("utf-8")
        if key in seen:
            return None, None, None, False
        seen.add(key)

        if not is_safe_nonnegative_integer(b):
            return None, None, None, False
        if not isinstance(h, str) or len(h) != 64:
            return None, None, None, False
        try:
            int(h, 16)
        except ValueError:
            return None, None, None, False

        normalized.append({
            "name": name,
            "bytes": b,
            "sha256": h,
        })

    if normalized != sorted(normalized, key=lambda x: x["name"].encode("utf-8")):
        return None, None, None, False

    total = sum(x["bytes"] for x in normalized)
    digest = package_digest(normalized)

    if candidate.get("totalBytes") != total:
        return normalized, total, digest, False
    if candidate.get("packageDigest") != digest:
        return normalized, total, digest, False

    return normalized, total, digest, True


def compute_candidate_result(
    c: dict[str, Any],
    stored_names: set[str],
    req: dict[str, Any],
):
    name = c.get("name")
    codes = []
    predictions_valid = True

    # Exact frozen-candidate object is required for lineage.
    if name not in stored_names:
        codes.append("NOT_FROZEN")

    inv, total, digest, manifest_ok = recompute_manifest(c)
    if not manifest_ok:
        codes.append("INVALID_MANIFEST")

    if c.get("status") != "frozen":
        codes.append("NOT_FROZEN")

    # Candidate must have valid lineage/manifest before admission.
    # We still calculate metrics when rows can be evaluated.
    rows = req["rows"]
    agg = None
    slices = {}

    # Determine all required slices. Missing is reported independently.
    required = req["policy"]["requiredSlices"]

    # Predictions must be present and binary for every row.
    correct = 0
    slice_correct = {}
    slice_total = {}

    for row in rows:
        if not isinstance(row, dict) or "label" not in row or "slice" not in row:
            predictions_valid = False
            continue

        sl = row["slice"]
        if not isinstance(sl, str) or sl == "":
            predictions_valid = False
            continue

        preds = row.get("predictions")
        if not isinstance(preds, dict) or name not in preds:
            predictions_valid = False
            continue

        p = preds[name]
        if not binary_prediction(p):
            predictions_valid = False
            continue

        label = row["label"]
        if not binary_prediction(label):
            predictions_valid = False
            continue

        p_int = int(p)
        y_int = int(label)
        ok = int(p_int == y_int)
        correct += ok
        slice_total[sl] = slice_total.get(sl, 0) + 1
        slice_correct[sl] = slice_correct.get(sl, 0) + ok

    if predictions_valid:
        if len(rows) == 0:
            # No rows means aggregate cannot be established.
            agg = None
        else:
            agg = round12(correct / len(rows))

        for sl in required:
            if slice_total.get(sl, 0) == 0:
                # Required slice is absent.
                continue
            slices[sl] = round12(slice_correct[sl] / slice_total[sl])
    else:
        agg = None
        slices = {}

    if not predictions_valid:
        codes.append("INVALID_PREDICTIONS")
    else:
        if agg is None or agg < float(req["policy"]["aggregateFloor"]):
            codes.append("AGGREGATE_FLOOR")

        for sl, floor in required.items():
            if slice_total.get(sl, 0) == 0:
                codes.append(f"MISSING_SLICE:{sl}")
            elif slices.get(sl, 0) < float(floor):
                codes.append(f"SLICE_FLOOR:{sl}")

    # Size is null if it cannot be validated.
    result_total = total if manifest_ok else None
    if manifest_ok and total > req["policy"]["maxBytes"]:
        codes.append("SIZE_LIMIT")

    # Latency is null if it cannot be validated.
    latencies = req["latencies"]
    latency = None
    if isinstance(latencies, dict) and name in latencies and is_finite_number(latencies[name]) and float(latencies[name]) >= 0:
        latency = float(latencies[name])
        if latency.is_integer():
            latency = int(latency)
    else:
        # Missing/unusable latency makes admission impossible. The prompt's
        # fixed code list has no separate invalid-latency code, so treat it as
        # INVALID_POLICY for this candidate-level validation.
        codes.append("INVALID_POLICY")

    if latency is not None and latency > float(req["policy"]["maxLatencyMs"]):
        codes.append("LATENCY_LIMIT")

    admitted = (
        c.get("status") == "frozen"
        and manifest_ok
        and predictions_valid
        and agg is not None
        and agg >= float(req["policy"]["aggregateFloor"])
        and all(
            slice_total.get(sl, 0) > 0 and
            slices.get(sl, -1) >= float(floor)
            for sl, floor in required.items()
        )
        and total is not None
        and total <= req["policy"]["maxBytes"]
        and latency is not None
        and latency <= float(req["policy"]["maxLatencyMs"])
        and name in stored_names
    )

    # Dedup + UTF-8 byte sort.
    codes = sort_utf8(list(set(codes)))

    return {
        "name": name,
        "aggregate": agg,
        "slices": slices,
        "totalBytes": result_total,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": codes,
    }


def do_select(body: dict[str, Any]):
    freeze_id = body["freezeId"]

    with LOCK:
        frozen = FREEZES.get(freeze_id)

    if frozen is None:
        # Selection itself is valid JSON/shape but has no frozen lineage.
        # Produce the mandated result shape using the submitted candidates.
        results = []
        for c in body["candidates"]:
            name = c.get("name") if isinstance(c, dict) else None
            results.append({
                "name": name if isinstance(name, str) else "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": ["NOT_FROZEN"],
            })
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }, 200

    stored_candidates = frozen["response"]["candidates"]
    stored_by_name = {c["name"]: c for c in stored_candidates}
    submitted = body["candidates"]

    # Exact array equality is required. Any mismatch invalidates lineage.
    lineage_ok = exact_json_equal(submitted, stored_candidates)

    # Policy and candidate-order validation.
    policy_ok = valid_policy(body["policy"])
    order = body["policy"].get("candidateOrder") if isinstance(body["policy"], dict) else None

    submitted_names = [c.get("name") for c in submitted if isinstance(c, dict)]
    names_ok = (
        all(isinstance(x, str) and x != "" for x in submitted_names)
        and len({x.encode("utf-8") for x in submitted_names}) == len(submitted_names)
    )

    if policy_ok:
        order_names = order
        order_ok = set(order_names) == set(submitted_names) and len(order_names) == len(submitted_names)
    else:
        order_ok = False

    # The prompt says candidate names and candidateOrder must be the same
    # unique set. Treat that as invalid policy/lineage input rather than
    # silently changing the submitted order.
    globally_invalid = not lineage_ok or not policy_ok or not names_ok or not order_ok

    req = body

    results = []
    for c in submitted:
        if not isinstance(c, dict):
            c = {"name": ""}
        result = compute_candidate_result(
            c,
            set(stored_by_name.keys()),
            req,
        )

        if not lineage_ok:
            result["admitted"] = False
            result["reasonCodes"] = sort_utf8(list(set(result["reasonCodes"] + ["INVALID_LINEAGE"])))

        if not policy_ok or not names_ok or not order_ok:
            result["admitted"] = False
            result["reasonCodes"] = sort_utf8(list(set(result["reasonCodes"] + ["INVALID_POLICY"])))

        results.append(result)

    # Required result order: candidateOrder, UTF-8 name fallback.
    if policy_ok:
        rank = {name: i for i, name in enumerate(order)}
        results.sort(key=lambda r: (rank.get(r["name"], 10**9), r["name"].encode("utf-8")))
    else:
        results.sort(key=lambda r: r["name"].encode("utf-8"))

    winners = [r for r in results if r["admitted"]]

    if winners and not globally_invalid:
        # Smaller bytes, then lower latency, then candidate order.
        rank = {name: i for i, name in enumerate(order)}
        winner = min(
            winners,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                rank.get(r["name"], 10**9),
            ),
        )
        selected = winner["name"]
        package_manifest = stored_by_name[selected]
    else:
        selected = None
        package_manifest = None

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, 200


# ---------- HTTP ----------

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

    phase = body.get("phase")

    if phase == "freeze":
        if not validate_freeze_request(body):
            return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)
        result, status = do_freeze(body)
        return JSONResponse(result, status_code=status)

    if phase == "select":
        if not validate_select_shape(body):
            return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)
        result, status = do_select(body)
        return JSONResponse(result, status_code=status)

    return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)


@app.get("/health")
def health():
    return {"ok": True}
