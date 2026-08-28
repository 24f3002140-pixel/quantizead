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


def utf8(value):
    return value.encode("utf-8")


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=utf8)


def finite(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def safe_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_MAX
    )


def binary(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and value in (0, 1)
    )


def make_inventory(files):
    if not isinstance(files, dict) or not files:
        return [], None, None, False

    inventory = []
    seen = set()

    for filename, content in files.items():
        if not isinstance(filename, str) or not filename:
            return [], None, None, False

        key = utf8(filename)
        if key in seen:
            return [], None, None, False
        seen.add(key)

        if not isinstance(content, str):
            return [], None, None, False

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    inventory.sort(key=lambda x: utf8(x["name"]))

    total = sum(x["bytes"] for x in inventory)

    if total > SAFE_MAX:
        return [], None, None, False

    digest = sha256(compact_json(inventory))

    return inventory, total, digest, True


def valid_freeze(body):
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

    calibration = body.get("calibrationDigest")
    tokenizer = body.get("tokenizerDigest")

    if not isinstance(calibration, str) or not calibration:
        return False

    if not isinstance(tokenizer, str) or not tokenizer:
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    allowed_seen = set()

    for reason in allowed:
        if not isinstance(reason, str) or not reason:
            return False

        key = utf8(reason)

        if key in allowed_seen:
            return False

        allowed_seen.add(key)

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or not candidates:
        return False

    names = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not isinstance(name, str) or not name:
            return False

        key = utf8(name)

        if key in names:
            return False

        names.add(key)

    return True


def process_freeze(body):
    freeze_id = body["freezeId"]

    with LOCK:
        if freeze_id in FREEZES:
            old = FREEZES[freeze_id]

            if old["input"] == body:
                return old["output"], 200

            return {"error": "FREEZE_ID_CONFLICT"}, 409

        calibration = body["calibrationDigest"]
        tokenizer = body["tokenizerDigest"]
        allowed = set(body["allowedUnsupportedReasons"])

        candidates = sorted(
            body["candidates"],
            key=lambda x: utf8(x["name"]),
        )

        output_candidates = []

        for candidate in candidates:
            inventory, total, package_digest, files_ok = make_inventory(
                candidate.get("files")
            )

            codes = []

            if not files_ok:
                inventory = []
                total = None
                package_digest = None
                codes.append("INVALID_INPUT")

            unsupported_reason = candidate.get("unsupportedReason")

            has_reason = (
                isinstance(unsupported_reason, str)
                and bool(unsupported_reason)
            )

            if has_reason:
                if unsupported_reason in allowed and files_ok:
                    status = "unsupported"
                elif unsupported_reason in allowed:
                    status = "invalid"
                else:
                    status = "invalid"
                    codes.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                status = "frozen"

                if candidate.get("loadable") is not True:
                    codes.append("NOT_LOADABLE")

                if candidate.get("calibrationDigest") != calibration:
                    codes.append("CALIBRATION_MISMATCH")

                if candidate.get("tokenizerDigest") != tokenizer:
                    codes.append("TOKENIZER_MISMATCH")

            if codes:
                status = "invalid"

            output_candidates.append({
                "name": candidate["name"],
                "status": status,
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package_digest,
                "reasonCodes": sort_codes(codes),
            })

        output = {
            "freezeId": freeze_id,
            "candidates": output_candidates,
        }

        FREEZES[freeze_id] = {
            "input": json.loads(
                json.dumps(body, ensure_ascii=False)
            ),
            "output": json.loads(
                json.dumps(output, ensure_ascii=False)
            ),
        }

        return output, 200


def validate_manifest(candidate):
    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None

    names = set()
    canonical = []

    for item in inventory:
        if not isinstance(item, dict):
            return False, None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False, None

        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")

        if not isinstance(name, str) or not name:
            return False, None

        key = utf8(name)

        if key in names:
            return False, None

        names.add(key)

        if not safe_integer(size):
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
            "bytes": size,
            "sha256": digest,
        })

    if canonical != sorted(
        canonical,
        key=lambda x: utf8(x["name"])
    ):
        return False, None

    total = sum(x["bytes"] for x in canonical)

    if total > SAFE_MAX:
        return False, None

    digest = sha256(compact_json(canonical))

    if candidate.get("totalBytes") != total:
        return False, None

    if candidate.get("packageDigest") != digest:
        return False, None

    return True, total


def validate_policy(policy):
    if not isinstance(policy, dict):
        return False

    if not safe_integer(policy.get("maxBytes")):
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

    for name, floor in required.items():
        if not isinstance(name, str) or not name:
            return False

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

        key = utf8(name)

        if key in seen:
            return False

        seen.add(key)

    return True


def evaluate_candidate(candidate, rows, policy, latencies):
    name = candidate.get("name", "")
    codes = []

    if candidate.get("status") != "frozen":
        codes.append("NOT_FROZEN")

    manifest_ok, total_bytes = validate_manifest(candidate)

    if not manifest_ok:
        codes.append("INVALID_MANIFEST")
        total_out = None
    else:
        total_out = total_bytes

    predictions_valid = True
    correct = 0
    slice_total = {}
    slice_correct = {}

    for row in rows:
        if not isinstance(row, dict):
            predictions_valid = False
            continue

        label = row.get("label")

        if "label" not in row or not binary(label):
            predictions_valid = False
            continue

        slice_name = row.get("slice")

        if not isinstance(slice_name, str):
            predictions_valid = False
            continue

        predictions = row.get("predictions")

        if (
            not isinstance(predictions, dict)
            or name not in predictions
        ):
            predictions_valid = False
            continue

        prediction = predictions[name]

        if not binary(prediction):
            predictions_valid = False
            continue

        slice_total[slice_name] = (
            slice_total.get(slice_name, 0) + 1
        )

        if int(prediction) == int(label):
            correct += 1
            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )

    aggregate = None

    slices = {
        name: None
        for name in policy["requiredSlices"]
    }

    if not predictions_valid:
        codes.append("INVALID_PREDICTIONS")

    elif not rows:
        codes.append("INVALID_PREDICTIONS")
        codes.append("AGGREGATE_FLOOR")

        for slice_name in policy["requiredSlices"]:
            codes.append("MISSING_SLICE:" + slice_name)

    else:
        aggregate = round(
            correct / len(rows),
            12
        )

        if aggregate < float(
            policy["aggregateFloor"]
        ):
            codes.append("AGGREGATE_FLOOR")

        for slice_name, floor in policy[
            "requiredSlices"
        ].items():

            count = slice_total.get(slice_name, 0)

            if count == 0:
                codes.append(
                    "MISSING_SLICE:" + slice_name
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
                        "SLICE_FLOOR:" + slice_name
                    )

    if (
        manifest_ok
        and total_bytes > policy["maxBytes"]
    ):
        codes.append("SIZE_LIMIT")

    latency = None

    if isinstance(latencies, dict):
        value = latencies.get(name)

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

            if float(latency) > float(
                policy["maxLatencyMs"]
            ):
                codes.append("LATENCY_LIMIT")

    reason_codes = sort_codes(codes)

    admitted = (
        len(reason_codes) == 0
        and candidate.get("status") == "frozen"
        and manifest_ok
        and predictions_valid
        and aggregate is not None
        and total_out is not None
        and latency is not None
    )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_out,
        "latencyMs": latency,
        "admitted": admitted,
        "reasonCodes": reason_codes,
    }


def process_select(body):
    freeze_id = body["freezeId"]

    with LOCK:
        stored = FREEZES.get(freeze_id)

    if stored is None:
        results = []

        for candidate in body["candidates"]:
            name = (
                candidate.get("name", "")
                if isinstance(candidate, dict)
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
            key=lambda x: utf8(x["name"])
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    frozen_candidates = stored[
        "output"
    ]["candidates"]

    lineage_ok = (
        body["candidates"]
        == frozen_candidates
    )

    policy = body["policy"]
    policy_ok = validate_policy(policy)

    submitted_names = []
    malformed = False

    for candidate in body["candidates"]:
        if not isinstance(candidate, dict):
            malformed = True
            continue

        name = candidate.get("name")

        if not isinstance(name, str):
            malformed = True
            continue

        submitted_names.append(name)

    if policy_ok:
        submitted_set = {
            utf8(x)
            for x in submitted_names
        }

        order_set = {
            utf8(x)
            for x in policy["candidateOrder"]
        }

        order_ok = (
            not malformed
            and len(submitted_names)
            == len(body["candidates"])
            and len(submitted_set)
            == len(submitted_names)
            and len(policy["candidateOrder"])
            == len(submitted_names)
            and submitted_set == order_set
        )
    else:
        order_ok = False

    results = []

    for candidate in body["candidates"]:
        if not isinstance(candidate, dict):
            results.append({
                "name": "",
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_codes([
                    "INVALID_LINEAGE",
                    "INVALID_POLICY",
                ]),
            })
            continue

        if policy_ok:
            result = evaluate_candidate(
                candidate,
                body["rows"],
                policy,
                body.get("latencies"),
            )
        else:
            result = {
                "name": candidate.get("name", ""),
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [],
            }

        if not lineage_ok:
            result["reasonCodes"].append(
                "INVALID_LINEAGE"
            )

        if not policy_ok or not order_ok:
            result["reasonCodes"].append(
                "INVALID_POLICY"
            )

        result["reasonCodes"] = sort_codes(
            result["reasonCodes"]
        )

        result["admitted"] = (
            len(result["reasonCodes"]) == 0
        )

        results.append(result)

    if policy_ok:
        rank = {
            name: index
            for index, name in enumerate(
                policy["candidateOrder"]
            )
        }

        results.sort(
            key=lambda x: (
                rank.get(
                    x["name"],
                    999999999
                ),
                utf8(x["name"]),
            )
        )
    else:
        results.sort(
            key=lambda x: utf8(x["name"])
        )

    eligible = [
        x for x in results
        if x["admitted"]
    ]

    selected = None
    package_manifest = None

    if (
        eligible
        and lineage_ok
        and policy_ok
        and order_ok
    ):
        rank = {
            name: index
            for index, name in enumerate(
                policy["candidateOrder"]
            )
        }

        winner = min(
            eligible,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                rank.get(
                    x["name"],
                    999999999
                ),
                utf8(x["name"]),
            )
        )

        selected = winner["name"]

        for candidate in frozen_candidates:
            if candidate["name"] == selected:
                package_manifest = candidate
                break

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


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

    if phase == "freeze":
        if not valid_freeze(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        response, status = process_freeze(body)

        return JSONResponse(
            response,
            status_code=status,
        )

    if phase == "select":
        if not isinstance(
            body.get("candidates"),
            list
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("rows"),
            list
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("policy"),
            dict
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not isinstance(
            body.get("freezeId"),
            str
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        return JSONResponse(
            process_select(body),
            status_code=200,
        )

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


@app.get("/")
def root():
    return {
        "service": "quantize",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
    }
