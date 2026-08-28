const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 10000;

const freezes = new Map();

const FREEZE_CODES = new Set([
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH",
]);

const SELECT_BASE_CODES = new Set([
  "NOT_FROZEN",
  "INVALID_LINEAGE",
  "INVALID_POLICY",
  "INVALID_PREDICTIONS",
  "INVALID_MANIFEST",
  "AGGREGATE_FLOOR",
  "SIZE_LIMIT",
  "LATENCY_LIMIT",
]);

function isObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function isString(x) {
  return typeof x === "string";
}

function nonEmptyString(x) {
  return typeof x === "string" && x.length > 0;
}

function safeInteger(x) {
  return Number.isSafeInteger(x);
}

function finiteNumber(x) {
  return typeof x === "number" && Number.isFinite(x);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function utf8Bytes(s) {
  return Buffer.byteLength(s, "utf8");
}

function canonicalJson(x) {
  return JSON.stringify(x);
}

function sortUtf8(a, b) {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return Buffer.compare(aa, bb);
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(sortUtf8);
}

function errorResponse(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(body));
}

function okResponse(res, body) {
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
  });
  res.end(JSON.stringify(body));
}

/* -------------------------------------------------------
   FILE / MANIFEST VALIDATION
------------------------------------------------------- */

function buildInventory(files) {
  if (!isObject(files)) {
    return { valid: false, inventory: [], totalBytes: null, packageDigest: null };
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return { valid: false, inventory: [], totalBytes: null, packageDigest: null };
  }

  for (const name of names) {
    if (!nonEmptyString(name)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    if (!isString(files[name])) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }
  }

  names.sort(sortUtf8);

  const inventory = [];

  for (const name of names) {
    const text = files[name];
    const bytes = utf8Bytes(text);
    const digest = sha256(Buffer.from(text, "utf8"));

    inventory.push({
      name: name,
      bytes: bytes,
      sha256: digest,
    });
  }

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }
  }

  /*
    IMPORTANT:
    Exact key order:
    name, bytes, sha256
  */
  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest,
  };
}

/*
  Recompute a submitted frozen candidate manifest.
  We DO NOT trust totalBytes/packageDigest supplied by select.
*/
function recomputeManifest(candidate) {
  if (!isObject(candidate)) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null,
    };
  }

  if (!nonEmptyString(candidate.name)) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null,
    };
  }

  if (!Array.isArray(candidate.inventory) || candidate.inventory.length === 0) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null,
    };
  }

  const names = new Set();
  const inventory = [];

  for (const item of candidate.inventory) {
    if (!isObject(item)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    if (!nonEmptyString(item.name)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    if (names.has(item.name)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    names.add(item.name);

    if (!safeInteger(item.bytes) || item.bytes < 0) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    if (
      !isString(item.sha256) ||
      !/^[0-9a-f]{64}$/.test(item.sha256)
    ) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }

    inventory.push({
      name: item.name,
      bytes: item.bytes,
      sha256: item.sha256,
    });
  }

  inventory.sort((a, b) => sortUtf8(a.name, b.name));

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null,
      };
    }
  }

  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest,
  };
}

/* -------------------------------------------------------
   DEEP EQUALITY
------------------------------------------------------- */

function deepEqual(a, b) {
  return canonicalJson(a) === canonicalJson(b);
}

/* -------------------------------------------------------
   FREEZE
------------------------------------------------------- */

function validateFreezeInput(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "freeze") return false;

  if (
    !nonEmptyString(body.freezeId) ||
    utf8Bytes(body.freezeId) > 128
  ) {
    return false;
  }

  if (!nonEmptyString(body.calibrationDigest)) return false;
  if (!nonEmptyString(body.tokenizerDigest)) return false;

  if (!Array.isArray(body.allowedUnsupportedReasons)) return false;

  const reasons = new Set();

  for (const reason of body.allowedUnsupportedReasons) {
    if (!nonEmptyString(reason)) return false;
    if (reasons.has(reason)) return false;
    reasons.add(reason);
  }

  if (!Array.isArray(body.candidates)) return false;

  /*
    The task explicitly requires a non-empty freeze candidate list.
  */
  if (body.candidates.length === 0) return false;

  const names = new Set();

  for (const c of body.candidates) {
    if (!isObject(c)) return false;

    if (!nonEmptyString(c.name)) return false;
    if (names.has(c.name)) return false;
    names.add(c.name);

    if (!isObject(c.files)) return false;
    if (Object.keys(c.files).length === 0) return false;

    for (const filename of Object.keys(c.files)) {
      if (!nonEmptyString(filename)) return false;
      if (!isString(c.files[filename])) return false;
    }

    if (typeof c.loadable !== "boolean") return false;

    if (!nonEmptyString(c.calibrationDigest)) return false;
    if (!nonEmptyString(c.tokenizerDigest)) return false;

    if (
      Object.prototype.hasOwnProperty.call(c, "unsupportedReason")
    ) {
      if (!nonEmptyString(c.unsupportedReason)) return false;
    }
  }

  return true;
}

function makeFreezeResponse(body) {
  const allowed = new Set(body.allowedUnsupportedReasons);

  const output = [];

  for (const c of body.candidates) {
    const manifest = buildInventory(c.files);

    const reasonCodes = [];

    const hasReason =
      Object.prototype.hasOwnProperty.call(c, "unsupportedReason");

    const reason = hasReason ? c.unsupportedReason : null;

    /*
      Unsupported reason is allowed:
      candidate is explicitly unsupported.
    */
    if (hasReason && allowed.has(reason)) {
      output.push({
        name: c.name,
        status: "unsupported",
        inventory: manifest.valid ? manifest.inventory : [],
        totalBytes: manifest.valid ? manifest.totalBytes : null,
        packageDigest: manifest.valid ? manifest.packageDigest : null,
        reasonCodes: [],
      });

      continue;
    }

    /*
      Unsupported reason exists but isn't allowed.
    */
    if (hasReason && !allowed.has(reason)) {
      reasonCodes.push("UNALLOWED_UNSUPPORTED_REASON");
    }

    /*
      If there is an unallowed reason, it is invalid.
      We still construct its manifest when possible.
    */
    if (!c.loadable) {
      reasonCodes.push("NOT_LOADABLE");
    }

    if (c.calibrationDigest !== body.calibrationDigest) {
      reasonCodes.push("CALIBRATION_MISMATCH");
    }

    if (c.tokenizerDigest !== body.tokenizerDigest) {
      reasonCodes.push("TOKENIZER_MISMATCH");
    }

    /*
      Invalid files => empty inventory and null values.
    */
    if (!manifest.valid) {
      reasonCodes.push("INVALID_INPUT");
    }

    reasonCodes = sortCodes(reasonCodes);

    let status = "frozen";

    if (reasonCodes.length > 0) {
      status = "invalid";
    }

    output.push({
      name: c.name,
      status,
      inventory: manifest.valid ? manifest.inventory : [],
      totalBytes: manifest.valid ? manifest.totalBytes : null,
      packageDigest: manifest.valid ? manifest.packageDigest : null,
      reasonCodes,
    });
  }

  output.sort((a, b) => sortUtf8(a.name, b.name));

  return {
    freezeId: body.freezeId,
    candidates: output,
  };
}

/* -------------------------------------------------------
   POLICY VALIDATION
------------------------------------------------------- */

function validatePolicy(policy, names) {
  if (!isObject(policy)) return false;

  if (!safeInteger(policy.maxBytes) || policy.maxBytes < 0) {
    return false;
  }

  if (
    !finiteNumber(policy.aggregateFloor) ||
    policy.aggregateFloor < 0 ||
    policy.aggregateFloor > 1
  ) {
    return false;
  }

  if (!isObject(policy.requiredSlices)) return false;

  const sliceNames = Object.keys(policy.requiredSlices);

  for (const slice of sliceNames) {
    if (!nonEmptyString(slice)) return false;

    const floor = policy.requiredSlices[slice];

    if (
      !finiteNumber(floor) ||
      floor < 0 ||
      floor > 1
    ) {
      return false;
    }
  }

  if (
    !finiteNumber(policy.maxLatencyMs) ||
    policy.maxLatencyMs < 0
  ) {
    return false;
  }

  if (!Array.isArray(policy.candidateOrder)) return false;

  const orderSet = new Set();

  for (const name of policy.candidateOrder) {
    if (!nonEmptyString(name)) return false;
    if (orderSet.has(name)) return false;
    orderSet.add(name);
  }

  if (orderSet.size !== names.size) return false;

  for (const name of names) {
    if (!orderSet.has(name)) return false;
  }

  return true;
}

/* -------------------------------------------------------
   PREDICTION VALIDATION
------------------------------------------------------- */

function validBinaryPrediction(x) {
  /*
    Binary prediction means exactly numeric 0 or 1.
    Do not accept strings "0"/"1".
  */
  return x === 0 || x === 1;
}

function evaluatePredictions(candidateName, rows, requiredSlices) {
  let valid = true;
  let correct = 0;

  const sliceStats = {};

  for (const slice of Object.keys(requiredSlices)) {
    sliceStats[slice] = {
      total: 0,
      correct: 0,
    };
  }

  for (const row of rows) {
    if (!isObject(row)) {
      valid = false;
      continue;
    }

    if (!Object.prototype.hasOwnProperty.call(row, "label")) {
      valid = false;
      continue;
    }

    if (!isString(row.slice) || row.slice.length === 0) {
      valid = false;
      continue;
    }

    if (!isObject(row.predictions)) {
      valid = false;
      continue;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        row.predictions,
        candidateName
      )
    ) {
      valid = false;
      continue;
    }

    const prediction = row.predictions[candidateName];

    if (!validBinaryPrediction(prediction)) {
      valid = false;
      continue;
    }

    if (prediction === row.label) {
      correct++;
    }

    if (Object.prototype.hasOwnProperty.call(sliceStats, row.slice)) {
      sliceStats[row.slice].total++;

      if (prediction === row.label) {
        sliceStats[row.slice].correct++;
      }
    }
  }

  if (!valid) {
    const slices = {};

    for (const name of Object.keys(requiredSlices)) {
      slices[name] = null;
    }

    return {
      valid: false,
      aggregate: null,
      slices,
    };
  }

  const aggregate =
    rows.length === 0
      ? null
      : Number((correct / rows.length).toFixed(12));

  const slices = {};

  for (const slice of Object.keys(requiredSlices)) {
    const s = sliceStats[slice];

    if (s.total === 0) {
      slices[slice] = null;
    } else {
      slices[slice] = Number(
        (s.correct / s.total).toFixed(12)
      );
    }
  }

  return {
    valid: true,
    aggregate,
    slices,
  };
}

/* -------------------------------------------------------
   SELECT
------------------------------------------------------- */

function processSelect(body) {
  const freeze = freezes.get(body.freezeId);

  if (!freeze) {
    return {
      freezeId: body.freezeId,
      selected: null,
      results: [],
      packageManifest: null,
      specialError: "NOT_FROZEN",
    };
  }

  /*
    Candidate array MUST exactly equal frozen response candidates.
  */
  if (
    !Array.isArray(body.candidates) ||
    !deepEqual(body.candidates, freeze.candidates)
  ) {
    return {
      freezeId: body.freezeId,
      selected: null,
      results: [],
      packageManifest: null,
      specialError: "INVALID_LINEAGE",
    };
  }

  const names = new Set();

  for (const c of freeze.candidates) {
    names.add(c.name);
  }

  if (!validatePolicy(body.policy, names)) {
    return {
      freezeId: body.freezeId,
      selected: null,
      results: [],
      packageManifest: null,
      specialError: "INVALID_POLICY",
    };
  }

  if (!isObject(body.latencies)) {
    return {
      freezeId: body.freezeId,
      selected: null,
      results: [],
      packageManifest: null,
      specialError: "INVALID_POLICY",
    };
  }

  if (!Array.isArray(body.rows)) {
    return {
      freezeId: body.freezeId,
      selected: null,
      results: [],
      packageManifest: null,
      specialError: "INVALID_POLICY",
    };
  }

  const requiredSlices = body.policy.requiredSlices;

  const order = body.policy.candidateOrder;

  const orderIndex = new Map();

  order.forEach((name, i) => {
    orderIndex.set(name, i);
  });

  const results = [];

  for (const frozenCandidate of freeze.candidates) {
    const name = frozenCandidate.name;

    const codes = [];

    /*
      Recompute manifest.
      We intentionally don't use submitted totalBytes.
    */
    const manifest = recomputeManifest(frozenCandidate);

    let totalBytes = null;

    if (manifest.valid) {
      totalBytes = manifest.totalBytes;
    } else {
      codes.push("INVALID_MANIFEST");
    }

    /*
      Check that recorded manifest itself is internally valid.
      This catches tampering even if inventory is otherwise shaped correctly.
    */
    if (manifest.valid) {
      if (
        frozenCandidate.totalBytes !== manifest.totalBytes ||
        frozenCandidate.packageDigest !== manifest.packageDigest
      ) {
        codes.push("INVALID_MANIFEST");
      }

      /*
        Verify inventory object itself is in canonical order.
      */
      const canonicalInventory =
        [...manifest.inventory].sort((a, b) =>
          sortUtf8(a.name, b.name)
        );

      if (
        !deepEqual(
          frozenCandidate.inventory,
          canonicalInventory
        )
      ) {
        codes.push("INVALID_MANIFEST");
      }
    }

    /*
      Latency.
    */
    let latencyMs = null;

    if (
      Object.prototype.hasOwnProperty.call(body.latencies, name) &&
      finiteNumber(body.latencies[name]) &&
      body.latencies[name] >= 0
    ) {
      latencyMs = body.latencies[name];
    }

    /*
      Prediction evaluation.
    */
    const evaluation = evaluatePredictions(
      name,
      body.rows,
      requiredSlices
    );

    let aggregate = evaluation.aggregate;
    let slices = evaluation.slices;

    if (!evaluation.valid) {
      codes.push("INVALID_PREDICTIONS");
    }

    /*
      Only evaluate floors when predictions are valid.
    */
    if (evaluation.valid) {
      if (
        aggregate === null ||
        aggregate < body.policy.aggregateFloor
      ) {
        codes.push("AGGREGATE_FLOOR");
      }

      for (const slice of Object.keys(requiredSlices)) {
        if (!Object.prototype.hasOwnProperty.call(slices, slice)) {
          codes.push(`MISSING_SLICE:${slice}`);
          continue;
        }

        if (slices[slice] === null) {
          codes.push(`MISSING_SLICE:${slice}`);
          continue;
        }

        if (slices[slice] < requiredSlices[slice]) {
          codes.push(`SLICE_FLOOR:${slice}`);
        }
      }
    }

    /*
      Only frozen candidates can be admitted.
    */
    if (frozenCandidate.status !== "frozen") {
      /*
        Its freeze reason codes already explain why it isn't frozen.
        Convert lineage problems into INVALID_LINEAGE.
      */
      codes.push("INVALID_LINEAGE");
    }

    if (
      totalBytes === null ||
      !safeInteger(totalBytes) ||
      totalBytes < 0
    ) {
      codes.push("INVALID_MANIFEST");
      totalBytes = null;
    } else if (totalBytes > body.policy.maxBytes) {
      codes.push("SIZE_LIMIT");
    }

    if (latencyMs === null) {
      codes.push("LATENCY_LIMIT");
    } else if (latencyMs > body.policy.maxLatencyMs) {
      codes.push("LATENCY_LIMIT");
    }

    const finalCodes = sortCodes(codes);

    const admitted = finalCodes.length === 0;

    results.push({
      name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: finalCodes,
    });
  }

  /*
    Results are ordered by candidateOrder.
    UTF-8 name is fallback.
  */
  results.sort((a, b) => {
    const ai = orderIndex.has(a.name)
      ? orderIndex.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = orderIndex.has(b.name)
      ? orderIndex.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) return ai - bi;

    return sortUtf8(a.name, b.name);
  });

  /*
    Winner:
      1. smaller bytes
      2. lower latency
      3. candidate order
  */
  const admitted = results.filter((r) => r.admitted);

  let winner = null;

  admitted.sort((a, b) => {
    if (a.totalBytes !== b.totalBytes) {
      return a.totalBytes - b.totalBytes;
    }

    if (a.latencyMs !== b.latencyMs) {
      return a.latencyMs - b.latencyMs;
    }

    return orderIndex.get(a.name) - orderIndex.get(b.name);
  });

  if (admitted.length > 0) {
    winner = admitted[0];
  }

  let packageManifest = null;
  let selected = null;

  if (winner) {
    selected = winner.name;

    const recorded = freeze.candidates.find(
      (c) => c.name === winner.name
    );

    packageManifest = recorded;
  }

  return {
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest,
  };
}

/* -------------------------------------------------------
   GLOBAL REQUEST VALIDATION
------------------------------------------------------- */

function validateSelectInput(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "select") return false;

  if (!nonEmptyString(body.freezeId)) return false;

  if (!Array.isArray(body.candidates)) return false;

  if (!Array.isArray(body.rows)) return false;

  if (!isObject(body.policy)) return false;

  return true;
}

/* -------------------------------------------------------
   HTTP SERVER
------------------------------------------------------- */

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/") {
    okResponse(res, {
      service: "quantize-admission-api",
      status: "ok",
      endpoint: "POST /quantize",
    });
    return;
  }

  if (req.method === "GET" && req.url === "/health") {
    okResponse(res, {
      status: "ok",
    });
    return;
  }

  if (req.method !== "POST" || req.url !== "/quantize") {
    errorResponse(res, 404, {
      error: "NOT_FOUND",
    });
    return;
  }

  let raw = "";

  req.on("data", (chunk) => {
    raw += chunk.toString("utf8");

    /*
      Basic protection against absurd requests.
    */
    if (Buffer.byteLength(raw, "utf8") > 20 * 1024 * 1024) {
      req.destroy();
    }
  });

  req.on("end", () => {
    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      errorResponse(res, 400, {
        error: "INVALID_INPUT",
      });
      return;
    }

    /*
      Unknown/missing phase => exact 400.
    */
    if (!isObject(body) || !nonEmptyString(body.phase)) {
      errorResponse(res, 400, {
        error: "INVALID_INPUT",
      });
      return;
    }

    /* ---------------- FREEZE ---------------- */

    if (body.phase === "freeze") {
      if (!validateFreezeInput(body)) {
        errorResponse(res, 400, {
          error: "INVALID_INPUT",
        });
        return;
      }

      const existing = freezes.get(body.freezeId);

      /*
        Important:
        Invalid freeze requests never reach this point,
        so they never reserve an ID.
      */

      if (existing) {
        if (deepEqual(existing.input, body)) {
          okResponse(res, existing.response);
          return;
        }

        errorResponse(res, 409, {
          error: "FREEZE_ID_CONFLICT",
        });
        return;
      }

      const response = makeFreezeResponse(body);

      freezes.set(body.freezeId, {
        input: body,
        response: response,
        candidates: response.candidates,
      });

      okResponse(res, response);
      return;
    }

    /* ---------------- SELECT ---------------- */

    if (body.phase === "select") {
      if (!validateSelectInput(body)) {
        errorResponse(res, 400, {
          error: "INVALID_INPUT",
        });
        return;
      }

      /*
        If freezeId doesn't exist, this is a valid select-shaped
        request but cannot select anything.
      */
      if (!freezes.has(body.freezeId)) {
        const result = processSelect(body);

        okResponse(res, {
          freezeId: body.freezeId,
          selected: null,
          results: [],
          packageManifest: null,
        });

        return;
      }

      const result = processSelect(body);

      /*
        Internal special errors become selection result codes.
      */
      if (result.specialError) {
        okResponse(res, {
          freezeId: body.freezeId,
          selected: null,
          results: [],
          packageManifest: null,
        });
        return;
      }

      okResponse(res, result);
      return;
    }

    /*
      Unknown phase.
    */
    errorResponse(res, 400, {
      error: "INVALID_INPUT",
    });
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Quantize service listening on ${PORT}`);
});
