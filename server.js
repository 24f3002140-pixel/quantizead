const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "50mb" }));

const freezes = new Map();

function isObj(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function nonEmptyString(x) {
  return typeof x === "string" && x.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function invalid(res) {
  return res.status(400).json({ error: "INVALID_INPUT" });
}

function sortedUniqueCodes(list) {
  return [...new Set(list)].sort(utf8Compare);
}

function finiteNonNegative(x) {
  return (
    typeof x === "number" &&
    Number.isFinite(x) &&
    x >= 0
  );
}

function safeNonNegativeInteger(x) {
  return (
    typeof x === "number" &&
    Number.isSafeInteger(x) &&
    x >= 0
  );
}

function validFloor(x) {
  return (
    typeof x === "number" &&
    Number.isFinite(x) &&
    x >= 0 &&
    x <= 1
  );
}

function binaryPrediction(x) {
  return typeof x === "number" && (x === 0 || x === 1);
}

/*
 * Deep equality.
 * Object key order does not matter.
 * Array order DOES matter.
 */
function deepEqual(a, b) {
  if (a === b) return true;

  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;

  if (Array.isArray(a)) {
    if (!Array.isArray(b)) return false;
    if (a.length !== b.length) return false;

    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }

    return true;
  }

  if (typeof a === "object") {
    if (Array.isArray(b)) return false;

    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();

    if (ak.length !== bk.length) return false;

    for (let i = 0; i < ak.length; i++) {
      if (ak[i] !== bk[i]) return false;

      if (!deepEqual(a[ak[i]], b[bk[i]])) {
        return false;
      }
    }

    return true;
  }

  return false;
}

/*
 * Build the artifact inventory.
 */
function buildInventory(files) {
  if (!isObj(files)) return null;

  const names = Object.keys(files);

  if (names.length === 0) return null;

  for (const name of names) {
    if (!nonEmptyString(name)) return null;

    if (typeof files[name] !== "string") {
      return null;
    }
  }

  names.sort(utf8Compare);

  const inventory = [];
  let totalBytes = 0;

  for (const name of names) {
    const bytes = Buffer.from(files[name], "utf8");

    inventory.push({
      name: name,
      bytes: bytes.length,
      sha256: sha256(bytes)
    });

    totalBytes += bytes.length;
  }

  /*
   * IMPORTANT:
   * JSON.stringify preserves:
   * name, bytes, sha256
   * in exactly that order.
   */
  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

/*
 * Validate the global freeze request.
 */
function validFreezeRequest(body) {
  if (!isObj(body)) return false;

  if (body.phase !== "freeze") return false;

  if (
    !nonEmptyString(body.freezeId) ||
    body.freezeId.length > 128
  ) {
    return false;
  }

  if (!nonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!nonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  const reasons = new Set();

  for (const reason of body.allowedUnsupportedReasons) {
    if (!nonEmptyString(reason)) return false;

    if (reasons.has(reason)) return false;

    reasons.add(reason);
  }

  /*
   * This is explicitly required by the question.
   */
  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  const names = new Set();

  for (const candidate of body.candidates) {
    if (!isObj(candidate)) return false;

    if (!nonEmptyString(candidate.name)) {
      return false;
    }

    if (names.has(candidate.name)) {
      return false;
    }

    names.add(candidate.name);
  }

  return true;
}

/*
 * Freeze one candidate.
 */
function freezeCandidate(candidate, request) {
  const inventory = buildInventory(candidate.files);

  /*
   * Invalid files invalidate the candidate only.
   */
  if (!inventory) {
    return {
      name: candidate.name,
      status: "invalid",
      inventory: [],
      totalBytes: null,
      packageDigest: null,
      reasonCodes: ["INVALID_INPUT"]
    };
  }

  /*
   * unsupportedReason has precedence.
   */
  if (
    Object.prototype.hasOwnProperty.call(
      candidate,
      "unsupportedReason"
    )
  ) {
    if (!nonEmptyString(candidate.unsupportedReason)) {
      return {
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      };
    }

    if (
      request.allowedUnsupportedReasons.includes(
        candidate.unsupportedReason
      )
    ) {
      return {
        name: candidate.name,
        status: "unsupported",
        inventory: inventory.inventory,
        totalBytes: inventory.totalBytes,
        packageDigest: inventory.packageDigest,
        reasonCodes: []
      };
    }

    return {
      name: candidate.name,
      status: "invalid",
      inventory: inventory.inventory,
      totalBytes: inventory.totalBytes,
      packageDigest: inventory.packageDigest,
      reasonCodes: [
        "UNALLOWED_UNSUPPORTED_REASON"
      ]
    };
  }

  const reasons = [];

  if (candidate.loadable !== true) {
    reasons.push("NOT_LOADABLE");
  }

  if (
    typeof candidate.calibrationDigest !== "string" ||
    candidate.calibrationDigest.length === 0 ||
    candidate.calibrationDigest !==
      request.calibrationDigest
  ) {
    reasons.push("CALIBRATION_MISMATCH");
  }

  if (
    typeof candidate.tokenizerDigest !== "string" ||
    candidate.tokenizerDigest.length === 0 ||
    candidate.tokenizerDigest !==
      request.tokenizerDigest
  ) {
    reasons.push("TOKENIZER_MISMATCH");
  }

  if (reasons.length > 0) {
    return {
      name: candidate.name,
      status: "invalid",
      inventory: inventory.inventory,
      totalBytes: inventory.totalBytes,
      packageDigest: inventory.packageDigest,
      reasonCodes: sortedUniqueCodes(reasons)
    };
  }

  return {
    name: candidate.name,
    status: "frozen",
    inventory: inventory.inventory,
    totalBytes: inventory.totalBytes,
    packageDigest: inventory.packageDigest,
    reasonCodes: []
  };
}

/*
 * FREEZE
 */
function freeze(body, res) {
  if (!validFreezeRequest(body)) {
    return invalid(res);
  }

  const old = freezes.get(body.freezeId);

  /*
   * Same freezeId + same request = exact replay.
   */
  if (old) {
    if (deepEqual(old.input, body)) {
      return res.status(200).json(old.response);
    }

    return res.status(409).json({
      error: "FREEZE_ID_CONFLICT"
    });
  }

  const candidates = body.candidates
    .map(candidate =>
      freezeCandidate(candidate, body)
    )
    .sort((a, b) =>
      utf8Compare(a.name, b.name)
    );

  const response = {
    freezeId: body.freezeId,
    candidates
  };

  freezes.set(body.freezeId, {
    input: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response))
  });

  return res.status(200).json(response);
}

/*
 * Validate SELECT top-level structure.
 */
function validSelectTop(body) {
  return (
    isObj(body) &&
    body.phase === "select" &&
    nonEmptyString(body.freezeId) &&
    Array.isArray(body.candidates) &&
    Array.isArray(body.rows) &&
    isObj(body.policy) &&
    isObj(body.latencies)
  );
}

/*
 * Validate policy.
 */
function validPolicy(policy, candidateNames) {
  if (!isObj(policy)) return false;

  if (!safeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!validFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isObj(policy.requiredSlices)) {
    return false;
  }

  const sliceNames = Object.keys(
    policy.requiredSlices
  );

  const seenSlices = new Set();

  for (const slice of sliceNames) {
    if (!nonEmptyString(slice)) {
      return false;
    }

    if (seenSlices.has(slice)) {
      return false;
    }

    seenSlices.add(slice);

    if (!validFloor(policy.requiredSlices[slice])) {
      return false;
    }
  }

  if (!finiteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (!Array.isArray(policy.candidateOrder)) {
    return false;
  }

  const order = new Set();

  for (const name of policy.candidateOrder) {
    if (!nonEmptyString(name)) {
      return false;
    }

    if (order.has(name)) {
      return false;
    }

    order.add(name);
  }

  /*
   * Exactly the same unique candidate set.
   */
  if (order.size !== candidateNames.size) {
    return false;
  }

  for (const name of candidateNames) {
    if (!order.has(name)) {
      return false;
    }
  }

  return true;
}

/*
 * Validate and recompute manifest.
 */
function validateManifest(candidate) {
  if (!isObj(candidate)) return null;

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const seen = new Set();

  for (const item of candidate.inventory) {
    if (!isObj(item)) return null;

    /*
     * Exact keys:
     * name, bytes, sha256
     */
    const keys = Object.keys(item);

    if (keys.length !== 3) {
      return null;
    }

    if (
      !nonEmptyString(item.name) ||
      !safeNonNegativeInteger(item.bytes) ||
      typeof item.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(item.sha256)
    ) {
      return null;
    }

    if (seen.has(item.name)) {
      return null;
    }

    seen.add(item.name);
  }

  /*
   * Inventory must already be UTF-8 sorted.
   */
  const sorted = [...candidate.inventory].sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  if (!deepEqual(sorted, candidate.inventory)) {
    return null;
  }

  const totalBytes =
    candidate.inventory.reduce(
      (sum, item) => sum + item.bytes,
      0
    );

  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(candidate.inventory),
      "utf8"
    )
  );

  if (
    candidate.packageDigest !== packageDigest
  ) {
    return null;
  }

  return {
    totalBytes,
    packageDigest
  };
}

/*
 * Evaluate predictions.
 */
function evaluateCandidate(
  name,
  rows,
  requiredSlices
) {
  if (rows.length === 0) {
    const slices = {};

    for (const slice of Object.keys(requiredSlices)) {
      slices[slice] = null;
    }

    return {
      valid: false,
      aggregate: null,
      slices
    };
  }

  for (const row of rows) {
    if (!isObj(row)) {
      return invalidEvaluation(requiredSlices);
    }

    if (!binaryPrediction(row.label)) {
      return invalidEvaluation(requiredSlices);
    }

    if (!nonEmptyString(row.slice)) {
      return invalidEvaluation(requiredSlices);
    }

    if (!isObj(row.predictions)) {
      return invalidEvaluation(requiredSlices);
    }

    if (
      !binaryPrediction(
        row.predictions[name]
      )
    ) {
      return invalidEvaluation(requiredSlices);
    }
  }

  let correct = 0;

  const totalBySlice = {};
  const correctBySlice = {};

  for (const row of rows) {
    const prediction =
      row.predictions[name];

    if (prediction === row.label) {
      correct++;
    }

    totalBySlice[row.slice] =
      (totalBySlice[row.slice] || 0) + 1;

    if (prediction === row.label) {
      correctBySlice[row.slice] =
        (correctBySlice[row.slice] || 0) + 1;
    }
  }

  const aggregate = Number(
    (correct / rows.length).toFixed(12)
  );

  const slices = {};

  for (const slice of Object.keys(
    requiredSlices
  )) {
    if (!(slice in totalBySlice)) {
      slices[slice] = null;
    } else {
      slices[slice] = Number(
        (
          correctBySlice[slice] /
          totalBySlice[slice]
        ).toFixed(12)
      );
    }
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

function invalidEvaluation(requiredSlices) {
  const slices = {};

  for (const slice of Object.keys(
    requiredSlices
  )) {
    slices[slice] = null;
  }

  return {
    valid: false,
    aggregate: null,
    slices
  };
}

/*
 * SELECT
 */
function select(body, res) {
  if (!validSelectTop(body)) {
    return invalid(res);
  }

  const submitted = body.candidates;
  const rows = body.rows;
  const policy = body.policy;

  const stored = freezes.get(body.freezeId);

  /*
   * Candidate names must be unique.
   */
  const names = new Set();
  let namesValid = true;

  for (const candidate of submitted) {
    if (
      !isObj(candidate) ||
      !nonEmptyString(candidate.name) ||
      names.has(candidate.name)
    ) {
      namesValid = false;
      continue;
    }

    names.add(candidate.name);
  }

  const policyValid =
    namesValid &&
    validPolicy(policy, names);

  /*
   * Exact frozen candidate array.
   */
  const exactLineage =
    !!stored &&
    deepEqual(
      stored.response.candidates,
      submitted
    );

  const storedByName = new Map();

  if (stored) {
    for (const candidate of
      stored.response.candidates) {
      storedByName.set(
        candidate.name,
        candidate
      );
    }
  }

  const results = [];

  for (const candidate of submitted) {
    const name =
      isObj(candidate) &&
      typeof candidate.name === "string"
        ? candidate.name
        : "";

    const reasonCodes = [];

    if (!stored) {
      reasonCodes.push("NOT_FROZEN");
    }

    if (!exactLineage) {
      reasonCodes.push("INVALID_LINEAGE");
    }

    if (!policyValid) {
      reasonCodes.push("INVALID_POLICY");
    }

    /*
     * Recompute manifest.
     */
    const manifest =
      validateManifest(candidate);

    let totalBytes = null;

    if (!manifest) {
      reasonCodes.push(
        "INVALID_MANIFEST"
      );
    } else {
      totalBytes =
        manifest.totalBytes;
    }

    /*
     * Predictions.
     */
    const evaluation =
      evaluateCandidate(
        name,
        rows,
        policyValid
          ? policy.requiredSlices
          : {}
      );

    if (!evaluation.valid) {
      reasonCodes.push(
        "INVALID_PREDICTIONS"
      );
    } else if (policyValid) {
      if (
        evaluation.aggregate <
        policy.aggregateFloor
      ) {
        reasonCodes.push(
          "AGGREGATE_FLOOR"
        );
      }

      for (const slice of Object.keys(
        policy.requiredSlices
      )) {
        if (
          evaluation.slices[slice] === null
        ) {
          reasonCodes.push(
            `MISSING_SLICE:${slice}`
          );
        } else if (
          evaluation.slices[slice] <
          policy.requiredSlices[slice]
        ) {
          reasonCodes.push(
            `SLICE_FLOOR:${slice}`
          );
        }
      }
    }

    /*
     * Latency.
     */
    let latencyMs = null;

    if (
      finiteNonNegative(
        body.latencies[name]
      )
    ) {
      latencyMs =
        body.latencies[name];
    } else {
      reasonCodes.push(
        "LATENCY_LIMIT"
      );
    }

    /*
     * Size.
     */
    if (
      policyValid &&
      totalBytes !== null &&
      totalBytes > policy.maxBytes
    ) {
      reasonCodes.push(
        "SIZE_LIMIT"
      );
    }

    /*
     * Latency limit.
     */
    if (
      policyValid &&
      latencyMs !== null &&
      latencyMs > policy.maxLatencyMs
    ) {
      reasonCodes.push(
        "LATENCY_LIMIT"
      );
    }

    /*
     * Candidate must actually be frozen.
     */
    const storedCandidate =
      storedByName.get(name);

    if (
      !storedCandidate ||
      storedCandidate.status !== "frozen"
    ) {
      reasonCodes.push(
        "NOT_FROZEN"
      );
    }

    const finalCodes =
      sortedUniqueCodes(reasonCodes);

    results.push({
      name,
      aggregate:
        evaluation.aggregate,
      slices:
        evaluation.slices,
      totalBytes,
      latencyMs,
      admitted:
        finalCodes.length === 0,
      reasonCodes: finalCodes
    });
  }

  /*
   * Results in candidateOrder.
   * UTF-8 name is fallback.
   */
  const order =
    policyValid
      ? policy.candidateOrder
      : [];

  const positions = new Map();

  order.forEach((name, index) => {
    positions.set(name, index);
  });

  results.sort((a, b) => {
    const ai = positions.has(a.name)
      ? positions.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = positions.has(b.name)
      ? positions.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(a.name, b.name);
  });

  /*
   * Winner:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidateOrder
   * 4. UTF-8 name
   */
  const admitted =
    results.filter(
      result => result.admitted
    );

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    admitted.sort((a, b) => {
      if (
        a.totalBytes !==
        b.totalBytes
      ) {
        return (
          a.totalBytes -
          b.totalBytes
        );
      }

      if (
        a.latencyMs !==
        b.latencyMs
      ) {
        return (
          a.latencyMs -
          b.latencyMs
        );
      }

      const ai = positions.has(a.name)
        ? positions.get(a.name)
        : Number.MAX_SAFE_INTEGER;

      const bi = positions.has(b.name)
        ? positions.get(b.name)
        : Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return utf8Compare(
        a.name,
        b.name
      );
    });

    selected = admitted[0].name;

    /*
     * EXACT recorded winner object.
     */
    packageManifest =
      storedByName.get(selected) ||
      null;
  }

  return res.status(200).json({
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest
  });
}

/*
 * POST /quantize
 */
app.post("/quantize", (req, res) => {
  if (!isObj(req.body)) {
    return invalid(res);
  }

  if (req.body.phase === "freeze") {
    return freeze(req.body, res);
  }

  if (req.body.phase === "select") {
    return select(req.body, res);
  }

  return invalid(res);
});

/*
 * Health endpoints.
 */
app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

const PORT =
  process.env.PORT || 10000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize service listening on ${PORT}`
    );
  }
);
