const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "50mb" }));

const freezes = new Map();

const ALLOWED_FREEZE_CODES = new Set([
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH"
]);

function isObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function nonEmptyString(x) {
  return typeof x === "string" && x.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

function sortedCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function safeInt(x) {
  return (
    typeof x === "number" &&
    Number.isSafeInteger(x)
  );
}

function safeNonNegativeInt(x) {
  return safeInt(x) && x >= 0;
}

function finiteNonNegative(x) {
  return (
    typeof x === "number" &&
    Number.isFinite(x) &&
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

function binary(x) {
  return (
    typeof x === "number" &&
    (x === 0 || x === 1)
  );
}

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
    if (!isObject(b)) return false;

    const ak = Object.keys(a).sort(utf8Compare);
    const bk = Object.keys(b).sort(utf8Compare);

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

/* =========================================================
   MANIFEST / ARTIFACT
   ========================================================= */

function makeInventory(files) {
  if (!isObject(files)) return null;

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
    const data = Buffer.from(files[name], "utf8");

    const item = {
      name: name,
      bytes: data.length,
      sha256: sha256(data)
    };

    inventory.push(item);
    totalBytes += data.length;

    if (!safeNonNegativeInt(totalBytes)) {
      return null;
    }
  }

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(inventory),
      "utf8"
    )
  );

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

/*
 * IMPORTANT:
 * Recompute the submitted manifest.
 *
 * We intentionally validate only the manifest representation
 * required by the specification:
 *   name
 *   bytes
 *   sha256
 */
function validateManifest(candidate) {
  if (!isObject(candidate)) {
    return null;
  }

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const seen = new Set();

  for (const item of candidate.inventory) {
    if (!isObject(item)) {
      return null;
    }

    if (!nonEmptyString(item.name)) {
      return null;
    }

    if (!safeNonNegativeInt(item.bytes)) {
      return null;
    }

    if (
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
   * Inventory must be sorted by UTF-8 filename.
   */
  for (
    let i = 1;
    i < candidate.inventory.length;
    i++
  ) {
    if (
      utf8Compare(
        candidate.inventory[i - 1].name,
        candidate.inventory[i].name
      ) > 0
    ) {
      return null;
    }
  }

  let totalBytes = 0;

  for (const item of candidate.inventory) {
    totalBytes += item.bytes;

    if (!safeNonNegativeInt(totalBytes)) {
      return null;
    }
  }

  /*
   * Submitted total must agree with recomputation.
   */
  if (
    !safeNonNegativeInt(candidate.totalBytes) ||
    candidate.totalBytes !== totalBytes
  ) {
    return null;
  }

  /*
   * Rebuild the exact compact JSON representation.
   * Object property order is explicitly:
   * name, bytes, sha256
   */
  const canonicalInventory =
    candidate.inventory.map(item => ({
      name: item.name,
      bytes: item.bytes,
      sha256: item.sha256
    }));

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(canonicalInventory),
      "utf8"
    )
  );

  if (
    typeof candidate.packageDigest !== "string" ||
    candidate.packageDigest !== packageDigest
  ) {
    return null;
  }

  return {
    totalBytes,
    packageDigest
  };
}

/* =========================================================
   FREEZE VALIDATION
   ========================================================= */

function validFreezeInput(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "freeze") {
    return false;
  }

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
    if (!nonEmptyString(reason)) {
      return false;
    }

    if (reasons.has(reason)) {
      return false;
    }

    reasons.add(reason);
  }

  /*
   * Explicit assignment requirement:
   * empty/non-array freeze candidates = INVALID_INPUT
   */
  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  const names = new Set();

  for (const candidate of body.candidates) {
    if (!isObject(candidate)) {
      return false;
    }

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

function freezeOne(candidate, request) {
  const artifact = makeInventory(candidate.files);

  /*
   * Invalid files:
   * empty inventory + null totals/digest.
   */
  if (!artifact) {
    return {
      name: candidate.name,
      status: "invalid",
      inventory: [],
      totalBytes: null,
      packageDigest: null,
      reasonCodes: ["INVALID_INPUT"]
    };
  }

  const reasons = [];

  /*
   * unsupportedReason is optional.
   */
  if (
    Object.prototype.hasOwnProperty.call(
      candidate,
      "unsupportedReason"
    )
  ) {
    if (
      typeof candidate.unsupportedReason !== "string" ||
      candidate.unsupportedReason.length === 0
    ) {
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
        inventory: artifact.inventory,
        totalBytes: artifact.totalBytes,
        packageDigest: artifact.packageDigest,
        reasonCodes: []
      };
    }

    return {
      name: candidate.name,
      status: "invalid",
      inventory: artifact.inventory,
      totalBytes: artifact.totalBytes,
      packageDigest: artifact.packageDigest,
      reasonCodes: [
        "UNALLOWED_UNSUPPORTED_REASON"
      ]
    };
  }

  /*
   * Normal frozen candidate.
   */
  if (candidate.loadable !== true) {
    reasons.push("NOT_LOADABLE");
  }

  if (
    !nonEmptyString(candidate.calibrationDigest) ||
    candidate.calibrationDigest !==
      request.calibrationDigest
  ) {
    reasons.push("CALIBRATION_MISMATCH");
  }

  if (
    !nonEmptyString(candidate.tokenizerDigest) ||
    candidate.tokenizerDigest !==
      request.tokenizerDigest
  ) {
    reasons.push("TOKENIZER_MISMATCH");
  }

  if (reasons.length > 0) {
    return {
      name: candidate.name,
      status: "invalid",
      inventory: artifact.inventory,
      totalBytes: artifact.totalBytes,
      packageDigest: artifact.packageDigest,
      reasonCodes: sortedCodes(reasons)
    };
  }

  return {
    name: candidate.name,
    status: "frozen",
    inventory: artifact.inventory,
    totalBytes: artifact.totalBytes,
    packageDigest: artifact.packageDigest,
    reasonCodes: []
  };
}

/* =========================================================
   FREEZE
   ========================================================= */

function doFreeze(body, res) {
  if (!validFreezeInput(body)) {
    return res.status(400).json({
      error: "INVALID_INPUT"
    });
  }

  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.input, body)) {
      return res.status(200).json(
        existing.response
      );
    }

    return res.status(409).json({
      error: "FREEZE_ID_CONFLICT"
    });
  }

  const candidates = body.candidates
    .map(candidate =>
      freezeOne(candidate, body)
    )
    .sort((a, b) =>
      utf8Compare(a.name, b.name)
    );

  const response = {
    freezeId: body.freezeId,
    candidates
  };

  /*
   * Only reserve the ID after complete validation.
   */
  freezes.set(
    body.freezeId,
    {
      input: JSON.parse(
        JSON.stringify(body)
      ),
      response: JSON.parse(
        JSON.stringify(response)
      )
    }
  );

  return res.status(200).json(response);
}

/* =========================================================
   SELECT VALIDATION
   ========================================================= */

function validSelectInput(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "select") {
    return false;
  }

  if (!nonEmptyString(body.freezeId)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  if (!Array.isArray(body.rows)) {
    return false;
  }

  if (!isObject(body.policy)) {
    return false;
  }

  if (!isObject(body.latencies)) {
    return false;
  }

  return true;
}

function validPolicy(policy, names) {
  if (!isObject(policy)) {
    return false;
  }

  if (!safeNonNegativeInt(policy.maxBytes)) {
    return false;
  }

  if (!validFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isObject(policy.requiredSlices)) {
    return false;
  }

  const sliceNames =
    Object.keys(policy.requiredSlices);

  const slices = new Set();

  for (const slice of sliceNames) {
    if (!nonEmptyString(slice)) {
      return false;
    }

    if (slices.has(slice)) {
      return false;
    }

    slices.add(slice);

    if (
      !validFloor(
        policy.requiredSlices[slice]
      )
    ) {
      return false;
    }
  }

  if (
    !finiteNonNegative(
      policy.maxLatencyMs
    )
  ) {
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

  if (order.size !== names.size) {
    return false;
  }

  for (const name of names) {
    if (!order.has(name)) {
      return false;
    }
  }

  return true;
}

/* =========================================================
   PREDICTIONS
   ========================================================= */

function invalidEvaluation(requiredSlices) {
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

function evaluate(name, rows, requiredSlices) {
  if (rows.length === 0) {
    return invalidEvaluation(
      requiredSlices
    );
  }

  for (const row of rows) {
    if (!isObject(row)) {
      return invalidEvaluation(
        requiredSlices
      );
    }

    if (!binary(row.label)) {
      return invalidEvaluation(
        requiredSlices
      );
    }

    if (!nonEmptyString(row.slice)) {
      return invalidEvaluation(
        requiredSlices
      );
    }

    if (!isObject(row.predictions)) {
      return invalidEvaluation(
        requiredSlices
      );
    }

    if (
      !binary(
        row.predictions[name]
      )
    ) {
      return invalidEvaluation(
        requiredSlices
      );
    }
  }

  let correct = 0;

  const total = {};
  const correctBySlice = {};

  for (const row of rows) {
    const prediction =
      row.predictions[name];

    total[row.slice] =
      (total[row.slice] || 0) + 1;

    if (prediction === row.label) {
      correct++;
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
    if (!(slice in total)) {
      slices[slice] = null;
    } else {
      slices[slice] = Number(
        (
          correctBySlice[slice] /
          total[slice]
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

/* =========================================================
   SELECT
   ========================================================= */

function doSelect(body, res) {
  if (!validSelectInput(body)) {
    return res.status(400).json({
      error: "INVALID_INPUT"
    });
  }

  const stored =
    freezes.get(body.freezeId);

  /*
   * Candidate names.
   */
  const names = new Set();
  let namesValid = true;

  for (const candidate of body.candidates) {
    if (
      !isObject(candidate) ||
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
    validPolicy(
      body.policy,
      names
    );

  /*
   * The supplied frozen candidate array
   * must exactly equal the stored response.
   */
  const lineageValid =
    !!stored &&
    deepEqual(
      stored.response.candidates,
      body.candidates
    );

  const storedCandidates =
    new Map();

  if (stored) {
    for (
      const candidate of
      stored.response.candidates
    ) {
      storedCandidates.set(
        candidate.name,
        candidate
      );
    }
  }

  const results = [];

  for (const submitted of body.candidates) {
    const name =
      isObject(submitted) &&
      typeof submitted.name === "string"
        ? submitted.name
        : "";

    const codes = [];

    if (!stored) {
      codes.push("NOT_FROZEN");
    }

    if (!lineageValid) {
      codes.push("INVALID_LINEAGE");
    }

    if (!policyValid) {
      codes.push("INVALID_POLICY");
    }

    /*
     * Recompute submitted manifest.
     */
    const manifest =
      validateManifest(submitted);

    let totalBytes = null;

    if (!manifest) {
      codes.push("INVALID_MANIFEST");
    } else {
      totalBytes =
        manifest.totalBytes;
    }

    /*
     * Prediction metrics.
     */
    const requiredSlices =
      policyValid
        ? body.policy.requiredSlices
        : {};

    const evaluation =
      evaluate(
        name,
        body.rows,
        requiredSlices
      );

    if (!evaluation.valid) {
      codes.push(
        "INVALID_PREDICTIONS"
      );
    } else if (policyValid) {
      if (
        evaluation.aggregate <
        body.policy.aggregateFloor
      ) {
        codes.push(
          "AGGREGATE_FLOOR"
        );
      }

      for (
        const slice of Object.keys(
          body.policy.requiredSlices
        )
      ) {
        if (
          evaluation.slices[slice] === null
        ) {
          codes.push(
            `MISSING_SLICE:${slice}`
          );
        } else if (
          evaluation.slices[slice] <
          body.policy.requiredSlices[slice]
        ) {
          codes.push(
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
      codes.push("LATENCY_LIMIT");
    }

    /*
     * Size.
     */
    if (
      policyValid &&
      totalBytes !== null &&
      totalBytes >
        body.policy.maxBytes
    ) {
      codes.push("SIZE_LIMIT");
    }

    /*
     * Latency ceiling.
     */
    if (
      policyValid &&
      latencyMs !== null &&
      latencyMs >
        body.policy.maxLatencyMs
    ) {
      codes.push("LATENCY_LIMIT");
    }

    /*
     * Must be an actually frozen candidate.
     */
    const recorded =
      storedCandidates.get(name);

    if (
      !recorded ||
      recorded.status !== "frozen"
    ) {
      codes.push("NOT_FROZEN");
    }

    const finalCodes =
      sortedCodes(codes);

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
      reasonCodes:
        finalCodes
    });
  }

  /*
   * Candidate order.
   */
  const positions = new Map();

  if (policyValid) {
    body.policy.candidateOrder.forEach(
      (name, index) => {
        positions.set(name, index);
      }
    );
  }

  results.sort((a, b) => {
    const ai =
      positions.has(a.name)
        ? positions.get(a.name)
        : Number.MAX_SAFE_INTEGER;

    const bi =
      positions.has(b.name)
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

  /*
   * Find admitted candidates.
   *
   * Tie break:
   *   1. smaller bytes
   *   2. lower latency
   *   3. candidate order
   *   4. UTF-8 name
   */
  const admitted =
    results.filter(
      x => x.admitted
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

      const ai =
        positions.has(a.name)
          ? positions.get(a.name)
          : Number.MAX_SAFE_INTEGER;

      const bi =
        positions.has(b.name)
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

    selected =
      admitted[0].name;

    /*
     * Exactly the recorded winner object.
     */
    packageManifest =
      storedCandidates.get(
        selected
      ) || null;
  }

  return res.status(200).json({
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest
  });
}

/* =========================================================
   ROUTES
   ========================================================= */

app.post("/quantize", (req, res) => {
  if (!isObject(req.body)) {
    return res.status(400).json({
      error: "INVALID_INPUT"
    });
  }

  if (req.body.phase === "freeze") {
    return doFreeze(req.body, res);
  }

  if (req.body.phase === "select") {
    return doSelect(req.body, res);
  }

  return res.status(400).json({
    error: "INVALID_INPUT"
  });
});

app.get("/", (req, res) => {
  res.json({
    status: "ok"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok"
  });
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
