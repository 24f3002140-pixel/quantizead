const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const freezes = new Map();

const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/* =========================================================
   BASIC HELPERS
========================================================= */

function isObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function sortUtf8(values) {
  return [...values].sort(utf8Compare);
}

function uniqueStrings(value) {
  if (!Array.isArray(value)) return false;

  const seen = new Set();

  for (const item of value) {
    if (!nonEmptyString(item)) return false;
    if (seen.has(item)) return false;
    seen.add(item);
  }

  return true;
}

function safeInteger(value) {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value)
  );
}

function nonNegativeSafeInteger(value) {
  return safeInteger(value) && value >= 0;
}

function finiteNonNegative(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0
  );
}

function floorValid(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function binary(value) {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    (value === 0 || value === 1)
  );
}

function round12(value) {
  const result = Number(value.toFixed(12));
  return Object.is(result, -0) ? 0 : result;
}

/*
 * Canonical comparison for replay detection.
 *
 * Object key order does not affect the meaning of the request.
 * Arrays retain their order.
 */
function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (isObject(value)) {
    const result = {};

    const keys = Object.keys(value).sort(utf8Compare);

    for (const key of keys) {
      result[key] = canonicalize(value[key]);
    }

    return result;
  }

  return value;
}

function canonicalString(value) {
  return JSON.stringify(canonicalize(value));
}

function exactJsonEqual(a, b) {
  return canonicalString(a) === canonicalString(b);
}

/* =========================================================
   JSON BODY READING
========================================================= */

function decodeUtf8(buffer) {
  /*
   * Fatal UTF-8 decoding prevents malformed byte sequences from
   * silently becoming replacement characters.
   */
  const decoder = new TextDecoder("utf-8", {
    fatal: true
  });

  return decoder.decode(buffer);
}

async function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    req.on("data", chunk => {
      chunks.push(Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk));
    });

    req.on("end", () => {
      try {
        const rawBuffer = Buffer.concat(chunks);
        const raw = decodeUtf8(rawBuffer);

        /*
         * JSON.parse rejects malformed JSON.
         */
        const parsed = JSON.parse(raw);

        resolve(parsed);
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", error => {
      reject(error);
    });
  });
}

/* =========================================================
   MANIFEST
========================================================= */

function buildManifest(files) {
  if (!isObject(files)) {
    return null;
  }

  const filenames = Object.keys(files);

  if (filenames.length === 0) {
    return null;
  }

  for (const filename of filenames) {
    if (!nonEmptyString(filename)) {
      return null;
    }

    if (typeof files[filename] !== "string") {
      return null;
    }
  }

  filenames.sort(utf8Compare);

  const inventory = [];

  for (const filename of filenames) {
    const bytes = Buffer.from(files[filename], "utf8");

    inventory.push({
      name: filename,
      bytes: bytes.length,
      sha256: sha256(bytes)
    });
  }

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return null;
    }
  }

  /*
   * JSON.stringify preserves the exact object key order:
   * name, bytes, sha256
   *
   * No whitespace is added.
   */
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
 * Recompute the manifest from the stored/submitted inventory.
 *
 * During SELECT the actual files are not supplied, so the grader
 * expects us to verify:
 *   - inventory structure
 *   - filename uniqueness
 *   - UTF-8 filename ordering
 *   - totalBytes
 *   - packageDigest
 */
function validateManifest(candidate) {
  if (!isObject(candidate)) {
    return null;
  }

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const inventory = [];
  const seen = new Set();

  for (const item of candidate.inventory) {
    if (!isObject(item)) {
      return null;
    }

    if (
      Object.keys(item).length !== 3 ||
      !Object.prototype.hasOwnProperty.call(item, "name") ||
      !Object.prototype.hasOwnProperty.call(item, "bytes") ||
      !Object.prototype.hasOwnProperty.call(item, "sha256")
    ) {
      return null;
    }

    if (!nonEmptyString(item.name)) {
      return null;
    }

    if (seen.has(item.name)) {
      return null;
    }

    seen.add(item.name);

    if (!nonNegativeSafeInteger(item.bytes)) {
      return null;
    }

    if (
      typeof item.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(item.sha256)
    ) {
      return null;
    }

    inventory.push({
      name: item.name,
      bytes: item.bytes,
      sha256: item.sha256
    });
  }

  /*
   * Inventory must already be in UTF-8 filename order.
   */
  const sortedInventory = [...inventory].sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  if (!exactJsonEqual(inventory, sortedInventory)) {
    return null;
  }

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return null;
    }
  }

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(inventory),
      "utf8"
    )
  );

  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  if (candidate.packageDigest !== packageDigest) {
    return null;
  }

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

/* =========================================================
   FREEZE REQUEST VALIDATION
========================================================= */

function validFreezeEnvelope(body) {
  if (!isObject(body)) {
    return false;
  }

  if (body.phase !== "freeze") {
    return false;
  }

  if (!nonEmptyString(body.freezeId)) {
    return false;
  }

  if (
    Buffer.byteLength(body.freezeId, "utf8") > 128
  ) {
    return false;
  }

  if (!nonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!nonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!uniqueStrings(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  return true;
}

/*
 * Candidate structural validation.
 *
 * Invalid FILE CONTENT is handled at candidate level because the
 * assignment explicitly requires an invalid candidate to return:
 *
 * inventory: []
 * totalBytes: null
 * packageDigest: null
 */
function validFreezeCandidateStructure(candidate) {
  if (!isObject(candidate)) {
    return false;
  }

  if (!nonEmptyString(candidate.name)) {
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(candidate, "files")) {
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(candidate, "loadable")) {
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(
    candidate,
    "calibrationDigest"
  )) {
    return false;
  }

  if (!Object.prototype.hasOwnProperty.call(
    candidate,
    "tokenizerDigest"
  )) {
    return false;
  }

  if (
    candidate.loadable !== true &&
    candidate.loadable !== false
  ) {
    return false;
  }

  if (!nonEmptyString(candidate.calibrationDigest)) {
    return false;
  }

  if (!nonEmptyString(candidate.tokenizerDigest)) {
    return false;
  }

  /*
   * If unsupportedReason exists, it must be a non-empty string.
   * null/empty reason is not a valid reason code.
   */
  if (
    Object.prototype.hasOwnProperty.call(
      candidate,
      "unsupportedReason"
    )
  ) {
    if (!nonEmptyString(candidate.unsupportedReason)) {
      return false;
    }
  }

  return true;
}

/* =========================================================
   FREEZE
========================================================= */

function freeze(body) {
  /*
   * IMPORTANT:
   * Validate the complete request before reserving freezeId.
   */
  if (!validFreezeEnvelope(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  const candidateNames = new Set();

  for (const candidate of body.candidates) {
    if (!validFreezeCandidateStructure(candidate)) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }

    if (candidateNames.has(candidate.name)) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }

    candidateNames.add(candidate.name);
  }

  const resultCandidates = [];

  for (const candidate of body.candidates) {
    /*
     * Files are candidate-level data.
     */
    const manifest = buildManifest(candidate.files);

    if (!manifest) {
      resultCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: [
          "INVALID_INPUT"
        ]
      });

      continue;
    }

    const codes = [];

    const hasUnsupportedReason =
      Object.prototype.hasOwnProperty.call(
        candidate,
        "unsupportedReason"
      );

    /*
     * A reason is only treated as a supported/allowed
     * unsupported reason when it appears in the request's
     * allowedUnsupportedReasons.
     */
    if (hasUnsupportedReason) {
      const reason = candidate.unsupportedReason;

      if (
        !body.allowedUnsupportedReasons.includes(reason)
      ) {
        codes.push(
          "UNALLOWED_UNSUPPORTED_REASON"
        );
      }

      /*
       * Any unsupported reason that is explicitly allowed
       * makes the candidate "unsupported".
       */
      if (codes.length === 0) {
        resultCandidates.push({
          name: candidate.name,
          status: "unsupported",
          inventory: manifest.inventory,
          totalBytes: manifest.totalBytes,
          packageDigest: manifest.packageDigest,
          reasonCodes: []
        });

        continue;
      }

      resultCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    /*
     * Without unsupportedReason the artifact MUST be loadable.
     */
    if (candidate.loadable !== true) {
      codes.push("NOT_LOADABLE");
    }

    if (
      candidate.calibrationDigest !==
      body.calibrationDigest
    ) {
      codes.push("CALIBRATION_MISMATCH");
    }

    if (
      candidate.tokenizerDigest !==
      body.tokenizerDigest
    ) {
      codes.push("TOKENIZER_MISMATCH");
    }

    if (codes.length > 0) {
      resultCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    resultCandidates.push({
      name: candidate.name,
      status: "frozen",
      inventory: manifest.inventory,
      totalBytes: manifest.totalBytes,
      packageDigest: manifest.packageDigest,
      reasonCodes: []
    });
  }

  /*
   * Freeze response is always sorted by UTF-8 candidate name.
   */
  resultCandidates.sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: resultCandidates
  };

  /*
   * Replay/conflict happens AFTER complete validation.
   */
  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (existing.inputCanonical === canonicalString(body)) {
      /*
       * Return the exact stored response.
       */
      return {
        status: 200,
        body: existing.response
      };
    }

    return {
      status: 409,
      body: {
        error: "FREEZE_ID_CONFLICT"
      }
    };
  }

  /*
   * Only valid freeze requests reserve the ID.
   */
  freezes.set(body.freezeId, {
    inputCanonical: canonicalString(body),
    response: JSON.parse(JSON.stringify(response))
  });

  return {
    status: 200,
    body: response
  };
}

/* =========================================================
   POLICY VALIDATION
========================================================= */

function validPolicy(policy) {
  if (!isObject(policy)) {
    return false;
  }

  /*
   * All required policy properties must exist.
   */
  const requiredKeys = [
    "maxBytes",
    "aggregateFloor",
    "requiredSlices",
    "maxLatencyMs",
    "candidateOrder"
  ];

  for (const key of requiredKeys) {
    if (
      !Object.prototype.hasOwnProperty.call(
        policy,
        key
      )
    ) {
      return false;
    }
  }

  if (!nonNegativeSafeInteger(policy.maxBytes)) {
    return false;
  }

  if (!floorValid(policy.aggregateFloor)) {
    return false;
  }

  if (!isObject(policy.requiredSlices)) {
    return false;
  }

  for (const sliceName of Object.keys(
    policy.requiredSlices
  )) {
    if (!nonEmptyString(sliceName)) {
      return false;
    }

    if (
      !floorValid(
        policy.requiredSlices[sliceName]
      )
    ) {
      return false;
    }
  }

  if (!finiteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (!uniqueStrings(policy.candidateOrder)) {
    return false;
  }

  return true;
}

/* =========================================================
   RESULT HELPERS
========================================================= */

function emptyResult(name) {
  return {
    name,
    aggregate: null,
    slices: {},
    totalBytes: null,
    latencyMs: null,
    admitted: false,
    reasonCodes: []
  };
}

function resultOrderComparator(order) {
  const index = new Map();

  order.forEach((name, i) => {
    index.set(name, i);
  });

  return (a, b) => {
    const ai = index.has(a.name)
      ? index.get(a.name)
      : null;

    const bi = index.has(b.name)
      ? index.get(b.name)
      : null;

    if (ai !== null && bi !== null) {
      return ai - bi;
    }

    if (ai !== null) {
      return -1;
    }

    if (bi !== null) {
      return 1;
    }

    return utf8Compare(a.name, b.name);
  };
}

/* =========================================================
   PREDICTION VALIDATION
========================================================= */

function calculateCandidateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  let predictionsValid = true;

  const correct = [];

  const sliceCorrect = {};
  const sliceTotal = {};

  /*
   * Validate every row.
   */
  for (const row of rows) {
    if (!isObject(row)) {
      predictionsValid = false;
      break;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        row,
        "label"
      )
    ) {
      predictionsValid = false;
      break;
    }

    /*
     * Labels are expected to be binary because predictions
     * are binary classification values.
     */
    if (!binary(row.label)) {
      predictionsValid = false;
      break;
    }

    if (!nonEmptyString(row.slice)) {
      predictionsValid = false;
      break;
    }

    if (!isObject(row.predictions)) {
      predictionsValid = false;
      break;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        row.predictions,
        candidateName
      )
    ) {
      predictionsValid = false;
      break;
    }

    const prediction =
      row.predictions[candidateName];

    if (!binary(prediction)) {
      predictionsValid = false;
      break;
    }

    const isCorrect =
      prediction === row.label;

    correct.push(isCorrect ? 1 : 0);

    if (
      Object.prototype.hasOwnProperty.call(
        sliceTotal,
        row.slice
      )
    ) {
      sliceTotal[row.slice] += 1;
      sliceCorrect[row.slice] += isCorrect ? 1 : 0;
    } else {
      sliceTotal[row.slice] = 1;
      sliceCorrect[row.slice] = isCorrect ? 1 : 0;
    }
  }

  if (!predictionsValid) {
    const slices = {};

    for (const sliceName of Object.keys(
      requiredSlices
    )) {
      slices[sliceName] = null;
    }

    return {
      valid: false,
      aggregate: null,
      slices
    };
  }

  /*
   * No rows => accuracy cannot be calculated.
   */
  if (rows.length === 0) {
    const slices = {};

    for (const sliceName of Object.keys(
      requiredSlices
    )) {
      slices[sliceName] = null;
    }

    return {
      valid: false,
      aggregate: null,
      slices
    };
  }

  const aggregate = round12(
    correct.reduce((sum, value) => sum + value, 0) /
    correct.length
  );

  /*
   * Only required slices are returned.
   */
  const slices = {};

  for (const sliceName of Object.keys(
    requiredSlices
  )) {
    if (
      !Object.prototype.hasOwnProperty.call(
        sliceTotal,
        sliceName
      )
    ) {
      slices[sliceName] = null;
      continue;
    }

    slices[sliceName] = round12(
      sliceCorrect[sliceName] /
      sliceTotal[sliceName]
    );
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

function select(body) {
  /*
   * Top-level SELECT shape.
   */
  if (!isObject(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (body.phase !== "select") {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (!nonEmptyString(body.freezeId)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (!Array.isArray(body.candidates)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (!Array.isArray(body.rows)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (!isObject(body.policy)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Candidate objects themselves must be structurally valid.
   */
  for (const candidate of body.candidates) {
    if (!isObject(candidate)) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }

    if (!nonEmptyString(candidate.name)) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }
  }

  const suppliedNames =
    body.candidates.map(c => c.name);

  /*
   * Candidate names must be unique.
   */
  if (
    new Set(suppliedNames).size !==
    suppliedNames.length
  ) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * A missing freeze is a normal selection response,
   * not a malformed HTTP request.
   */
  const stored = freezes.get(body.freezeId);

  if (!stored) {
    const order = Array.isArray(
      body.policy.candidateOrder
    )
      ? body.policy.candidateOrder
      : [];

    const results = body.candidates.map(
      candidate => {
        const result = emptyResult(candidate.name);

        result.reasonCodes = [
          "NOT_FROZEN"
        ];

        return result;
      }
    );

    results.sort(
      resultOrderComparator(order)
    );

    return {
      status: 200,
      body: {
        freezeId: body.freezeId,
        selected: null,
        results,
        packageManifest: null
      }
    };
  }

  /*
   * Policy validation.
   *
   * This is represented through INVALID_POLICY in the
   * selection result rather than converting the whole
   * selection into HTTP 400.
   */
  const policyValid =
    validPolicy(body.policy);

  const candidateOrder =
    Array.isArray(body.policy.candidateOrder)
      ? body.policy.candidateOrder
      : [];

  /*
   * Candidate array must EXACTLY equal the stored freeze
   * candidate response.
   */
  const lineageValid =
    exactJsonEqual(
      body.candidates,
      stored.response.candidates
    );

  const storedNames =
    stored.response.candidates.map(
      candidate => candidate.name
    );

  /*
   * candidateOrder must contain the same unique set
   * as the supplied candidate names.
   */
  let candidateSetValid = false;

  if (
    uniqueStrings(candidateOrder) &&
    new Set(candidateOrder).size ===
      suppliedNames.length
  ) {
    const a = new Set(suppliedNames);
    const b = new Set(candidateOrder);

    candidateSetValid =
      a.size === b.size &&
      [...a].every(name => b.has(name));
  }

  /*
   * Latencies must be an object.
   */
  const latenciesValid =
    isObject(body.latencies);

  /*
   * Basic row structure.
   */
  let rowsStructurallyValid = true;

  for (const row of body.rows) {
    if (!isObject(row)) {
      rowsStructurallyValid = false;
      break;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        row,
        "label"
      )
    ) {
      rowsStructurallyValid = false;
      break;
    }

    if (!nonEmptyString(row.slice)) {
      rowsStructurallyValid = false;
      break;
    }

    if (!isObject(row.predictions)) {
      rowsStructurallyValid = false;
      break;
    }
  }

  const results = [];

  /*
   * Process the STORED candidate set.
   *
   * This means a tampered submitted candidate cannot
   * become a new candidate.
   */
  for (const storedCandidate of stored.response.candidates) {
    const result =
      emptyResult(storedCandidate.name);

    const codes = [];

    /* -----------------------------------------------------
       LINEAGE
    ----------------------------------------------------- */

    if (!lineageValid) {
      codes.push("INVALID_LINEAGE");
    }

    /*
     * Only status "frozen" is admissible.
     */
    if (storedCandidate.status !== "frozen") {
      codes.push("INVALID_LINEAGE");
    }

    /* -----------------------------------------------------
       MANIFEST
    ----------------------------------------------------- */

    const manifest =
      validateManifest(storedCandidate);

    if (!manifest) {
      codes.push("INVALID_MANIFEST");
    } else {
      result.totalBytes =
        manifest.totalBytes;
    }

    /* -----------------------------------------------------
       PREDICTIONS
    ----------------------------------------------------- */

    const metrics =
      calculateCandidateMetrics(
        storedCandidate.name,
        body.rows,
        policyValid
          ? body.policy.requiredSlices
          : {}
      );

    result.aggregate =
      metrics.aggregate;

    result.slices =
      metrics.slices;

    if (!metrics.valid) {
      codes.push("INVALID_PREDICTIONS");
    }

    /*
     * If policy is invalid, prediction metrics are still
     * useful when possible, but no policy thresholds are
     * applied.
     */
    if (!policyValid) {
      codes.push("INVALID_POLICY");
    }

    /* -----------------------------------------------------
       REQUIRED SLICE / AGGREGATE GATES
    ----------------------------------------------------- */

    if (
      policyValid &&
      metrics.valid
    ) {
      if (
        result.aggregate === null ||
        result.aggregate <
          body.policy.aggregateFloor
      ) {
        codes.push("AGGREGATE_FLOOR");
      }

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        const value =
          result.slices[sliceName];

        if (value === null) {
          codes.push(
            `MISSING_SLICE:${sliceName}`
          );
        } else if (
          value <
          body.policy.requiredSlices[sliceName]
        ) {
          codes.push(
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    /* -----------------------------------------------------
       SIZE
    ----------------------------------------------------- */

    if (
      policyValid &&
      result.totalBytes !== null &&
      result.totalBytes >
        body.policy.maxBytes
    ) {
      codes.push("SIZE_LIMIT");
    }

    /* -----------------------------------------------------
       LATENCY
    ----------------------------------------------------- */

    let latencyValid = false;

    if (
      latenciesValid &&
      Object.prototype.hasOwnProperty.call(
        body.latencies,
        storedCandidate.name
      ) &&
      finiteNonNegative(
        body.latencies[
          storedCandidate.name
        ]
      )
    ) {
      result.latencyMs =
        body.latencies[
          storedCandidate.name
        ];

      latencyValid = true;

      if (
        policyValid &&
        result.latencyMs >
          body.policy.maxLatencyMs
      ) {
        codes.push("LATENCY_LIMIT");
      }
    } else {
      /*
       * There is no separate INVALID_LATENCY code in the
       * specification. An unverifiable latency therefore
       * cannot satisfy the latency admission gate.
       */
      codes.push("LATENCY_LIMIT");
    }

    /* -----------------------------------------------------
       GLOBAL SELECT STRUCTURE
    ----------------------------------------------------- */

    if (!candidateSetValid) {
      codes.push("INVALID_POLICY");
    }

    if (!latenciesValid) {
      codes.push("INVALID_POLICY");
    }

    if (!rowsStructurallyValid) {
      codes.push("INVALID_PREDICTIONS");
    }

    /*
     * If predictions are structurally invalid, all metric
     * values must be null.
     */
    if (
      !rowsStructurallyValid
    ) {
      result.aggregate = null;

      if (policyValid) {
        result.slices = {};

        for (const sliceName of Object.keys(
          body.policy.requiredSlices
        )) {
          result.slices[sliceName] = null;
        }
      } else {
        result.slices = {};
      }
    }

    result.reasonCodes =
      sortCodes(codes);

    /*
     * Admission requires ALL gates.
     */
    result.admitted =
      result.reasonCodes.length === 0 &&
      storedCandidate.status === "frozen" &&
      manifest !== null &&
      metrics.valid &&
      candidateSetValid &&
      policyValid &&
      rowsStructurallyValid &&
      latencyValid &&
      result.aggregate !== null &&
      result.totalBytes !== null &&
      result.latencyMs !== null;

    results.push(result);
  }

  /*
   * Results:
   *   candidateOrder first
   *   UTF-8 name fallback
   */
  results.sort(
    resultOrderComparator(candidateOrder)
  );

  /* =======================================================
     WINNER
  ======================================================= */

  const admitted =
    results.filter(
      result => result.admitted
    );

  const orderIndex = new Map();

  candidateOrder.forEach((name, index) => {
    orderIndex.set(name, index);
  });

  /*
   * Smaller bytes,
   * then lower latency,
   * then candidateOrder,
   * then UTF-8 name.
   */
  admitted.sort((a, b) => {
    if (a.totalBytes !== b.totalBytes) {
      return a.totalBytes - b.totalBytes;
    }

    if (a.latencyMs !== b.latencyMs) {
      return a.latencyMs - b.latencyMs;
    }

    const ai =
      orderIndex.has(a.name)
        ? orderIndex.get(a.name)
        : Number.MAX_SAFE_INTEGER;

    const bi =
      orderIndex.has(b.name)
        ? orderIndex.get(b.name)
        : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(
      a.name,
      b.name
    );
  });

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    selected =
      admitted[0].name;

    /*
     * Exactly the recorded winner object.
     */
    packageManifest =
      stored.response.candidates.find(
        candidate =>
          candidate.name === selected
      );
  }

  return {
    status: 200,
    body: {
      freezeId: body.freezeId,
      selected,
      results,
      packageManifest
    }
  };
}

/* =========================================================
   HTTP RESPONSE
========================================================= */

function send(res, status, body) {
  const text = JSON.stringify(body);

  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length":
      Buffer.byteLength(text, "utf8"),
    "Cache-Control": "no-store"
  });

  res.end(text);
}

/* =========================================================
   HTTP SERVER
========================================================= */

const server = http.createServer(
  async (req, res) => {
    /*
     * Root health endpoint.
     */
    if (
      req.method === "GET" &&
      req.url === "/"
    ) {
      return send(res, 200, {
        service: "quantize-admission-api",
        status: "ok"
      });
    }

    /*
     * Health endpoint.
     */
    if (
      req.method === "GET" &&
      req.url === "/health"
    ) {
      return send(res, 200, {
        status: "ok"
      });
    }

    /*
     * Only POST /quantize is supported.
     */
    if (
      req.method !== "POST" ||
      req.url !== "/quantize"
    ) {
      return send(res, 404, {
        error: "NOT_FOUND"
      });
    }

    let body;

    try {
      body = await readRequestBody(req);
    } catch {
      return send(res, 400, {
        error: "INVALID_INPUT"
      });
    }

    let result;

    try {
      if (
        body &&
        body.phase === "freeze"
      ) {
        result = freeze(body);
      } else if (
        body &&
        body.phase === "select"
      ) {
        result = select(body);
      } else {
        result = {
          status: 400,
          body: {
            error: "INVALID_INPUT"
          }
        };
      }
    } catch (error) {
      /*
       * Do not allow an unexpected server exception to leave
       * the grader's POST request hanging.
       */
      console.error(
        "Request processing error:",
        error
      );

      result = {
        status: 500,
        body: {
          error: "INTERNAL_ERROR"
        }
      };
    }

    return send(
      res,
      result.status,
      result.body
    );
  }
);

/* =========================================================
   START
========================================================= */

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize service listening on ${PORT}`
    );
  }
);

server.on("error", error => {
  console.error(
    "Server error:",
    error
  );
});
