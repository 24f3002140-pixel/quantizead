const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const freezes = new Map();

/* ============================================================
   BASIC HELPERS
============================================================ */

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function nonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function uniqueStrings(v) {
  if (!Array.isArray(v)) return false;

  const seen = new Set();

  for (const x of v) {
    if (!nonEmptyString(x) || seen.has(x)) {
      return false;
    }
    seen.add(x);
  }

  return true;
}

function safeNonNegativeInteger(v) {
  return (
    typeof v === "number" &&
    Number.isSafeInteger(v) &&
    v >= 0
  );
}

function finiteNonNegative(v) {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0
  );
}

function validFloor(v) {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0 &&
    v <= 1
  );
}

function binaryPrediction(v) {
  return (
    typeof v === "number" &&
    Number.isInteger(v) &&
    (v === 0 || v === 1)
  );
}

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

function round12(v) {
  const x = Number(v.toFixed(12));
  return Object.is(x, -0) ? 0 : x;
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

/*
 * Canonical comparison used for replay detection.
 * It preserves array ordering but sorts object keys by UTF-8.
 */
function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  if (isObject(value)) {
    const out = {};
    const keys = Object.keys(value).sort(utf8Compare);

    for (const key of keys) {
      out[key] = canonicalize(value[key]);
    }

    return out;
  }

  return value;
}

function deepEqual(a, b) {
  return (
    JSON.stringify(canonicalize(a)) ===
    JSON.stringify(canonicalize(b))
  );
}

/* ============================================================
   MANIFEST
============================================================ */

/*
 * Files are JSON object properties whose values are UTF-8 text.
 *
 * Inventory:
 *   name
 *   bytes
 *   sha256
 *
 * Inventory is sorted by UTF-8 filename.
 */
function buildManifest(files) {
  if (!isObject(files)) {
    return null;
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return null;
  }

  for (const name of names) {
    if (!nonEmptyString(name)) {
      return null;
    }

    if (typeof files[name] !== "string") {
      return null;
    }
  }

  names.sort(utf8Compare);

  const inventory = [];

  for (const name of names) {
    const bytes = Buffer.from(files[name], "utf8");

    inventory.push({
      name: name,
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
   * JSON.stringify produces compact JSON.
   * Object insertion order is exactly:
   * name, bytes, sha256.
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
 * Recompute a stored/submitted inventory.
 * Never trust submitted totalBytes/packageDigest.
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

    if (!nonEmptyString(item.name)) {
      return null;
    }

    if (seen.has(item.name)) {
      return null;
    }

    seen.add(item.name);

    if (!safeNonNegativeInteger(item.bytes)) {
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
   * Inventory MUST already be sorted by UTF-8 filename.
   */
  const sorted = [...inventory].sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  if (!deepEqual(inventory, sorted)) {
    return null;
  }

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return null;
    }
  }

  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(inventory),
      "utf8"
    )
  );

  if (candidate.packageDigest !== packageDigest) {
    return null;
  }

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

/* ============================================================
   FREEZE VALIDATION
============================================================ */

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

  /*
   * SPEC SAYS CHARACTERS, NOT UTF-8 BYTES.
   */
  if (body.freezeId.length > 128) {
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
 * Candidate names are part of request structure.
 * Everything else can be represented as an invalid candidate.
 */
function validCandidateNames(candidates) {
  const seen = new Set();

  for (const c of candidates) {
    if (!isObject(c)) {
      return false;
    }

    if (!nonEmptyString(c.name)) {
      return false;
    }

    if (seen.has(c.name)) {
      return false;
    }

    seen.add(c.name);
  }

  return true;
}

/* ============================================================
   FREEZE
============================================================ */

function doFreeze(body) {
  /*
   * Only envelope-level malformed freeze requests are 400.
   */
  if (!validFreezeEnvelope(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Candidate names must be unique.
   */
  if (!validCandidateNames(body.candidates)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Check replay/conflict BEFORE doing any persistent write.
   */
  const existing = freezes.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.request, body)) {
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

  const results = [];

  for (const c of body.candidates) {
    const codes = [];

    /*
     * --------------------------------------------------------
     * Files
     * --------------------------------------------------------
     *
     * Invalid files do NOT reject the whole freeze request.
     * They produce:
     *   inventory: []
     *   totalBytes: null
     *   packageDigest: null
     */
    const manifest = buildManifest(c.files);

    if (!manifest) {
      results.push({
        name: c.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      });

      continue;
    }

    /*
     * --------------------------------------------------------
     * Candidate fields
     * --------------------------------------------------------
     */

    if (
      c.loadable !== true &&
      c.loadable !== false
    ) {
      codes.push("INVALID_INPUT");
    }

    if (!nonEmptyString(c.calibrationDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (!nonEmptyString(c.tokenizerDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (
      c.unsupportedReason !== undefined &&
      c.unsupportedReason !== null &&
      typeof c.unsupportedReason !== "string"
    ) {
      codes.push("INVALID_INPUT");
    }

    if (codes.length > 0) {
      results.push({
        name: c.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    /*
     * --------------------------------------------------------
     * unsupportedReason
     * --------------------------------------------------------
     */

    const hasReason =
      typeof c.unsupportedReason === "string" &&
      c.unsupportedReason.length > 0;

    if (hasReason) {
      const allowed =
        body.allowedUnsupportedReasons.includes(
          c.unsupportedReason
        );

      /*
       * Reason exists but isn't allowed => invalid.
       */
      if (!allowed) {
        results.push({
          name: c.name,
          status: "invalid",
          inventory: [],
          totalBytes: null,
          packageDigest: null,
          reasonCodes: [
            "UNALLOWED_UNSUPPORTED_REASON"
          ]
        });

        continue;
      }

      /*
       * Allowed unsupported reason => unsupported.
       *
       * The artifact is still frozen with its real manifest.
       */
      results.push({
        name: c.name,
        status: "unsupported",
        inventory: manifest.inventory,
        totalBytes: manifest.totalBytes,
        packageDigest: manifest.packageDigest,
        reasonCodes: []
      });

      continue;
    }

    /*
     * --------------------------------------------------------
     * Normal frozen candidate
     * --------------------------------------------------------
     */

    if (c.loadable !== true) {
      codes.push("NOT_LOADABLE");
    }

    if (
      c.calibrationDigest !==
      body.calibrationDigest
    ) {
      codes.push("CALIBRATION_MISMATCH");
    }

    if (
      c.tokenizerDigest !==
      body.tokenizerDigest
    ) {
      codes.push("TOKENIZER_MISMATCH");
    }

    if (codes.length > 0) {
      results.push({
        name: c.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    results.push({
      name: c.name,
      status: "frozen",
      inventory: manifest.inventory,
      totalBytes: manifest.totalBytes,
      packageDigest: manifest.packageDigest,
      reasonCodes: []
    });
  }

  /*
   * Candidate response sorted by UTF-8 name.
   */
  results.sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: results
  };

  /*
   * Persist complete response.
   */
  freezes.set(body.freezeId, {
    request: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response))
  });

  return {
    status: 200,
    body: response
  };
}

/* ============================================================
   POLICY
============================================================ */

function validPolicy(policy) {
  if (!isObject(policy)) {
    return false;
  }

  if (
    !safeNonNegativeInteger(policy.maxBytes)
  ) {
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

  const sliceSet = new Set();

  for (const name of sliceNames) {
    if (!nonEmptyString(name)) {
      return false;
    }

    if (sliceSet.has(name)) {
      return false;
    }

    sliceSet.add(name);

    if (
      !validFloor(
        policy.requiredSlices[name]
      )
    ) {
      return false;
    }
  }

  if (
    !finiteNonNegative(policy.maxLatencyMs)
  ) {
    return false;
  }

  if (
    !uniqueStrings(policy.candidateOrder)
  ) {
    return false;
  }

  return true;
}

/* ============================================================
   SELECT ENVELOPE
============================================================ */

function validSelectEnvelope(body) {
  /*
   * Assignment explicitly says:
   *
   * select request without array candidates and rows
   * plus object policy => 400
   */
  if (!isObject(body)) {
    return false;
  }

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

  return true;
}

/* ============================================================
   ROW VALIDATION
============================================================ */

function rowsStructurallyValid(rows) {
  if (!Array.isArray(rows)) {
    return false;
  }

  for (const row of rows) {
    if (!isObject(row)) {
      return false;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        row,
        "label"
      )
    ) {
      return false;
    }

    if (!binaryPrediction(row.label)) {
      return false;
    }

    if (!nonEmptyString(row.slice)) {
      return false;
    }

    if (!isObject(row.predictions)) {
      return false;
    }
  }

  return true;
}

/* ============================================================
   CANDIDATE ORDER
============================================================ */

function sameCandidateSet(aNames, bNames) {
  if (
    !Array.isArray(aNames) ||
    !Array.isArray(bNames)
  ) {
    return false;
  }

  if (aNames.length !== bNames.length) {
    return false;
  }

  const a = new Set(aNames);
  const b = new Set(bNames);

  if (a.size !== aNames.length) {
    return false;
  }

  if (b.size !== bNames.length) {
    return false;
  }

  if (a.size !== b.size) {
    return false;
  }

  for (const name of a) {
    if (!b.has(name)) {
      return false;
    }
  }

  return true;
}

/* ============================================================
   METRICS
============================================================ */

function calculateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  let predictionsValid = true;

  /*
   * Empty rows means no aggregate can be computed.
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

  let correct = 0;

  /*
   * Validate EVERY row first.
   */
  for (const row of rows) {
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

    if (!binaryPrediction(prediction)) {
      predictionsValid = false;
      break;
    }

    if (prediction === row.label) {
      correct++;
    }
  }

  const slices = {};

  if (!predictionsValid) {
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

  const aggregate =
    round12(correct / rows.length);

  /*
   * Required slices.
   */
  for (const sliceName of Object.keys(
    requiredSlices
  )) {
    const sliceRows =
      rows.filter(
        row => row.slice === sliceName
      );

    if (sliceRows.length === 0) {
      slices[sliceName] = null;
      continue;
    }

    let sliceCorrect = 0;

    for (const row of sliceRows) {
      const prediction =
        row.predictions[candidateName];

      if (!binaryPrediction(prediction)) {
        predictionsValid = false;
        break;
      }

      if (prediction === row.label) {
        sliceCorrect++;
      }
    }

    if (!predictionsValid) {
      break;
    }

    slices[sliceName] =
      round12(
        sliceCorrect / sliceRows.length
      );
  }

  if (!predictionsValid) {
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

  return {
    valid: true,
    aggregate,
    slices
  };
}

/* ============================================================
   SELECT
============================================================ */

function doSelect(body) {
  /*
   * Only the explicit malformed select envelope is 400.
   */
  if (!validSelectEnvelope(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Candidate objects must at least expose names so that
   * the request can be processed.
   */
  for (const c of body.candidates) {
    if (
      !isObject(c) ||
      !nonEmptyString(c.name)
    ) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }
  }

  /*
   * Unknown freeze ID.
   *
   * This is NOT a malformed request.
   * Return a normal selection response.
   */
  const stored =
    freezes.get(body.freezeId);

  if (!stored) {
    const order =
      Array.isArray(
        body.policy.candidateOrder
      )
        ? body.policy.candidateOrder
        : [];

    const results =
      body.candidates.map(c => ({
        name: c.name,
        aggregate: null,
        slices: {},
        totalBytes: null,
        latencyMs: null,
        admitted: false,
        reasonCodes: ["NOT_FROZEN"]
      }));

    results.sort(
      makeResultComparator(order)
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

  const storedCandidates =
    stored.response.candidates;

  const storedNames =
    storedCandidates.map(
      c => c.name
    );

  const submittedNames =
    body.candidates.map(
      c => c.name
    );

  /*
   * The supplied candidate array must exactly equal the
   * stored response.
   */
  const lineageValid =
    deepEqual(
      body.candidates,
      storedCandidates
    );

  /*
   * Policy validation.
   */
  const policyValid =
    validPolicy(body.policy);

  /*
   * Candidate order must be the same unique set.
   */
  const candidateSetValid =
    policyValid &&
    sameCandidateSet(
      storedNames,
      body.policy.candidateOrder
    );

  /*
   * Latencies must be an object.
   */
  const latenciesValid =
    isObject(body.latencies);

  /*
   * Rows structural validation.
   */
  const rowsValid =
    rowsStructurallyValid(
      body.rows
    );

  const results = [];

  for (const candidate of storedCandidates) {
    const codes = [];

    /*
     * --------------------------------------------------------
     * LINEAGE
     * --------------------------------------------------------
     */
    if (
      !lineageValid ||
      candidate.status !== "frozen"
    ) {
      codes.push(
        candidate.status === "frozen"
          ? "INVALID_LINEAGE"
          : "INVALID_LINEAGE"
      );
    }

    /*
     * --------------------------------------------------------
     * MANIFEST
     * --------------------------------------------------------
     */
    const manifest =
      validateManifest(candidate);

    let totalBytes = null;

    if (!manifest) {
      codes.push(
        "INVALID_MANIFEST"
      );
    } else {
      totalBytes =
        manifest.totalBytes;
    }

    /*
     * --------------------------------------------------------
     * PREDICTIONS
     * --------------------------------------------------------
     */
    let aggregate = null;
    let slices = {};

    if (rowsValid) {
      const metrics =
        calculateMetrics(
          candidate.name,
          body.rows,
          policyValid
            ? body.policy.requiredSlices
            : {}
        );

      aggregate =
        metrics.aggregate;

      slices =
        metrics.slices;

      if (!metrics.valid) {
        codes.push(
          "INVALID_PREDICTIONS"
        );
      }
    } else {
      codes.push(
        "INVALID_PREDICTIONS"
      );

      if (policyValid) {
        for (const sliceName of Object.keys(
          body.policy.requiredSlices
        )) {
          slices[sliceName] = null;
        }
      }
    }

    /*
     * --------------------------------------------------------
     * POLICY
     * --------------------------------------------------------
     */
    if (!policyValid) {
      codes.push(
        "INVALID_POLICY"
      );
    }

    if (
      policyValid &&
      !candidateSetValid
    ) {
      codes.push(
        "INVALID_POLICY"
      );
    }

    /*
     * --------------------------------------------------------
     * ACCURACY
     * --------------------------------------------------------
     */
    if (
      policyValid &&
      rowsValid &&
      aggregate !== null
    ) {
      if (
        aggregate <
        body.policy.aggregateFloor
      ) {
        codes.push(
          "AGGREGATE_FLOOR"
        );
      }

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        const value =
          slices[sliceName];

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

    /*
     * --------------------------------------------------------
     * SIZE
     * --------------------------------------------------------
     */
    if (
      policyValid &&
      totalBytes !== null &&
      totalBytes >
        body.policy.maxBytes
    ) {
      codes.push(
        "SIZE_LIMIT"
      );
    }

    /*
     * --------------------------------------------------------
     * LATENCY
     * --------------------------------------------------------
     */
    let latencyMs = null;

    if (
      latenciesValid &&
      Object.prototype.hasOwnProperty.call(
        body.latencies,
        candidate.name
      ) &&
      finiteNonNegative(
        body.latencies[candidate.name]
      )
    ) {
      latencyMs =
        body.latencies[candidate.name];

      if (
        policyValid &&
        latencyMs >
          body.policy.maxLatencyMs
      ) {
        codes.push(
          "LATENCY_LIMIT"
        );
      }
    } else {
      /*
       * Cannot validate latency => cannot admit.
       */
      codes.push(
        "LATENCY_LIMIT"
      );
    }

    /*
     * --------------------------------------------------------
     * FINAL
     * --------------------------------------------------------
     */
    const reasonCodes =
      sortCodes(codes);

    const admitted =
      candidate.status === "frozen" &&
      lineageValid &&
      manifest !== null &&
      policyValid &&
      candidateSetValid &&
      rowsValid &&
      aggregate !== null &&
      totalBytes !== null &&
      latencyMs !== null &&
      reasonCodes.length === 0;

    results.push({
      name: candidate.name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes
    });
  }

  /*
   * --------------------------------------------------------
   * RESULT ORDER
   * --------------------------------------------------------
   */
  const order =
    body.policy.candidateOrder;

  results.sort(
    makeResultComparator(order)
  );

  /*
   * --------------------------------------------------------
   * WINNER
   * --------------------------------------------------------
   *
   * smaller bytes
   * then lower latency
   * then candidate order
   * then UTF-8 name
   * --------------------------------------------------------
   */
  const admitted =
    results.filter(
      r => r.admitted
    );

  const positions = new Map();

  if (Array.isArray(order)) {
    order.forEach(
      (name, index) => {
        positions.set(
          name,
          index
        );
      }
    );
  }

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

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    selected =
      admitted[0].name;

    packageManifest =
      storedCandidates.find(
        c => c.name === selected
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

/* ============================================================
   RESULT ORDER COMPARATOR
============================================================ */

function makeResultComparator(order) {
  const positions = new Map();

  if (Array.isArray(order)) {
    order.forEach(
      (name, index) => {
        positions.set(
          name,
          index
        );
      }
    );
  }

  return (a, b) => {
    const ai =
      positions.has(a.name)
        ? positions.get(a.name)
        : null;

    const bi =
      positions.has(b.name)
        ? positions.get(b.name)
        : null;

    if (
      ai !== null &&
      bi !== null
    ) {
      return ai - bi;
    }

    if (ai !== null) {
      return -1;
    }

    if (bi !== null) {
      return 1;
    }

    return utf8Compare(
      a.name,
      b.name
    );
  };
}

/* ============================================================
   HTTP RESPONSE
============================================================ */

function send(res, status, body) {
  const text =
    JSON.stringify(body);

  res.writeHead(status, {
    "Content-Type":
      "application/json",
    "Content-Length":
      Buffer.byteLength(
        text,
        "utf8"
      ),
    "Cache-Control":
      "no-store"
  });

  res.end(text);
}

/* ============================================================
   REQUEST BODY
============================================================ */

function readJsonBody(req) {
  return new Promise(
    (resolve, reject) => {
      const chunks = [];

      req.on(
        "data",
        chunk => {
          chunks.push(
            Buffer.isBuffer(chunk)
              ? chunk
              : Buffer.from(chunk)
          );
        }
      );

      req.on(
        "end",
        () => {
          try {
            const buffer =
              Buffer.concat(chunks);

            /*
             * Decode complete request as UTF-8.
             */
            const decoder =
              new TextDecoder(
                "utf-8",
                {
                  fatal: true
                }
              );

            const text =
              decoder.decode(buffer);

            const body =
              JSON.parse(text);

            resolve(body);
          } catch (err) {
            reject(err);
          }
        }
      );

      req.on(
        "error",
        reject
      );
    }
  );
}

/* ============================================================
   SERVER
============================================================ */

const server =
  http.createServer(
    async (req, res) => {
      /*
       * ------------------------------------------------------
       * HOME
       * ------------------------------------------------------
       */
      if (
        req.method === "GET" &&
        req.url === "/"
      ) {
        return send(
          res,
          200,
          {
            service:
              "quantize-admission-api",
            status: "ok"
          }
        );
      }

      /*
       * ------------------------------------------------------
       * HEALTH
       * ------------------------------------------------------
       */
      if (
        req.method === "GET" &&
        req.url === "/health"
      ) {
        return send(
          res,
          200,
          {
            status: "ok"
          }
        );
      }

      /*
       * ------------------------------------------------------
       * QUANTIZE
       * ------------------------------------------------------
       */
      if (
        req.method !== "POST" ||
        req.url !== "/quantize"
      ) {
        return send(
          res,
          404,
          {
            error: "NOT_FOUND"
          }
        );
      }

      let body;

      try {
        body =
          await readJsonBody(req);
      } catch {
        return send(
          res,
          400,
          {
            error:
              "INVALID_INPUT"
          }
        );
      }

      let result;

      try {
        if (
          body &&
          body.phase === "freeze"
        ) {
          result =
            doFreeze(body);
        } else if (
          body &&
          body.phase === "select"
        ) {
          result =
            doSelect(body);
        } else {
          result = {
            status: 400,
            body: {
              error:
                "INVALID_INPUT"
            }
          };
        }
      } catch (err) {
        console.error(
          "quantize processing error:",
          err
        );

        return send(
          res,
          500,
          {
            error:
              "INTERNAL_ERROR"
          }
        );
      }

      return send(
        res,
        result.status,
        result.body
      );
    }
  );

/* ============================================================
   START
============================================================ */

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize admission API listening on ${PORT}`
    );
  }
);

server.on(
  "error",
  err => {
    console.error(
      "Server error:",
      err
    );
  }
);
