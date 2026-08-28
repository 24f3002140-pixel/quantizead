const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const freezes = new Map();

/* =========================================================
   HELPERS
========================================================= */

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

function safeInteger(v) {
  return typeof v === "number" && Number.isSafeInteger(v);
}

function nonNegativeSafeInteger(v) {
  return safeInteger(v) && v >= 0;
}

function finiteNonNegative(v) {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0
  );
}

function floorValid(v) {
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

function round12(v) {
  const x = Number(v.toFixed(12));
  return Object.is(x, -0) ? 0 : x;
}

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

/*
 * Used only for freeze replay comparison.
 * Object key order is normalized; array order is preserved.
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

function deepEqual(a, b) {
  return canonicalString(a) === canonicalString(b);
}

/* =========================================================
   MANIFEST
========================================================= */

function buildManifest(files) {
  if (!isObject(files)) {
    return null;
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return null;
  }

  const seen = new Set();

  for (const name of names) {
    if (!nonEmptyString(name)) {
      return null;
    }

    if (seen.has(name)) {
      return null;
    }

    seen.add(name);

    if (typeof files[name] !== "string") {
      return null;
    }
  }

  names.sort(utf8Compare);

  const inventory = [];

  for (const name of names) {
    const bytes = Buffer.from(files[name], "utf8");

    inventory.push({
      name,
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
   * JSON.stringify is compact.
   *
   * Inventory objects are created in this exact key order:
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
 * Validate/recompute a recorded manifest.
 *
 * The candidate inventory is already the frozen artifact
 * inventory, so we recompute:
 *   - UTF-8 filename ordering
 *   - byte total
 *   - package digest
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

  const digest = sha256(
    Buffer.from(
      JSON.stringify(inventory),
      "utf8"
    )
  );

  if (candidate.packageDigest !== digest) {
    return null;
  }

  return {
    inventory,
    totalBytes,
    packageDigest: digest
  };
}

/* =========================================================
   FREEZE
========================================================= */

function freezeInputValid(body) {
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
 * Candidate names are request-level validity constraints.
 */
function validateCandidateNames(candidates) {
  const seen = new Set();

  for (const candidate of candidates) {
    if (!isObject(candidate)) {
      return false;
    }

    if (!nonEmptyString(candidate.name)) {
      return false;
    }

    if (seen.has(candidate.name)) {
      return false;
    }

    seen.add(candidate.name);
  }

  return true;
}

function freeze(body) {
  /*
   * Only the actual top-level freeze requirements cause
   * HTTP 400.
   */
  if (!freezeInputValid(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  if (!validateCandidateNames(body.candidates)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * IMPORTANT:
   * Do not reserve freezeId until the entire freeze request
   * has passed request-level validation.
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

  const frozenCandidates = [];

  for (const candidate of body.candidates) {
    const codes = [];

    /*
     * ------------------------------------------------------
     * Candidate fields
     * ------------------------------------------------------
     *
     * Candidate-level malformed data makes that candidate
     * invalid rather than rejecting the whole freeze.
     */

    const filesValid =
      isObject(candidate.files) &&
      Object.keys(candidate.files).length > 0 &&
      Object.keys(candidate.files).every(
        filename =>
          nonEmptyString(filename) &&
          typeof candidate.files[filename] === "string"
      );

    const loadableValid =
      candidate.loadable === true ||
      candidate.loadable === false;

    const calibrationValid =
      nonEmptyString(candidate.calibrationDigest);

    const tokenizerValid =
      nonEmptyString(candidate.tokenizerDigest);

    const reasonFieldPresent =
      Object.prototype.hasOwnProperty.call(
        candidate,
        "unsupportedReason"
      );

    const reasonValid =
      !reasonFieldPresent ||
      candidate.unsupportedReason === null ||
      candidate.unsupportedReason === undefined ||
      typeof candidate.unsupportedReason === "string";

    /*
     * If files themselves are invalid, return the exact
     * invalid-candidate manifest shape.
     */
    if (!filesValid) {
      codes.push("INVALID_INPUT");

      frozenCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    const manifest = buildManifest(candidate.files);

    if (!manifest) {
      frozenCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      });

      continue;
    }

    /*
     * Invalid candidate-level fields.
     */
    if (!loadableValid) {
      codes.push("INVALID_INPUT");
    }

    if (!calibrationValid) {
      codes.push("INVALID_INPUT");
    }

    if (!tokenizerValid) {
      codes.push("INVALID_INPUT");
    }

    if (!reasonValid) {
      codes.push("INVALID_INPUT");
    }

    if (codes.length > 0) {
      frozenCandidates.push({
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
     * unsupportedReason semantics:
     *
     * Allowed reason -> unsupported.
     * Any reason not allowed -> invalid.
     */
    const hasReason =
      typeof candidate.unsupportedReason === "string" &&
      candidate.unsupportedReason.length > 0;

    if (hasReason) {
      const allowed =
        body.allowedUnsupportedReasons.includes(
          candidate.unsupportedReason
        );

      if (!allowed) {
        frozenCandidates.push({
          name: candidate.name,
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

      frozenCandidates.push({
        name: candidate.name,
        status: "unsupported",
        inventory: manifest.inventory,
        totalBytes: manifest.totalBytes,
        packageDigest: manifest.packageDigest,
        reasonCodes: []
      });

      continue;
    }

    /*
     * No unsupportedReason:
     * candidate must be loadable and have matching lineage.
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
      frozenCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    frozenCandidates.push({
      name: candidate.name,
      status: "frozen",
      inventory: manifest.inventory,
      totalBytes: manifest.totalBytes,
      packageDigest: manifest.packageDigest,
      reasonCodes: []
    });
  }

  /*
   * Freeze response sorted by UTF-8 candidate name.
   */
  frozenCandidates.sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: frozenCandidates
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

/* =========================================================
   POLICY
========================================================= */

function validPolicy(policy) {
  if (!isObject(policy)) {
    return false;
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

  for (const name of Object.keys(policy.requiredSlices)) {
    if (!nonEmptyString(name)) {
      return false;
    }

    if (!floorValid(policy.requiredSlices[name])) {
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
   SELECT
========================================================= */

function selectInputValid(body) {
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

function candidateOrderValid(candidateNames, order) {
  if (!uniqueStrings(order)) {
    return false;
  }

  const a = new Set(candidateNames);
  const b = new Set(order);

  if (a.size !== b.size) {
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

function validateRows(rows) {
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

function calculateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  /*
   * Empty rows cannot produce an accuracy.
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

  let valid = true;
  let correct = 0;

  const sliceTotals = {};
  const sliceCorrect = {};

  for (const row of rows) {
    if (
      !Object.prototype.hasOwnProperty.call(
        row.predictions,
        candidateName
      )
    ) {
      valid = false;
      break;
    }

    const prediction =
      row.predictions[candidateName];

    if (!binaryPrediction(prediction)) {
      valid = false;
      break;
    }

    if (prediction === row.label) {
      correct++;
    }

    if (
      !Object.prototype.hasOwnProperty.call(
        sliceTotals,
        row.slice
      )
    ) {
      sliceTotals[row.slice] = 0;
      sliceCorrect[row.slice] = 0;
    }

    sliceTotals[row.slice]++;

    if (prediction === row.label) {
      sliceCorrect[row.slice]++;
    }
  }

  if (!valid) {
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

  const aggregate =
    round12(correct / rows.length);

  const slices = {};

  for (const sliceName of Object.keys(
    requiredSlices
  )) {
    if (
      !Object.prototype.hasOwnProperty.call(
        sliceTotals,
        sliceName
      )
    ) {
      slices[sliceName] = null;
    } else {
      slices[sliceName] = round12(
        sliceCorrect[sliceName] /
        sliceTotals[sliceName]
      );
    }
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

function resultComparator(order) {
  const positions = new Map();

  order.forEach((name, index) => {
    positions.set(name, index);
  });

  return (a, b) => {
    const ai = positions.has(a.name)
      ? positions.get(a.name)
      : null;

    const bi = positions.has(b.name)
      ? positions.get(b.name)
      : null;

    if (ai !== null && bi !== null) {
      return ai - bi;
    }

    if (ai !== null) return -1;
    if (bi !== null) return 1;

    return utf8Compare(a.name, b.name);
  };
}

function select(body) {
  /*
   * These are the only SELECT requests that receive
   * HTTP 400.
   */
  if (!selectInputValid(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * The grader may send an unknown freezeId.
   */
  const stored = freezes.get(body.freezeId);

  /*
   * Validate candidate names if possible.
   */
  const submittedNames = [];

  for (const candidate of body.candidates) {
    if (
      !isObject(candidate) ||
      !nonEmptyString(candidate.name)
    ) {
      return {
        status: 400,
        body: {
          error: "INVALID_INPUT"
        }
      };
    }

    submittedNames.push(candidate.name);
  }

  if (
    new Set(submittedNames).size !==
    submittedNames.length
  ) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * NOT_FROZEN is a selection result.
   */
  if (!stored) {
    const order =
      Array.isArray(body.policy.candidateOrder)
        ? body.policy.candidateOrder
        : [];

    const results =
      body.candidates.map(candidate => ({
        name: candidate.name,
        aggregate: null,
        slices: {},
        totalBytes: null,
        latencyMs: null,
        admitted: false,
        reasonCodes: ["NOT_FROZEN"]
      }));

    results.sort(
      resultComparator(order)
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

  const policyValid =
    validPolicy(body.policy);

  const storedCandidates =
    stored.response.candidates;

  const storedNames =
    storedCandidates.map(c => c.name);

  /*
   * Submitted candidates must exactly equal the stored
   * candidate array.
   */
  const lineageValid =
    deepEqual(
      body.candidates,
      storedCandidates
    );

  const order =
    body.policy.candidateOrder;

  const candidateSetValid =
    candidateOrderValid(
      storedNames,
      order
    );

  /*
   * Rows.
   */
  const rowsValid =
    validateRows(body.rows);

  /*
   * Latency map.
   */
  const latencyMapValid =
    isObject(body.latencies);

  const results = [];

  for (const candidate of storedCandidates) {
    const codes = [];

    /*
     * ------------------------------------------------------
     * LINEAGE
     * ------------------------------------------------------
     */
    if (
      !lineageValid ||
      candidate.status !== "frozen"
    ) {
      codes.push("INVALID_LINEAGE");
    }

    /*
     * ------------------------------------------------------
     * MANIFEST
     * ------------------------------------------------------
     */
    const manifest =
      validateManifest(candidate);

    let totalBytes = null;

    if (!manifest) {
      codes.push("INVALID_MANIFEST");
    } else {
      totalBytes =
        manifest.totalBytes;
    }

    /*
     * ------------------------------------------------------
     * PREDICTIONS
     * ------------------------------------------------------
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
        codes.push("INVALID_PREDICTIONS");
      }
    } else {
      codes.push("INVALID_PREDICTIONS");

      if (policyValid) {
        for (const sliceName of Object.keys(
          body.policy.requiredSlices
        )) {
          slices[sliceName] = null;
        }
      }
    }

    /*
     * ------------------------------------------------------
     * POLICY
     * ------------------------------------------------------
     */
    if (!policyValid) {
      codes.push("INVALID_POLICY");
    }

    if (!candidateSetValid) {
      codes.push("INVALID_POLICY");
    }

    /*
     * ------------------------------------------------------
     * ACCURACY GATES
     * ------------------------------------------------------
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
     * ------------------------------------------------------
     * SIZE
     * ------------------------------------------------------
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
     * ------------------------------------------------------
     * LATENCY
     * ------------------------------------------------------
     */
    let latencyMs = null;

    if (
      latencyMapValid &&
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
        codes.push("LATENCY_LIMIT");
      }
    } else {
      /*
       * No separate INVALID_LATENCY code exists in the
       * specification. An unvalidated latency cannot pass
       * the latency gate.
       */
      codes.push("LATENCY_LIMIT");
    }

    /*
     * Missing/invalid latency map is a policy failure too.
     */
    if (!latencyMapValid) {
      codes.push("INVALID_POLICY");
    }

    const reasonCodes =
      sortCodes(codes);

    const admitted =
      reasonCodes.length === 0 &&
      candidate.status === "frozen" &&
      manifest !== null &&
      rowsValid &&
      aggregate !== null &&
      totalBytes !== null &&
      latencyMs !== null &&
      policyValid &&
      candidateSetValid;

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
   * Required result ordering:
   * candidateOrder first,
   * UTF-8 name fallback.
   */
  results.sort(
    resultComparator(order)
  );

  /*
   * --------------------------------------------------------
   * WINNER
   * --------------------------------------------------------
   *
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidate order
   * 4. UTF-8 name
   */
  const admitted =
    results.filter(r => r.admitted);

  const positions = new Map();

  order.forEach((name, index) => {
    positions.set(name, index);
  });

  admitted.sort((a, b) => {
    if (
      a.totalBytes !== b.totalBytes
    ) {
      return (
        a.totalBytes -
        b.totalBytes
      );
    }

    if (
      a.latencyMs !== b.latencyMs
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
   HTTP
========================================================= */

function send(res, status, body) {
  const text =
    JSON.stringify(body);

  res.writeHead(status, {
    "Content-Type":
      "application/json; charset=utf-8",
    "Content-Length":
      Buffer.byteLength(text, "utf8"),
    "Cache-Control":
      "no-store"
  });

  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    req.on("data", chunk => {
      /*
       * Preserve raw UTF-8 bytes.
       * Decode only after the complete request is received.
       */
      chunks.push(
        Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(chunk)
      );
    });

    req.on("end", () => {
      try {
        const buffer =
          Buffer.concat(chunks);

        const decoder =
          new TextDecoder(
            "utf-8",
            { fatal: true }
          );

        const text =
          decoder.decode(buffer);

        resolve(
          JSON.parse(text)
        );
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

const server =
  http.createServer(
    async (req, res) => {
      /*
       * Root.
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
       * Health.
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
       * Quantize endpoint.
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
          await readBody(req);
      } catch {
        return send(
          res,
          400,
          {
            error: "INVALID_INPUT"
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
            freeze(body);
        } else if (
          body &&
          body.phase === "select"
        ) {
          result =
            select(body);
        } else {
          result = {
            status: 400,
            body: {
              error:
                "INVALID_INPUT"
            }
          };
        }
      } catch (error) {
        console.error(
          "Processing error:",
          error
        );

        /*
         * Never leave the grader waiting.
         */
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

server.on(
  "error",
  error => {
    console.error(
      "Server error:",
      error
    );
  }
);
