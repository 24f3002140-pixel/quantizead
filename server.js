"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;

/*
 * Stateful freeze database.
 * This survives multiple requests while the process is alive.
 */
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
    Buffer.from(String(a), "utf8"),
    Buffer.from(String(b), "utf8")
  );
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function round12(value) {
  return Number(value.toFixed(12));
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

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

/*
 * Used only for comparing freeze requests.
 * Object key order does not affect equality.
 * Array order DOES affect equality.
 */
function canonical(v) {
  if (Array.isArray(v)) {
    return v.map(canonical);
  }

  if (isObject(v)) {
    const result = {};

    for (const key of Object.keys(v).sort(utf8Compare)) {
      result[key] = canonical(v[key]);
    }

    return result;
  }

  return v;
}

function deepEqual(a, b) {
  return (
    JSON.stringify(canonical(a)) ===
    JSON.stringify(canonical(b))
  );
}

/* ============================================================
   FILE MANIFEST
============================================================ */

function makeManifest(files) {
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

    /*
     * File text is DATA.
     * Never execute/evaluate it.
     */
    if (typeof files[filename] !== "string") {
      return null;
    }
  }

  filenames.sort(utf8Compare);

  const inventory = [];

  for (const filename of filenames) {
    const data = Buffer.from(files[filename], "utf8");

    inventory.push({
      name: filename,
      bytes: data.length,
      sha256: sha256(data)
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
   * Exact required key order:
   * name, bytes, sha256
   *
   * JSON.stringify is compact.
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

/* ============================================================
   RECORDED MANIFEST VALIDATION
============================================================ */

function validateManifest(candidate) {
  if (!isObject(candidate)) {
    return null;
  }

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const inventory = [];
  const names = new Set();

  for (const item of candidate.inventory) {
    if (!isObject(item)) {
      return null;
    }

    if (!nonEmptyString(item.name)) {
      return null;
    }

    if (names.has(item.name)) {
      return null;
    }

    names.add(item.name);

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
   * Must already be sorted by UTF-8 filename.
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

  /*
   * Recompute instead of trusting supplied totalBytes.
   */
  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  /*
   * Recompute instead of trusting supplied digest.
   */
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
   FREEZE TOP-LEVEL VALIDATION
============================================================ */

function validFreezeRequest(body) {
  if (!isObject(body)) {
    return false;
  }

  if (body.phase !== "freeze") {
    return false;
  }

  if (!nonEmptyString(body.freezeId)) {
    return false;
  }

  if (body.freezeId.length > 128) {
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
   * empty/non-array freeze candidate list => 400.
   */
  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  /*
   * Candidate names are request structure.
   */
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

/* ============================================================
   FREEZE
============================================================ */

function freeze(body) {
  if (!validFreezeRequest(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Replay / conflict.
   */
  const previous = freezes.get(body.freezeId);

  if (previous) {
    if (deepEqual(previous.request, body)) {
      return {
        status: 200,
        body: previous.response
      };
    }

    return {
      status: 409,
      body: {
        error: "FREEZE_ID_CONFLICT"
      }
    };
  }

  const resultCandidates = [];

  for (const candidate of body.candidates) {
    const manifest = makeManifest(candidate.files);

    /*
     * Invalid files affect only this candidate.
     */
    if (manifest === null) {
      resultCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      });

      continue;
    }

    const codes = [];

    /*
     * Candidate fields.
     */
    if (
      candidate.loadable !== true &&
      candidate.loadable !== false
    ) {
      codes.push("INVALID_INPUT");
    }

    if (!nonEmptyString(candidate.calibrationDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (!nonEmptyString(candidate.tokenizerDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (
      candidate.unsupportedReason !== undefined &&
      candidate.unsupportedReason !== null &&
      typeof candidate.unsupportedReason !== "string"
    ) {
      codes.push("INVALID_INPUT");
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

    /*
     * Unsupported reason.
     */
    const unsupported =
      typeof candidate.unsupportedReason === "string" &&
      candidate.unsupportedReason.length > 0;

    if (unsupported) {
      if (
        !body.allowedUnsupportedReasons.includes(
          candidate.unsupportedReason
        )
      ) {
        resultCandidates.push({
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

    /*
     * Normal frozen candidate.
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

  resultCandidates.sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: resultCandidates
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
   SELECT TOP-LEVEL VALIDATION
============================================================ */

function validSelectEnvelope(body) {
  if (!isObject(body)) {
    return false;
  }

  if (body.phase !== "select") {
    return false;
  }

  if (!nonEmptyString(body.freezeId)) {
    return false;
  }

  /*
   * Arrays may be empty.
   */
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
   POLICY
============================================================ */

function validatePolicy(policy) {
  if (!isObject(policy)) {
    return false;
  }

  if (!safeNonNegativeInteger(policy.maxBytes)) {
    return false;
  }

  if (!validFloor(policy.aggregateFloor)) {
    return false;
  }

  if (!isObject(policy.requiredSlices)) {
    return false;
  }

  for (const name of Object.keys(policy.requiredSlices)) {
    if (!nonEmptyString(name)) {
      return false;
    }

    if (!validFloor(policy.requiredSlices[name])) {
      return false;
    }
  }

  if (!finiteNonNegative(policy.maxLatencyMs)) {
    return false;
  }

  if (!Array.isArray(policy.candidateOrder)) {
    return false;
  }

  const names = new Set();

  for (const name of policy.candidateOrder) {
    if (!nonEmptyString(name)) {
      return false;
    }

    if (names.has(name)) {
      return false;
    }

    names.add(name);
  }

  return true;
}

/* ============================================================
   ROW VALIDATION
============================================================ */

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

/* ============================================================
   SET VALIDATION
============================================================ */

function sameUniqueSet(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b)) {
    return false;
  }

  const sa = new Set(a);
  const sb = new Set(b);

  if (sa.size !== a.length) {
    return false;
  }

  if (sb.size !== b.length) {
    return false;
  }

  if (sa.size !== sb.size) {
    return false;
  }

  for (const value of sa) {
    if (!sb.has(value)) {
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
  const nullSlices = {};

  for (const sliceName of Object.keys(requiredSlices)) {
    nullSlices[sliceName] = null;
  }

  /*
   * No rows => no valid prediction measurement.
   */
  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: nullSlices
    };
  }

  let correct = 0;

  for (const row of rows) {
    if (
      !Object.prototype.hasOwnProperty.call(
        row.predictions,
        candidateName
      )
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: nullSlices
      };
    }

    const prediction =
      row.predictions[candidateName];

    if (!binaryPrediction(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: nullSlices
      };
    }

    if (prediction === row.label) {
      correct++;
    }
  }

  const aggregate =
    round12(correct / rows.length);

  const slices = {};

  for (const sliceName of Object.keys(requiredSlices)) {
    const sliceRows = rows.filter(
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
        return {
          valid: false,
          aggregate: null,
          slices: nullSlices
        };
      }

      if (prediction === row.label) {
        sliceCorrect++;
      }
    }

    slices[sliceName] =
      round12(
        sliceCorrect / sliceRows.length
      );
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

/* ============================================================
   RESULT SORT
============================================================ */

function sortResults(results, candidateOrder) {
  const position = new Map();

  if (Array.isArray(candidateOrder)) {
    candidateOrder.forEach(
      (name, index) => {
        position.set(name, index);
      }
    );
  }

  results.sort((a, b) => {
    const ai = position.has(a.name)
      ? position.get(a.name)
      : null;

    const bi = position.has(b.name)
      ? position.get(b.name)
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
  });
}

/* ============================================================
   SELECT
============================================================ */

function select(body) {
  /*
   * IMPORTANT:
   *
   * This is the ONLY select-level 400 check.
   *
   * Candidate contents are NOT individually rejected with 400.
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
   * Unknown freeze ID.
   */
  if (!freezes.has(body.freezeId)) {
    const order =
      Array.isArray(body.policy.candidateOrder)
        ? body.policy.candidateOrder
        : [];

    const results = body.candidates.map(
      candidate => ({
        name:
          isObject(candidate) &&
          nonEmptyString(candidate.name)
            ? candidate.name
            : "",
        aggregate: null,
        slices: {},
        totalBytes: null,
        latencyMs: null,
        admitted: false,
        reasonCodes: ["NOT_FROZEN"]
      })
    );

    sortResults(results, order);

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

  const frozen =
    freezes.get(body.freezeId);

  const storedCandidates =
    frozen.response.candidates;

  const storedNames =
    storedCandidates.map(
      candidate => candidate.name
    );

  const submittedNames =
    body.candidates.map(candidate =>
      isObject(candidate)
        ? candidate.name
        : undefined
    );

  /*
   * Exact candidate array comparison.
   */
  const exactLineage =
    deepEqual(
      body.candidates,
      storedCandidates
    );

  /*
   * Policy.
   */
  const policyValid =
    validatePolicy(body.policy);

  /*
   * Candidate order unique set.
   */
  const candidateOrderValid =
    policyValid &&
    sameUniqueSet(
      storedNames,
      body.policy.candidateOrder
    );

  /*
   * Rows.
   */
  const rowsValid =
    validateRows(body.rows);

  /*
   * Latencies.
   */
  const latencyObject =
    isObject(body.latencies);

  const results = [];

  for (const candidate of storedCandidates) {
    const codes = [];

    /*
     * --------------------------------------------------------
     * LINEAGE
     * --------------------------------------------------------
     */
    if (!exactLineage) {
      codes.push("INVALID_LINEAGE");
    }

    /*
     * --------------------------------------------------------
     * FROZEN
     * --------------------------------------------------------
     */
    if (candidate.status !== "frozen") {
      codes.push("NOT_FROZEN");
    }

    /*
     * --------------------------------------------------------
     * MANIFEST
     * --------------------------------------------------------
     */
    const manifest =
      validateManifest(candidate);

    let totalBytes = null;

    if (manifest === null) {
      codes.push("INVALID_MANIFEST");
    } else {
      totalBytes = manifest.totalBytes;
    }

    /*
     * --------------------------------------------------------
     * POLICY
     * --------------------------------------------------------
     */
    if (!policyValid || !candidateOrderValid) {
      codes.push("INVALID_POLICY");
    }

    /*
     * --------------------------------------------------------
     * PREDICTIONS
     * --------------------------------------------------------
     */
    let aggregate = null;
    let slices = {};

    if (rowsValid && policyValid) {
      const metrics =
        calculateMetrics(
          candidate.name,
          body.rows,
          body.policy.requiredSlices
        );

      aggregate = metrics.aggregate;
      slices = metrics.slices;

      if (!metrics.valid) {
        codes.push("INVALID_PREDICTIONS");
      }
    } else {
      codes.push("INVALID_PREDICTIONS");

      if (policyValid) {
        for (
          const sliceName of Object.keys(
            body.policy.requiredSlices
          )
        ) {
          slices[sliceName] = null;
        }
      }
    }

    /*
     * --------------------------------------------------------
     * AGGREGATE + SLICES
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
        codes.push("AGGREGATE_FLOOR");
      }

      for (
        const sliceName of Object.keys(
          body.policy.requiredSlices
        )
      ) {
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
      codes.push("SIZE_LIMIT");
    }

    /*
     * --------------------------------------------------------
     * LATENCY
     * --------------------------------------------------------
     */
    let latencyMs = null;

    if (
      latencyObject &&
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
       * Cannot validate latency.
       */
      codes.push("LATENCY_LIMIT");
    }

    /*
     * --------------------------------------------------------
     * FINAL CODES
     * --------------------------------------------------------
     */
    const reasonCodes =
      sortCodes(codes);

    const admitted =
      candidate.status === "frozen" &&
      exactLineage &&
      manifest !== null &&
      policyValid &&
      candidateOrderValid &&
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
   * Result ordering.
   */
  sortResults(
    results,
    body.policy.candidateOrder
  );

  /*
   * Winner:
   *   1. smallest bytes
   *   2. lowest latency
   *   3. candidateOrder
   *   4. UTF-8 name
   */
  const orderPosition = new Map();

  if (Array.isArray(body.policy.candidateOrder)) {
    body.policy.candidateOrder.forEach(
      (name, index) => {
        orderPosition.set(name, index);
      }
    );
  }

  const winners =
    results.filter(
      result => result.admitted
    );

  winners.sort((a, b) => {
    if (a.totalBytes !== b.totalBytes) {
      return a.totalBytes - b.totalBytes;
    }

    if (a.latencyMs !== b.latencyMs) {
      return a.latencyMs - b.latencyMs;
    }

    const ai = orderPosition.has(a.name)
      ? orderPosition.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = orderPosition.has(b.name)
      ? orderPosition.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(a.name, b.name);
  });

  let selected = null;
  let packageManifest = null;

  if (winners.length > 0) {
    selected = winners[0].name;

    /*
     * Exactly the recorded winner object.
     */
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

/* ============================================================
   HTTP BODY
============================================================ */

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];

    req.on("data", chunk => {
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
          new TextDecoder("utf-8", {
            fatal: true
          });

        const text =
          decoder.decode(buffer);

        resolve(JSON.parse(text));
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

/* ============================================================
   RESPONSE
============================================================ */

function sendJson(res, status, body) {
  const text = JSON.stringify(body);

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

/* ============================================================
   SERVER
============================================================ */

const server =
  http.createServer(
    async (req, res) => {
      /*
       * Health.
       */
      if (
        req.method === "GET" &&
        req.url === "/health"
      ) {
        return sendJson(
          res,
          200,
          { status: "ok" }
        );
      }

      /*
       * Root.
       */
      if (
        req.method === "GET" &&
        req.url === "/"
      ) {
        return sendJson(
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
       * Grader endpoint.
       */
      if (
        req.method !== "POST" ||
        req.url !== "/quantize"
      ) {
        return sendJson(
          res,
          404,
          {
            error: "NOT_FOUND"
          }
        );
      }

      let body;

      try {
        body = await readJson(req);
      } catch {
        return sendJson(
          res,
          400,
          {
            error: "INVALID_INPUT"
          }
        );
      }

      let result;

      try {
        /*
         * Unknown or missing phase.
         */
        if (
          !isObject(body) ||
          (
            body.phase !== "freeze" &&
            body.phase !== "select"
          )
        ) {
          result = {
            status: 400,
            body: {
              error: "INVALID_INPUT"
            }
          };
        } else if (
          body.phase === "freeze"
        ) {
          result = freeze(body);
        } else {
          result = select(body);
        }
      } catch (error) {
        console.error(
          "Unhandled /quantize error:",
          error
        );

        result = {
          status: 500,
          body: {
            error: "INTERNAL_ERROR"
          }
        };
      }

      return sendJson(
        res,
        result.status,
        result.body
      );
    }
  );

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
  error => {
    console.error(
      "Server error:",
      error
    );
  }
);
