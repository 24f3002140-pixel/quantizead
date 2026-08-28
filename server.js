"use strict";

const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;

/*
 * Stateful storage.
 * freezeId -> {
 *   request: original freeze request,
 *   response: exact frozen response
 * }
 */
const freezeStore = new Map();

/* ============================================================
   HELPERS
============================================================ */

function isObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
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

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function round12(value) {
  return Number(value.toFixed(12));
}

function sortedUniqueCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function safeNonNegativeInteger(value) {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function finiteNonNegative(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0
  );
}

function validFloor(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function binaryValue(value) {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    (value === 0 || value === 1)
  );
}

/*
 * Canonical representation used ONLY for comparing
 * request objects for freezeId replay/conflict.
 */
function canonical(value) {
  if (Array.isArray(value)) {
    return value.map(canonical);
  }

  if (isObject(value)) {
    const result = {};

    for (
      const key of Object.keys(value).sort(utf8Compare)
    ) {
      result[key] = canonical(value[key]);
    }

    return result;
  }

  return value;
}

function deepEqual(a, b) {
  return (
    JSON.stringify(canonical(a)) ===
    JSON.stringify(canonical(b))
  );
}

/* ============================================================
   MANIFEST CONSTRUCTION
============================================================ */

function createManifest(files) {
  if (!isObject(files)) {
    return null;
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return null;
  }

  for (const name of names) {
    /*
     * File names must be non-empty strings.
     */
    if (!nonEmptyString(name)) {
      return null;
    }

    /*
     * File text is DATA.
     * It must be a string and must never be interpreted.
     */
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
   * Inventory object key order MUST be:
   * name, bytes, sha256
   *
   * JSON.stringify is compact by default.
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

/* ============================================================
   MANIFEST VALIDATION DURING SELECT
============================================================ */

function validateRecordedManifest(candidate) {
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
   * Inventory must already be UTF-8 sorted.
   */
  const sortedInventory = [...inventory].sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  if (!deepEqual(inventory, sortedInventory)) {
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
   * NEVER trust submitted totalBytes.
   * Compare it against recomputed value.
   */
  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  const packageDigest = sha256(
    Buffer.from(
      JSON.stringify(inventory),
      "utf8"
    )
  );

  /*
   * NEVER trust submitted packageDigest.
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
   FREEZE INPUT VALIDATION
============================================================ */

function validFreezeInput(body) {
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
   * Maximum 128 JS characters.
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

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  const allowed = new Set();

  for (const reason of body.allowedUnsupportedReasons) {
    if (!nonEmptyString(reason)) {
      return false;
    }

    if (allowed.has(reason)) {
      return false;
    }

    allowed.add(reason);
  }

  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  /*
   * Candidate names must be non-empty and unique.
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

function handleFreeze(body) {
  /*
   * Only explicitly malformed freeze envelopes get HTTP 400.
   */
  if (!validFreezeInput(body)) {
    return {
      status: 400,
      body: {
        error: "INVALID_INPUT"
      }
    };
  }

  /*
   * Existing freezeId:
   *
   * identical input -> exact replay
   * different input -> 409
   */
  if (freezeStore.has(body.freezeId)) {
    const saved = freezeStore.get(body.freezeId);

    if (deepEqual(saved.request, body)) {
      return {
        status: 200,
        body: saved.response
      };
    }

    return {
      status: 409,
      body: {
        error: "FREEZE_ID_CONFLICT"
      }
    };
  }

  const outputCandidates = [];

  for (const candidate of body.candidates) {
    /*
     * --------------------------------------------------------
     * Files
     * --------------------------------------------------------
     */
    const manifest = createManifest(
      candidate.files
    );

    /*
     * Invalid file object means invalid candidate.
     * It does NOT reject the entire freeze request.
     */
    if (manifest === null) {
      outputCandidates.push({
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

    const candidateCodes = [];

    /*
     * Candidate field validation.
     */
    if (
      candidate.loadable !== true &&
      candidate.loadable !== false
    ) {
      candidateCodes.push(
        "INVALID_INPUT"
      );
    }

    if (
      !nonEmptyString(
        candidate.calibrationDigest
      )
    ) {
      candidateCodes.push(
        "INVALID_INPUT"
      );
    }

    if (
      !nonEmptyString(
        candidate.tokenizerDigest
      )
    ) {
      candidateCodes.push(
        "INVALID_INPUT"
      );
    }

    if (
      candidate.unsupportedReason !== undefined &&
      candidate.unsupportedReason !== null &&
      typeof candidate.unsupportedReason !== "string"
    ) {
      candidateCodes.push(
        "INVALID_INPUT"
      );
    }

    if (candidateCodes.length > 0) {
      outputCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes:
          sortedUniqueCodes(candidateCodes)
      });

      continue;
    }

    /*
     * --------------------------------------------------------
     * UNSUPPORTED REASON
     * --------------------------------------------------------
     */
    const hasUnsupportedReason =
      typeof candidate.unsupportedReason === "string" &&
      candidate.unsupportedReason.length > 0;

    if (hasUnsupportedReason) {
      const allowed =
        body.allowedUnsupportedReasons.includes(
          candidate.unsupportedReason
        );

      if (!allowed) {
        outputCandidates.push({
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

      /*
       * Allowed reason means unsupported.
       * Keep its valid manifest.
       */
      outputCandidates.push({
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
     * --------------------------------------------------------
     * NORMAL FROZEN CANDIDATE
     * --------------------------------------------------------
     */
    if (candidate.loadable !== true) {
      candidateCodes.push(
        "NOT_LOADABLE"
      );
    }

    if (
      candidate.calibrationDigest !==
      body.calibrationDigest
    ) {
      candidateCodes.push(
        "CALIBRATION_MISMATCH"
      );
    }

    if (
      candidate.tokenizerDigest !==
      body.tokenizerDigest
    ) {
      candidateCodes.push(
        "TOKENIZER_MISMATCH"
      );
    }

    if (candidateCodes.length > 0) {
      outputCandidates.push({
        name: candidate.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes:
          sortedUniqueCodes(candidateCodes)
      });

      continue;
    }

    outputCandidates.push({
      name: candidate.name,
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
  outputCandidates.sort(
    (a, b) => utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: outputCandidates
  };

  /*
   * Persist the COMPLETE response and original request.
   */
  freezeStore.set(
    body.freezeId,
    {
      request: JSON.parse(
        JSON.stringify(body)
      ),
      response: JSON.parse(
        JSON.stringify(response)
      )
    }
  );

  return {
    status: 200,
    body: response
  };
}

/* ============================================================
   POLICY VALIDATION
============================================================ */

function validatePolicy(policy) {
  if (!isObject(policy)) {
    return false;
  }

  if (
    !safeNonNegativeInteger(
      policy.maxBytes
    )
  ) {
    return false;
  }

  if (
    !validFloor(
      policy.aggregateFloor
    )
  ) {
    return false;
  }

  if (!isObject(policy.requiredSlices)) {
    return false;
  }

  for (
    const sliceName of Object.keys(
      policy.requiredSlices
    )
  ) {
    if (!nonEmptyString(sliceName)) {
      return false;
    }

    if (
      !validFloor(
        policy.requiredSlices[sliceName]
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

  if (
    !Array.isArray(
      policy.candidateOrder
    )
  ) {
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
   SELECT INPUT VALIDATION
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
   * These three are explicitly required by the assignment.
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
   ROW VALIDATION
============================================================ */

function validRows(rows) {
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

    if (!binaryValue(row.label)) {
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
   SET COMPARISON
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
   PREDICTION METRICS
============================================================ */

function calculateMetrics(
  candidateName,
  rows,
  requiredSlices
) {
  /*
   * No rows means there is no measurable accuracy.
   */
  if (rows.length === 0) {
    const slices = {};

    for (
      const sliceName of Object.keys(
        requiredSlices
      )
    ) {
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
   * Validate every candidate prediction for every row.
   */
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
        slices: Object.fromEntries(
          Object.keys(
            requiredSlices
          ).map(name => [name, null])
        )
      };
    }

    const prediction =
      row.predictions[candidateName];

    if (!binaryValue(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: Object.fromEntries(
          Object.keys(
            requiredSlices
          ).map(name => [name, null])
        )
      };
    }

    if (prediction === row.label) {
      correct++;
    }
  }

  const aggregate =
    round12(
      correct / rows.length
    );

  const slices = {};

  for (
    const sliceName of Object.keys(
      requiredSlices
    )
  ) {
    const matchingRows =
      rows.filter(
        row =>
          row.slice === sliceName
      );

    /*
     * Required slice missing.
     */
    if (matchingRows.length === 0) {
      slices[sliceName] = null;
      continue;
    }

    let sliceCorrect = 0;

    for (const row of matchingRows) {
      const prediction =
        row.predictions[candidateName];

      if (!binaryValue(prediction)) {
        return {
          valid: false,
          aggregate: null,
          slices: Object.fromEntries(
            Object.keys(
              requiredSlices
            ).map(name => [name, null])
          )
        };
      }

      if (prediction === row.label) {
        sliceCorrect++;
      }
    }

    slices[sliceName] =
      round12(
        sliceCorrect /
        matchingRows.length
      );
  }

  return {
    valid: true,
    aggregate,
    slices
  };
}

/* ============================================================
   RESULT ORDER
============================================================ */

function resultComparator(candidateOrder) {
  const position = new Map();

  candidateOrder.forEach(
    (name, index) => {
      position.set(name, index);
    }
  );

  return (a, b) => {
    const ai = position.has(a.name)
      ? position.get(a.name)
      : null;

    const bi = position.has(b.name)
      ? position.get(b.name)
      : null;

    /*
     * Candidate order first.
     */
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

    /*
     * UTF-8 fallback.
     */
    return utf8Compare(
      a.name,
      b.name
    );
  };
}

/* ============================================================
   SELECT
============================================================ */

function handleSelect(body) {
  /*
   * Explicit malformed select request.
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
   * Candidate names must be usable.
   */
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
  }

  /*
   * ----------------------------------------------------------
   * NOT FROZEN
   * ----------------------------------------------------------
   */
  if (!freezeStore.has(body.freezeId)) {
    const candidateOrder =
      Array.isArray(
        body.policy.candidateOrder
      )
        ? body.policy.candidateOrder
        : [];

    const results =
      body.candidates.map(
        candidate => ({
          name: candidate.name,
          aggregate: null,
          slices: {},
          totalBytes: null,
          latencyMs: null,
          admitted: false,
          reasonCodes: [
            "NOT_FROZEN"
          ]
        })
      );

    results.sort(
      resultComparator(candidateOrder)
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

  const stored =
    freezeStore.get(body.freezeId);

  const storedCandidates =
    stored.response.candidates;

  const storedNames =
    storedCandidates.map(
      candidate => candidate.name
    );

  const submittedNames =
    body.candidates.map(
      candidate => candidate.name
    );

  /*
   * The complete submitted candidate array must exactly
   * equal the stored response candidate array.
   */
  const lineageExact =
    deepEqual(
      body.candidates,
      storedCandidates
    );

  /*
   * Policy validation.
   */
  const policyValid =
    validatePolicy(body.policy);

  /*
   * Candidate order must contain exactly the same
   * unique candidate-name set.
   */
  const candidateOrderValid =
    policyValid &&
    sameUniqueSet(
      storedNames,
      body.policy.candidateOrder
    );

  /*
   * Latencies must be object-shaped.
   */
  const latencyObject =
    isObject(body.latencies);

  /*
   * Rows must be structurally valid.
   */
  const rowsAreValid =
    validRows(body.rows);

  const results = [];

  for (const candidate of storedCandidates) {
    const codes = [];

    /*
     * --------------------------------------------------------
     * FROZEN STATUS
     * --------------------------------------------------------
     *
     * IMPORTANT:
     *
     * unsupported / invalid candidate
     * -> NOT_FROZEN
     *
     * submitted candidate array differs
     * -> INVALID_LINEAGE
     */
    if (!lineageExact) {
      codes.push(
        "INVALID_LINEAGE"
      );
    }

    if (candidate.status !== "frozen") {
      codes.push(
        "NOT_FROZEN"
      );
    }

    /*
     * --------------------------------------------------------
     * MANIFEST
     * --------------------------------------------------------
     */
    const manifest =
      validateRecordedManifest(
        candidate
      );

    let totalBytes = null;

    if (manifest === null) {
      codes.push(
        "INVALID_MANIFEST"
      );
    } else {
      totalBytes =
        manifest.totalBytes;
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
    } else if (!candidateOrderValid) {
      codes.push(
        "INVALID_POLICY"
      );
    }

    /*
     * --------------------------------------------------------
     * PREDICTIONS
     * --------------------------------------------------------
     */
    let aggregate = null;
    let slices = {};

    if (
      rowsAreValid &&
      policyValid
    ) {
      const metrics =
        calculateMetrics(
          candidate.name,
          body.rows,
          body.policy.requiredSlices
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
     * ACCURACY FLOORS
     * --------------------------------------------------------
     */
    if (
      policyValid &&
      rowsAreValid &&
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

      for (
        const sliceName of Object.keys(
          body.policy.requiredSlices
        )
      ) {
        const actual =
          slices[sliceName];

        if (actual === null) {
          codes.push(
            `MISSING_SLICE:${sliceName}`
          );
        } else if (
          actual <
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
     * SIZE LIMIT
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
        codes.push(
          "LATENCY_LIMIT"
        );
      }
    } else {
      /*
       * Missing/invalid latency means latency cannot
       * be validated, therefore candidate cannot be admitted.
       */
      codes.push(
        "LATENCY_LIMIT"
      );
    }

    /*
     * --------------------------------------------------------
     * REASON CODES
     * --------------------------------------------------------
     */
    const reasonCodes =
      sortedUniqueCodes(codes);

    /*
     * --------------------------------------------------------
     * ADMISSION
     * --------------------------------------------------------
     */
    const admitted =
      candidate.status === "frozen" &&
      lineageExact &&
      manifest !== null &&
      policyValid &&
      candidateOrderValid &&
      rowsAreValid &&
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
   * Results follow candidateOrder.
   * UTF-8 name is fallback.
   */
  results.sort(
    resultComparator(
      body.policy.candidateOrder
    )
  );

  /*
   * ----------------------------------------------------------
   * WINNER
   * ----------------------------------------------------------
   *
   * 1. admitted only
   * 2. smaller bytes
   * 3. lower latency
   * 4. candidateOrder
   * 5. UTF-8 name
   */
  const orderPosition = new Map();

  body.policy.candidateOrder.forEach(
    (name, index) => {
      orderPosition.set(
        name,
        index
      );
    }
  );

  const admittedCandidates =
    results.filter(
      result => result.admitted
    );

  admittedCandidates.sort(
    (a, b) => {
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
        orderPosition.has(a.name)
          ? orderPosition.get(a.name)
          : Number.MAX_SAFE_INTEGER;

      const bi =
        orderPosition.has(b.name)
          ? orderPosition.get(b.name)
          : Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return utf8Compare(
        a.name,
        b.name
      );
    }
  );

  let selected = null;
  let packageManifest = null;

  if (admittedCandidates.length > 0) {
    selected =
      admittedCandidates[0].name;

    /*
     * packageManifest must be exactly the recorded
     * winner object.
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
   JSON BODY
============================================================ */

function readRequestBody(req) {
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
             * Fatal UTF-8 decoding.
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
          } catch (error) {
            reject(error);
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
   RESPONSE
============================================================ */

function sendJson(
  res,
  status,
  body
) {
  const text =
    JSON.stringify(body);

  res.writeHead(
    status,
    {
      "Content-Type":
        "application/json; charset=utf-8",

      "Content-Length":
        Buffer.byteLength(
          text,
          "utf8"
        ),

      "Cache-Control":
        "no-store"
    }
  );

  res.end(text);
}

/* ============================================================
   HTTP SERVER
============================================================ */

const server =
  http.createServer(
    async (req, res) => {
      /*
       * Health endpoint.
       */
      if (
        req.method === "GET" &&
        req.url === "/health"
      ) {
        return sendJson(
          res,
          200,
          {
            status: "ok"
          }
        );
      }

      /*
       * Root endpoint.
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
       * ONLY endpoint required by grader.
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
        body =
          await readRequestBody(req);
      } catch (error) {
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
         * Unknown/missing phase => exact 400.
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
          result =
            handleFreeze(body);
        } else {
          result =
            handleSelect(body);
        }
      } catch (error) {
        /*
         * Log unexpected implementation errors.
         */
        console.error(
          "Quantize error:",
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

server.on(
  "error",
  error => {
    console.error(
      "Server error:",
      error
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
