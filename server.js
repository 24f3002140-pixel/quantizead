const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 10000;

// Persistent only for the lifetime of this Render instance.
const freezes = new Map();

const FREEZE_CODES = new Set([
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH"
]);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function isObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function isNonEmptyString(x) {
  return typeof x === "string" && x.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function uniqueStrings(arr) {
  if (!Array.isArray(arr)) return false;
  const s = new Set();
  for (const x of arr) {
    if (!isNonEmptyString(x) || s.has(x)) return false;
    s.add(x);
  }
  return true;
}

function safeNumber(x) {
  return (
    typeof x === "number" &&
    Number.isFinite(x) &&
    Number.isSafeInteger(x)
  );
}

function nonNegativeFinite(x) {
  return typeof x === "number" && Number.isFinite(x) && x >= 0;
}

function finiteFloor(x) {
  return (
    typeof x === "number" &&
    Number.isFinite(x) &&
    x >= 0 &&
    x <= 1
  );
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/*
 * EXACT package digest rule:
 * SHA-256(UTF8(JSON.stringify(inventory)))
 *
 * Inventory objects MUST have keys in this order:
 * name, bytes, sha256
 */
function makeInventory(files) {
  if (!isObject(files)) return null;

  const names = Object.keys(files);

  if (names.length === 0) return null;

  // JS object keys are unique already.
  for (const name of names) {
    if (!isNonEmptyString(name)) return null;
    if (typeof files[name] !== "string") return null;

    // Validate UTF-8 by round trip.
    const buf = Buffer.from(files[name], "utf8");
    if (buf.toString("utf8") !== files[name]) return null;
  }

  names.sort(utf8Compare);

  const inventory = [];

  for (const name of names) {
    const buf = Buffer.from(files[name], "utf8");

    inventory.push({
      name: name,
      bytes: buf.length,
      sha256: sha256(buf)
    });
  }

  const totalBytes = inventory.reduce((sum, x) => sum + x.bytes, 0);

  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

function invalidFreezeCandidate(name, codes, manifest) {
  if (manifest) {
    return {
      name,
      status: "invalid",
      inventory: manifest.inventory,
      totalBytes: manifest.totalBytes,
      packageDigest: manifest.packageDigest,
      reasonCodes: sortCodes(codes)
    };
  }

  return {
    name,
    status: "invalid",
    inventory: [],
    totalBytes: null,
    packageDigest: null,
    reasonCodes: sortCodes(codes)
  };
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function validBinaryPrediction(x) {
  return (
    typeof x === "number" &&
    Number.isInteger(x) &&
    (x === 0 || x === 1)
  );
}

function rounded12(x) {
  return Number(x.toFixed(12));
}

function requestBodyIsValidFreeze(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "freeze") return false;

  if (!isNonEmptyString(body.freezeId)) return false;
  if (Buffer.byteLength(body.freezeId, "utf8") > 128) return false;

  if (!isNonEmptyString(body.calibrationDigest)) return false;
  if (!isNonEmptyString(body.tokenizerDigest)) return false;

  if (!uniqueStrings(body.allowedUnsupportedReasons)) return false;

  // IMPORTANT: empty candidates is globally invalid.
  if (!Array.isArray(body.candidates) || body.candidates.length === 0) {
    return false;
  }

  return true;
}

function processFreeze(body) {
  if (!requestBodyIsValidFreeze(body)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  const candidateNames = new Set();

  for (const c of body.candidates) {
    if (!isObject(c)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    if (!isNonEmptyString(c.name) || candidateNames.has(c.name)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    candidateNames.add(c.name);

    if (!isObject(c.files) || Object.keys(c.files).length === 0) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    for (const filename of Object.keys(c.files)) {
      if (!isNonEmptyString(filename) || typeof c.files[filename] !== "string") {
        return {
          status: 400,
          body: { error: "INVALID_INPUT" }
        };
      }
    }
  }

  /*
   * Important:
   * Validate the complete freeze request BEFORE reserving freezeId.
   */
  const resultCandidates = [];

  for (const c of body.candidates) {
    const codes = [];

    const manifest = makeInventory(c.files);

    if (!manifest) {
      codes.push("INVALID_INPUT");
    }

    const hasReason =
      c.unsupportedReason !== undefined &&
      c.unsupportedReason !== null &&
      c.unsupportedReason !== "";

    if (hasReason && typeof c.unsupportedReason !== "string") {
      codes.push("INVALID_INPUT");
    }

    if (hasReason) {
      if (!body.allowedUnsupportedReasons.includes(c.unsupportedReason)) {
        codes.push("UNALLOWED_UNSUPPORTED_REASON");
      }
    }

    if (c.loadable !== true && c.loadable !== false) {
      codes.push("INVALID_INPUT");
    }

    if (!isNonEmptyString(c.calibrationDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (!isNonEmptyString(c.tokenizerDigest)) {
      codes.push("INVALID_INPUT");
    }

    if (
      isNonEmptyString(c.calibrationDigest) &&
      c.calibrationDigest !== body.calibrationDigest
    ) {
      codes.push("CALIBRATION_MISMATCH");
    }

    if (
      isNonEmptyString(c.tokenizerDigest) &&
      c.tokenizerDigest !== body.tokenizerDigest
    ) {
      codes.push("TOKENIZER_MISMATCH");
    }

    /*
     * An unsupportedReason makes the candidate unsupported only if
     * that reason is explicitly allowed.
     */
    const allowedUnsupported =
      hasReason &&
      typeof c.unsupportedReason === "string" &&
      body.allowedUnsupportedReasons.includes(c.unsupportedReason);

    if (!hasReason && c.loadable === false) {
      codes.push("NOT_LOADABLE");
    }

    if (hasReason && !allowedUnsupported) {
      // Already captured by UNALLOWED_UNSUPPORTED_REASON.
    }

    /*
     * Any reason makes status invalid.
     */
    if (codes.length > 0) {
      resultCandidates.push(
        invalidFreezeCandidate(
          c.name,
          codes,
          manifest
        )
      );
      continue;
    }

    if (allowedUnsupported) {
      resultCandidates.push({
        name: c.name,
        status: "unsupported",
        inventory: manifest.inventory,
        totalBytes: manifest.totalBytes,
        packageDigest: manifest.packageDigest,
        reasonCodes: []
      });
    } else {
      resultCandidates.push({
        name: c.name,
        status: "frozen",
        inventory: manifest.inventory,
        totalBytes: manifest.totalBytes,
        packageDigest: manifest.packageDigest,
        reasonCodes: []
      });
    }
  }

  resultCandidates.sort((a, b) => utf8Compare(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates: resultCandidates
  };

  /*
   * Only reserve freezeId AFTER complete validation.
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
      body: { error: "FREEZE_ID_CONFLICT" }
    };
  }

  freezes.set(body.freezeId, {
    request: body,
    response
  });

  return {
    status: 200,
    body: response
  };
}

function validatePolicy(policy) {
  if (!isObject(policy)) return false;

  if (!safeNumber(policy.maxBytes)) return false;
  if (policy.maxBytes < 0) return false;

  if (!finiteFloor(policy.aggregateFloor)) return false;

  if (!isObject(policy.requiredSlices)) return false;

  for (const slice of Object.keys(policy.requiredSlices)) {
    if (!isNonEmptyString(slice)) return false;
    if (!finiteFloor(policy.requiredSlices[slice])) return false;
  }

  if (!nonNegativeFinite(policy.maxLatencyMs)) return false;

  if (!uniqueStrings(policy.candidateOrder)) return false;

  return true;
}

function processSelect(body) {
  if (!isObject(body)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  if (body.phase !== "select") {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  if (!isNonEmptyString(body.freezeId)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  /*
   * Required by the specification:
   * candidates and rows MUST be arrays.
   * policy MUST be an object.
   */
  if (!Array.isArray(body.candidates)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  if (!Array.isArray(body.rows)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  if (!isObject(body.policy)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  const stored = freezes.get(body.freezeId);

  if (!stored) {
    return {
      status: 200,
      body: {
        freezeId: body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  /*
   * Candidate array must exactly equal the frozen response.
   */
  if (!deepEqual(body.candidates, stored.response.candidates)) {
    return {
      status: 200,
      body: {
        freezeId: body.freezeId,
        selected: null,
        results: [],
        packageManifest: null
      }
    };
  }

  const policyValid = validatePolicy(body.policy);

  const storedNames = stored.response.candidates.map(x => x.name);
  const orderNames = body.policy.candidateOrder || [];

  const storedSet = new Set(storedNames);
  const orderSet = new Set(orderNames);

  let candidateSetValid =
    storedNames.length === orderNames.length;

  if (candidateSetValid) {
    for (const n of storedNames) {
      if (!orderSet.has(n)) {
        candidateSetValid = false;
        break;
      }
    }
  }

  /*
   * Latencies must be an object.
   */
  const latenciesValid = isObject(body.latencies);

  /*
   * Validate rows structurally.
   */
  let rowsValid = true;

  for (const row of body.rows) {
    if (!isObject(row)) {
      rowsValid = false;
      break;
    }

    if (!Object.prototype.hasOwnProperty.call(row, "label")) {
      rowsValid = false;
      break;
    }

    if (!isNonEmptyString(row.slice)) {
      rowsValid = false;
      break;
    }

    if (!isObject(row.predictions)) {
      rowsValid = false;
      break;
    }
  }

  const globallyInvalidPolicy =
    !policyValid ||
    !candidateSetValid ||
    !latenciesValid ||
    !rowsValid;

  const results = [];

  for (const candidate of stored.response.candidates) {
    const codes = [];

    /*
     * Validate manifest from STORED freeze data.
     * Do NOT trust submitted totalBytes.
     */
    let computedManifest = null;

    const storedInventory = candidate.inventory;

    if (!Array.isArray(storedInventory)) {
      codes.push("INVALID_MANIFEST");
    } else {
      const rebuilt = [];

      let inventoryValid = true;

      for (const item of storedInventory) {
        if (!isObject(item)) {
          inventoryValid = false;
          break;
        }

        if (!isNonEmptyString(item.name)) {
          inventoryValid = false;
          break;
        }

        if (!safeNumber(item.bytes) || item.bytes < 0) {
          inventoryValid = false;
          break;
        }

        if (
          typeof item.sha256 !== "string" ||
          !/^[0-9a-f]{64}$/.test(item.sha256)
        ) {
          inventoryValid = false;
          break;
        }

        // Explicit key-order reconstruction.
        rebuilt.push({
          name: item.name,
          bytes: item.bytes,
          sha256: item.sha256
        });
      }

      if (!inventoryValid) {
        codes.push("INVALID_MANIFEST");
      } else {
        rebuilt.sort((a, b) => utf8Compare(a.name, b.name));

        let total = 0;
        for (const item of rebuilt) {
          total += item.bytes;
        }

        const digest = sha256(
          Buffer.from(JSON.stringify(rebuilt), "utf8")
        );

        /*
         * Verify digest and stored total.
         */
        if (
          candidate.packageDigest !== digest ||
          candidate.totalBytes !== total
        ) {
          codes.push("INVALID_MANIFEST");
        } else {
          computedManifest = {
            inventory: rebuilt,
            totalBytes: total,
            packageDigest: digest
          };
        }
      }
    }

    /*
     * Lineage is represented by a valid frozen candidate.
     */
    if (candidate.status !== "frozen") {
      codes.push("INVALID_LINEAGE");
    }

    /*
     * Predictions.
     */
    let predictionsValid = true;

    const aggregateValues = [];

    for (const row of body.rows) {
      const pred = row.predictions[candidate.name];

      if (!validBinaryPrediction(pred)) {
        predictionsValid = false;
        break;
      }

      aggregateValues.push(pred === row.label ? 1 : 0);
    }

    let aggregate = null;
    let slices = {};

    if (predictionsValid) {
      if (aggregateValues.length === 0) {
        aggregate = null;
      } else {
        const sum = aggregateValues.reduce((a, b) => a + b, 0);
        aggregate = rounded12(sum / aggregateValues.length);
      }

      /*
       * Required slices.
       */
      for (const sliceName of Object.keys(body.policy.requiredSlices || {})) {
        const sliceRows = body.rows.filter(
          r => r.slice === sliceName
        );

        if (sliceRows.length === 0) {
          codes.push(`MISSING_SLICE:${sliceName}`);
          slices[sliceName] = null;
        } else {
          let correct = 0;

          for (const row of sliceRows) {
            const pred = row.predictions[candidate.name];

            if (!validBinaryPrediction(pred)) {
              predictionsValid = false;
              break;
            }

            if (pred === row.label) correct++;
          }

          if (!predictionsValid) {
            slices[sliceName] = null;
          } else {
            slices[sliceName] = rounded12(
              correct / sliceRows.length
            );
          }
        }
      }
    }

    if (!predictionsValid) {
      aggregate = null;

      /*
       * Specification requires null prediction metrics.
       */
      for (const sliceName of Object.keys(body.policy.requiredSlices || {})) {
        slices[sliceName] = null;
      }

      codes.push("INVALID_PREDICTIONS");
    }

    /*
     * Constraint checks only if values are valid.
     */
    if (policyValid) {
      if (
        predictionsValid &&
        aggregate !== null &&
        aggregate < body.policy.aggregateFloor
      ) {
        codes.push("AGGREGATE_FLOOR");
      }

      if (predictionsValid) {
        for (const sliceName of Object.keys(body.policy.requiredSlices)) {
          const value = slices[sliceName];

          if (value === null || value === undefined) {
            if (!codes.includes(`MISSING_SLICE:${sliceName}`)) {
              codes.push(`MISSING_SLICE:${sliceName}`);
            }
          } else if (
            value < body.policy.requiredSlices[sliceName]
          ) {
            codes.push(`SLICE_FLOOR:${sliceName}`);
          }
        }
      }
    }

    /*
     * Size.
     */
    let totalBytes = null;

    if (computedManifest) {
      totalBytes = computedManifest.totalBytes;

      if (
        policyValid &&
        totalBytes > body.policy.maxBytes
      ) {
        codes.push("SIZE_LIMIT");
      }
    }

    /*
     * Latency.
     */
    let latencyMs = null;

    if (
      latenciesValid &&
      Object.prototype.hasOwnProperty.call(
        body.latencies,
        candidate.name
      ) &&
      nonNegativeFinite(body.latencies[candidate.name])
    ) {
      latencyMs = body.latencies[candidate.name];

      if (
        policyValid &&
        latencyMs > body.policy.maxLatencyMs
      ) {
        codes.push("LATENCY_LIMIT");
      }
    } else {
      codes.push("LATENCY_LIMIT");
    }

    if (globallyInvalidPolicy) {
      codes.push("INVALID_POLICY");
    }

    /*
     * If the submitted candidate array does not match the frozen
     * candidate array, lineage is invalid.
     */
    if (!deepEqual(body.candidates, stored.response.candidates)) {
      codes.push("INVALID_LINEAGE");
    }

    const finalCodes = sortCodes(codes);

    const admitted =
      !globallyInvalidPolicy &&
      finalCodes.length === 0 &&
      candidate.status === "frozen" &&
      computedManifest !== null &&
      predictionsValid &&
      aggregate !== null &&
      totalBytes !== null &&
      latencyMs !== null;

    results.push({
      name: candidate.name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: finalCodes
    });
  }

  /*
   * Result order = candidateOrder, UTF-8 fallback.
   */
  results.sort((a, b) => {
    const ai = orderNames.indexOf(a.name);
    const bi = orderNames.indexOf(b.name);

    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;

    return utf8Compare(a.name, b.name);
  });

  /*
   * Select admitted:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidateOrder
   */
  const admitted = results.filter(x => x.admitted);

  admitted.sort((a, b) => {
    if (a.totalBytes !== b.totalBytes) {
      return a.totalBytes - b.totalBytes;
    }

    if (a.latencyMs !== b.latencyMs) {
      return a.latencyMs - b.latencyMs;
    }

    const ai = orderNames.indexOf(a.name);
    const bi = orderNames.indexOf(b.name);

    if (ai !== -1 && bi !== -1) {
      return ai - bi;
    }

    return utf8Compare(a.name, b.name);
  });

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    selected = admitted[0].name;

    const winner = stored.response.candidates.find(
      x => x.name === selected
    );

    /*
     * EXACT recorded winner object.
     */
    packageManifest = winner;
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

function send(res, status, body) {
  const text = JSON.stringify(body);

  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(text)
  });

  res.end(text);
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/") {
    return send(res, 200, {
      service: "quantize-admission-api",
      status: "ok"
    });
  }

  if (req.method === "GET" && req.url === "/health") {
    return send(res, 200, { status: "ok" });
  }

  if (req.method !== "POST" || req.url !== "/quantize") {
    return send(res, 404, { error: "NOT_FOUND" });
  }

  let raw = "";

  req.on("data", chunk => {
    raw += chunk.toString();
  });

  req.on("end", () => {
    let body;

    try {
      body = JSON.parse(raw);
    } catch {
      return send(res, 400, { error: "INVALID_INPUT" });
    }

    let result;

    try {
      if (body && body.phase === "freeze") {
        result = processFreeze(body);
      } else if (body && body.phase === "select") {
        result = processSelect(body);
      } else {
        result = {
          status: 400,
          body: { error: "INVALID_INPUT" }
        };
      }
    } catch (err) {
      console.error("quantize error:", err);

      result = {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    send(res, result.status, result.body);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Quantize service listening on ${PORT}`);
});
