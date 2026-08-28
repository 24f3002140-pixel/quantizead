const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT) || 10000;
const freezes = new Map();

const FREEZE_CODES = [
  "INVALID_INPUT",
  "UNALLOWED_UNSUPPORTED_REASON",
  "NOT_LOADABLE",
  "CALIBRATION_MISMATCH",
  "TOKENIZER_MISMATCH"
];

const SELECT_CODES = [
  "NOT_FROZEN",
  "INVALID_LINEAGE",
  "INVALID_POLICY",
  "INVALID_PREDICTIONS",
  "INVALID_MANIFEST",
  "AGGREGATE_FLOOR",
  "SIZE_LIMIT",
  "LATENCY_LIMIT"
];

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
    if (!nonEmptyString(x) || seen.has(x)) return false;
    seen.add(x);
  }

  return true;
}

function safeInteger(v) {
  return (
    typeof v === "number" &&
    Number.isSafeInteger(v)
  );
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

function sha256(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function deepEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function binaryPrediction(v) {
  return (
    typeof v === "number" &&
    Number.isInteger(v) &&
    (v === 0 || v === 1)
  );
}

function round12(v) {
  return Number(v.toFixed(12));
}

/* -------------------------------------------------------
   MANIFEST
------------------------------------------------------- */

function buildManifest(files) {
  if (!isObject(files)) return null;

  const names = Object.keys(files);

  if (names.length === 0) return null;

  for (const name of names) {
    if (!nonEmptyString(name)) return null;
    if (typeof files[name] !== "string") return null;
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

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return null;
    }
  }

  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
  );

  return {
    inventory,
    totalBytes,
    packageDigest
  };
}

function validateStoredManifest(candidate) {
  if (!isObject(candidate)) return null;

  if (!Array.isArray(candidate.inventory)) {
    return null;
  }

  const inventory = [];
  const seen = new Set();

  for (const item of candidate.inventory) {
    if (!isObject(item)) return null;

    if (!nonEmptyString(item.name)) return null;

    if (seen.has(item.name)) return null;
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

  inventory.sort((a, b) => utf8Compare(a.name, b.name));

  let totalBytes = 0;

  for (const item of inventory) {
    totalBytes += item.bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return null;
    }
  }

  if (!nonNegativeSafeInteger(candidate.totalBytes)) {
    return null;
  }

  if (candidate.totalBytes !== totalBytes) {
    return null;
  }

  const digest = sha256(
    Buffer.from(JSON.stringify(inventory), "utf8")
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

/* -------------------------------------------------------
   FREEZE
------------------------------------------------------- */

function validFreezeEnvelope(body) {
  if (!isObject(body)) return false;

  if (body.phase !== "freeze") return false;

  if (!nonEmptyString(body.freezeId)) return false;

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

function freeze(body) {
  if (!validFreezeEnvelope(body)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

  const names = new Set();

  /*
   * IMPORTANT:
   * Validate the entire request BEFORE reserving freezeId.
   */
  for (const c of body.candidates) {
    if (!isObject(c)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    if (!nonEmptyString(c.name) || names.has(c.name)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    names.add(c.name);

    if (!isObject(c.files) || Object.keys(c.files).length === 0) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    for (const filename of Object.keys(c.files)) {
      if (
        !nonEmptyString(filename) ||
        typeof c.files[filename] !== "string"
      ) {
        return {
          status: 400,
          body: { error: "INVALID_INPUT" }
        };
      }
    }

    if (c.loadable !== true && c.loadable !== false) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    if (!nonEmptyString(c.calibrationDigest)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    if (!nonEmptyString(c.tokenizerDigest)) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }

    if (
      c.unsupportedReason !== undefined &&
      c.unsupportedReason !== null &&
      typeof c.unsupportedReason !== "string"
    ) {
      return {
        status: 400,
        body: { error: "INVALID_INPUT" }
      };
    }
  }

  const resultCandidates = [];

  for (const c of body.candidates) {
    const codes = [];
    const manifest = buildManifest(c.files);

    if (!manifest) {
      codes.push("INVALID_INPUT");
    }

    const hasReason =
      typeof c.unsupportedReason === "string" &&
      c.unsupportedReason.length > 0;

    const allowedReason =
      hasReason &&
      body.allowedUnsupportedReasons.includes(
        c.unsupportedReason
      );

    if (hasReason && !allowedReason) {
      codes.push("UNALLOWED_UNSUPPORTED_REASON");
    }

    if (!hasReason && c.loadable === false) {
      codes.push("NOT_LOADABLE");
    }

    if (
      c.calibrationDigest !== body.calibrationDigest
    ) {
      codes.push("CALIBRATION_MISMATCH");
    }

    if (
      c.tokenizerDigest !== body.tokenizerDigest
    ) {
      codes.push("TOKENIZER_MISMATCH");
    }

    if (codes.length > 0) {
      resultCandidates.push({
        name: c.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortCodes(codes)
      });

      continue;
    }

    if (allowedReason) {
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

  resultCandidates.sort((a, b) =>
    utf8Compare(a.name, b.name)
  );

  const response = {
    freezeId: body.freezeId,
    candidates: resultCandidates
  };

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

  freezes.set(body.freezeId, {
    request: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response))
  });

  return {
    status: 200,
    body: response
  };
}

/* -------------------------------------------------------
   SELECT VALIDATION
------------------------------------------------------- */

function validPolicy(policy) {
  if (!isObject(policy)) return false;

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
    if (!nonEmptyString(name)) return false;

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

function select(body) {
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

  if (!nonEmptyString(body.freezeId)) {
    return {
      status: 400,
      body: { error: "INVALID_INPUT" }
    };
  }

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

  const candidateLineageValid = deepEqual(
    body.candidates,
    stored.response.candidates
  );

  const policyValid = validPolicy(body.policy);

  const storedNames =
    stored.response.candidates.map(c => c.name);

  const orderNames =
    body.policy.candidateOrder;

  let candidateSetValid = true;

  if (storedNames.length !== orderNames.length) {
    candidateSetValid = false;
  } else {
    const a = new Set(storedNames);
    const b = new Set(orderNames);

    if (a.size !== b.size) {
      candidateSetValid = false;
    }

    for (const name of a) {
      if (!b.has(name)) {
        candidateSetValid = false;
        break;
      }
    }
  }

  const latenciesValid = isObject(body.latencies);

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

    if (!nonEmptyString(row.slice)) {
      rowsValid = false;
      break;
    }

    if (!isObject(row.predictions)) {
      rowsValid = false;
      break;
    }
  }

  const globallyInvalid =
    !candidateLineageValid ||
    !policyValid ||
    !candidateSetValid ||
    !latenciesValid ||
    !rowsValid;

  const results = [];

  for (const candidate of stored.response.candidates) {
    const codes = [];

    /* -----------------------------
       Manifest
    ----------------------------- */

    const manifest =
      validateStoredManifest(candidate);

    if (!manifest) {
      codes.push("INVALID_MANIFEST");
    }

    /* -----------------------------
       Lineage
    ----------------------------- */

    if (
      !candidateLineageValid ||
      candidate.status !== "frozen"
    ) {
      codes.push("INVALID_LINEAGE");
    }

    /* -----------------------------
       Predictions
    ----------------------------- */

    let predictionsValid = true;

    const correct = [];

    for (const row of body.rows) {
      if (
        !Object.prototype.hasOwnProperty.call(
          row.predictions,
          candidate.name
        )
      ) {
        predictionsValid = false;
        break;
      }

      const p =
        row.predictions[candidate.name];

      if (!binaryPrediction(p)) {
        predictionsValid = false;
        break;
      }

      if (p === row.label) {
        correct.push(1);
      } else {
        correct.push(0);
      }
    }

    let aggregate = null;
    const slices = {};

    if (predictionsValid && body.rows.length > 0) {
      aggregate = round12(
        correct.reduce((a, b) => a + b, 0) /
        correct.length
      );

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        const sliceRows =
          body.rows.filter(
            r => r.slice === sliceName
          );

        if (sliceRows.length === 0) {
          slices[sliceName] = null;
          codes.push(`MISSING_SLICE:${sliceName}`);
          continue;
        }

        let sliceCorrect = 0;

        for (const row of sliceRows) {
          const p =
            row.predictions[candidate.name];

          if (!binaryPrediction(p)) {
            predictionsValid = false;
            break;
          }

          if (p === row.label) {
            sliceCorrect++;
          }
        }

        if (!predictionsValid) {
          slices[sliceName] = null;
        } else {
          slices[sliceName] =
            round12(
              sliceCorrect / sliceRows.length
            );
        }
      }
    }

    if (!predictionsValid) {
      aggregate = null;

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        slices[sliceName] = null;
      }

      codes.push("INVALID_PREDICTIONS");
    }

    /* -----------------------------
       Accuracy constraints
    ----------------------------- */

    if (policyValid && predictionsValid) {
      if (
        aggregate !== null &&
        aggregate < body.policy.aggregateFloor
      ) {
        codes.push("AGGREGATE_FLOOR");
      }

      for (const sliceName of Object.keys(
        body.policy.requiredSlices
      )) {
        const value = slices[sliceName];

        if (value === null) {
          if (
            !codes.includes(
              `MISSING_SLICE:${sliceName}`
            )
          ) {
            codes.push(
              `MISSING_SLICE:${sliceName}`
            );
          }
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

    /* -----------------------------
       Size
    ----------------------------- */

    let totalBytes = null;

    if (manifest) {
      totalBytes = manifest.totalBytes;

      if (
        policyValid &&
        totalBytes > body.policy.maxBytes
      ) {
        codes.push("SIZE_LIMIT");
      }
    }

    /* -----------------------------
       Latency
    ----------------------------- */

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
        latencyMs > body.policy.maxLatencyMs
      ) {
        codes.push("LATENCY_LIMIT");
      }
    } else {
      codes.push("LATENCY_LIMIT");
    }

    if (globallyInvalid) {
      codes.push("INVALID_POLICY");
    }

    const reasonCodes = sortCodes(codes);

    const admitted =
      reasonCodes.length === 0 &&
      candidate.status === "frozen" &&
      manifest !== null &&
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
      reasonCodes
    });
  }

  /* -----------------------------
     Result ordering
  ----------------------------- */

  results.sort((a, b) => {
    const ai = orderNames.indexOf(a.name);
    const bi = orderNames.indexOf(b.name);

    if (ai !== -1 && bi !== -1) {
      return ai - bi;
    }

    if (ai !== -1) return -1;
    if (bi !== -1) return 1;

    return utf8Compare(a.name, b.name);
  });

  /* -----------------------------
     Winner
  ----------------------------- */

  const admitted =
    results.filter(r => r.admitted);

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

    packageManifest =
      stored.response.candidates.find(
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

/* -------------------------------------------------------
   HTTP
------------------------------------------------------- */

function send(res, status, body) {
  const text = JSON.stringify(body);

  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length":
      Buffer.byteLength(text, "utf8")
  });

  res.end(text);
}

const server = http.createServer(
  (req, res) => {

    if (
      req.method === "GET" &&
      req.url === "/"
    ) {
      return send(res, 200, {
        service: "quantize-admission-api",
        status: "ok"
      });
    }

    if (
      req.method === "GET" &&
      req.url === "/health"
    ) {
      return send(res, 200, {
        status: "ok"
      });
    }

    if (
      req.method !== "POST" ||
      req.url !== "/quantize"
    ) {
      return send(res, 404, {
        error: "NOT_FOUND"
      });
    }

    let raw = "";

    req.on("data", chunk => {
      raw += chunk.toString("utf8");

      /*
       * Prevent absurd request sizes.
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
        return send(res, 400, {
          error: "INVALID_INPUT"
        });
      }

      let result;

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

      send(
        res,
        result.status,
        result.body
      );
    });
  }
);

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Quantize service listening on ${PORT}`
    );
  }
);
