const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "50mb" }));

const freezes = new Map();

const isObj = x =>
  x !== null && typeof x === "object" && !Array.isArray(x);

const str = x => typeof x === "string" && x.length > 0;

const utf8cmp = (a, b) =>
  Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

const sha256 = x =>
  crypto.createHash("sha256").update(x).digest("hex");

const invalid = res =>
  res.status(400).json({ error: "INVALID_INPUT" });

const codes = xs => [...new Set(xs)].sort(utf8cmp);

const finiteNN = x =>
  typeof x === "number" && Number.isFinite(x) && x >= 0;

const safeNNInt = x =>
  typeof x === "number" &&
  Number.isSafeInteger(x) &&
  x >= 0;

const floor = x =>
  typeof x === "number" &&
  Number.isFinite(x) &&
  x >= 0 &&
  x <= 1;

const binary = x =>
  typeof x === "number" && (x === 0 || x === 1);

function equal(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;

  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!equal(a[i], b[i])) return false;
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
      if (!equal(a[ak[i]], b[bk[i]])) return false;
    }

    return true;
  }

  return false;
}

function inventory(files) {
  if (!isObj(files) || Object.keys(files).length === 0)
    return null;

  const names = Object.keys(files);

  for (const n of names) {
    if (!str(n) || typeof files[n] !== "string")
      return null;
  }

  names.sort(utf8cmp);

  const inv = [];
  let total = 0;

  for (const name of names) {
    const buf = Buffer.from(files[name], "utf8");

    inv.push({
      name,
      bytes: buf.length,
      sha256: sha256(buf)
    });

    total += buf.length;
  }

  const packageDigest = sha256(
    Buffer.from(JSON.stringify(inv), "utf8")
  );

  return {
    inventory: inv,
    totalBytes: total,
    packageDigest
  };
}

/* ============================================================
   FREEZE
   ============================================================ */

function validFreezeTop(body) {
  if (!isObj(body)) return false;
  if (body.phase !== "freeze") return false;

  if (!str(body.freezeId) || body.freezeId.length > 128)
    return false;

  if (!str(body.calibrationDigest))
    return false;

  if (!str(body.tokenizerDigest))
    return false;

  if (!Array.isArray(body.allowedUnsupportedReasons))
    return false;

  const reasons = new Set();

  for (const r of body.allowedUnsupportedReasons) {
    if (!str(r) || reasons.has(r))
      return false;

    reasons.add(r);
  }

  /*
   * The assignment explicitly says:
   * empty/non-array freeze candidates => HTTP 400
   */
  if (!Array.isArray(body.candidates) ||
      body.candidates.length === 0)
    return false;

  const names = new Set();

  for (const c of body.candidates) {
    if (!isObj(c))
      return false;

    if (!str(c.name) || names.has(c.name))
      return false;

    names.add(c.name);
  }

  return true;
}

function makeFreezeCandidate(c, body) {
  const reasonCodes = [];

  /*
   * Bad files invalidate ONLY this candidate.
   * They do not invalidate the entire freeze request.
   */
  const inv = inventory(c.files);

  if (!inv) {
    return {
      name: c.name,
      status: "invalid",
      inventory: [],
      totalBytes: null,
      packageDigest: null,
      reasonCodes: ["INVALID_INPUT"]
    };
  }

  /*
   * unsupportedReason takes precedence.
   */
  if (Object.prototype.hasOwnProperty.call(c, "unsupportedReason")) {
    if (!str(c.unsupportedReason)) {
      return {
        name: c.name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      };
    }

    if (body.allowedUnsupportedReasons.includes(c.unsupportedReason)) {
      return {
        name: c.name,
        status: "unsupported",
        inventory: inv.inventory,
        totalBytes: inv.totalBytes,
        packageDigest: inv.packageDigest,
        reasonCodes: []
      };
    }

    return {
      name: c.name,
      status: "invalid",
      inventory: inv.inventory,
      totalBytes: inv.totalBytes,
      packageDigest: inv.packageDigest,
      reasonCodes: ["UNALLOWED_UNSUPPORTED_REASON"]
    };
  }

  /*
   * Normal candidate.
   */
  if (c.loadable !== true)
    reasonCodes.push("NOT_LOADABLE");

  if (!str(c.calibrationDigest))
    reasonCodes.push("CALIBRATION_MISMATCH");
  else if (c.calibrationDigest !== body.calibrationDigest)
    reasonCodes.push("CALIBRATION_MISMATCH");

  if (!str(c.tokenizerDigest))
    reasonCodes.push("TOKENIZER_MISMATCH");
  else if (c.tokenizerDigest !== body.tokenizerDigest)
    reasonCodes.push("TOKENIZER_MISMATCH");

  if (reasonCodes.length > 0) {
    return {
      name: c.name,
      status: "invalid",
      inventory: inv.inventory,
      totalBytes: inv.totalBytes,
      packageDigest: inv.packageDigest,
      reasonCodes: codes(reasonCodes)
    };
  }

  return {
    name: c.name,
    status: "frozen",
    inventory: inv.inventory,
    totalBytes: inv.totalBytes,
    packageDigest: inv.packageDigest,
    reasonCodes: []
  };
}

function freeze(body, res) {
  if (!validFreezeTop(body))
    return invalid(res);

  const old = freezes.get(body.freezeId);

  if (old) {
    if (equal(old.input, body))
      return res.status(200).json(old.response);

    return res.status(409).json({
      error: "FREEZE_ID_CONFLICT"
    });
  }

  const result = body.candidates
    .map(c => makeFreezeCandidate(c, body))
    .sort((a, b) => utf8cmp(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates: result
  };

  freezes.set(body.freezeId, {
    input: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response))
  });

  return res.status(200).json(response);
}

/* ============================================================
   SELECT
   ============================================================ */

function validSelectTop(body) {
  return (
    isObj(body) &&
    Array.isArray(body.candidates) &&
    Array.isArray(body.rows) &&
    isObj(body.policy)
  );
}

function validPolicy(policy, names) {
  if (!safeNNInt(policy.maxBytes))
    return false;

  if (!floor(policy.aggregateFloor))
    return false;

  if (!isObj(policy.requiredSlices))
    return false;

  for (const s of Object.keys(policy.requiredSlices)) {
    if (!str(s))
      return false;

    if (!floor(policy.requiredSlices[s]))
      return false;
  }

  if (!finiteNN(policy.maxLatencyMs))
    return false;

  if (!Array.isArray(policy.candidateOrder))
    return false;

  const order = new Set();

  for (const n of policy.candidateOrder) {
    if (!str(n) || order.has(n))
      return false;

    order.add(n);
  }

  if (order.size !== names.size)
    return false;

  for (const n of names) {
    if (!order.has(n))
      return false;
  }

  return true;
}

function checkManifest(c) {
  if (!isObj(c))
    return null;

  if (!Array.isArray(c.inventory))
    return null;

  const seen = new Set();

  for (const x of c.inventory) {
    if (!isObj(x))
      return null;

    if (
      Object.keys(x).length !== 3 ||
      !str(x.name) ||
      !safeNNInt(x.bytes) ||
      typeof x.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(x.sha256)
    ) {
      return null;
    }

    if (seen.has(x.name))
      return null;

    seen.add(x.name);
  }

  const sorted = [...c.inventory].sort((a, b) =>
    utf8cmp(a.name, b.name)
  );

  if (!equal(sorted, c.inventory))
    return null;

  const total = c.inventory.reduce(
    (a, x) => a + x.bytes,
    0
  );

  if (c.totalBytes !== total)
    return null;

  const digest = sha256(
    Buffer.from(JSON.stringify(c.inventory), "utf8")
  );

  if (c.packageDigest !== digest)
    return null;

  return {
    totalBytes: total,
    packageDigest: digest
  };
}

function evaluate(name, rows, requiredSlices) {
  if (rows.length === 0) {
    const s = {};
    for (const x of Object.keys(requiredSlices))
      s[x] = null;

    return {
      valid: false,
      aggregate: null,
      slices: s
    };
  }

  for (const row of rows) {
    if (!isObj(row))
      return badEvaluation(requiredSlices);

    if (!binary(row.label))
      return badEvaluation(requiredSlices);

    if (!str(row.slice))
      return badEvaluation(requiredSlices);

    if (!isObj(row.predictions))
      return badEvaluation(requiredSlices);

    if (!binary(row.predictions[name]))
      return badEvaluation(requiredSlices);
  }

  let correct = 0;

  const totalBySlice = {};
  const correctBySlice = {};

  for (const row of rows) {
    const p = row.predictions[name];

    if (p === row.label)
      correct++;

    totalBySlice[row.slice] =
      (totalBySlice[row.slice] || 0) + 1;

    if (p === row.label) {
      correctBySlice[row.slice] =
        (correctBySlice[row.slice] || 0) + 1;
    }
  }

  const aggregate =
    Number((correct / rows.length).toFixed(12));

  const slices = {};

  for (const s of Object.keys(requiredSlices)) {
    if (!(s in totalBySlice)) {
      slices[s] = null;
    } else {
      slices[s] =
        Number(
          (
            correctBySlice[s] /
            totalBySlice[s]
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

function badEvaluation(requiredSlices) {
  const slices = {};

  for (const s of Object.keys(requiredSlices))
    slices[s] = null;

  return {
    valid: false,
    aggregate: null,
    slices
  };
}

function select(body, res) {
  if (!validSelectTop(body))
    return invalid(res);

  const submitted = body.candidates;
  const rows = body.rows;
  const policy = body.policy;

  const stored = freezes.get(body.freezeId);

  const names = new Set();
  let namesValid = true;

  for (const c of submitted) {
    if (!isObj(c) || !str(c.name) || names.has(c.name)) {
      namesValid = false;
      continue;
    }

    names.add(c.name);
  }

  const pValid =
    namesValid &&
    validPolicy(policy, names);

  const exactLineage =
    !!stored &&
    equal(stored.response.candidates, submitted);

  const storedByName = new Map();

  if (stored) {
    for (const c of stored.response.candidates)
      storedByName.set(c.name, c);
  }

  const results = [];

  for (const c of submitted) {
    const name =
      isObj(c) && typeof c.name === "string"
        ? c.name
        : "";

    const reasonCodes = [];

    if (!stored)
      reasonCodes.push("NOT_FROZEN");

    if (!exactLineage)
      reasonCodes.push("INVALID_LINEAGE");

    if (!pValid)
      reasonCodes.push("INVALID_POLICY");

    const manifest = checkManifest(c);

    let totalBytes = null;

    if (!manifest) {
      reasonCodes.push("INVALID_MANIFEST");
    } else {
      totalBytes = manifest.totalBytes;
    }

    const ev = evaluate(
      name,
      rows,
      pValid ? policy.requiredSlices : {}
    );

    if (!ev.valid) {
      reasonCodes.push("INVALID_PREDICTIONS");
    } else if (pValid) {
      if (ev.aggregate < policy.aggregateFloor)
        reasonCodes.push("AGGREGATE_FLOOR");

      for (const s of Object.keys(policy.requiredSlices)) {
        if (ev.slices[s] === null)
          reasonCodes.push(`MISSING_SLICE:${s}`);
        else if (
          ev.slices[s] <
          policy.requiredSlices[s]
        )
          reasonCodes.push(`SLICE_FLOOR:${s}`);
      }
    }

    let latencyMs = null;

    if (
      isObj(body.latencies) &&
      finiteNN(body.latencies[name])
    ) {
      latencyMs = body.latencies[name];
    } else {
      reasonCodes.push("LATENCY_LIMIT");
    }

    if (
      pValid &&
      totalBytes !== null &&
      totalBytes > policy.maxBytes
    ) {
      reasonCodes.push("SIZE_LIMIT");
    }

    if (
      pValid &&
      latencyMs !== null &&
      latencyMs > policy.maxLatencyMs
    ) {
      reasonCodes.push("LATENCY_LIMIT");
    }

    const storedCandidate =
      storedByName.get(name);

    if (
      !storedCandidate ||
      storedCandidate.status !== "frozen"
    ) {
      reasonCodes.push("NOT_FROZEN");
    }

    const finalCodes = codes(reasonCodes);

    results.push({
      name,
      aggregate: ev.aggregate,
      slices: ev.slices,
      totalBytes,
      latencyMs,
      admitted: finalCodes.length === 0,
      reasonCodes: finalCodes
    });
  }

  /*
   * Result order:
   * candidateOrder first,
   * UTF-8 name fallback.
   */
  const order =
    pValid
      ? policy.candidateOrder
      : [];

  const pos = new Map(
    order.map((n, i) => [n, i])
  );

  results.sort((a, b) => {
    const ai = pos.has(a.name)
      ? pos.get(a.name)
      : Number.MAX_SAFE_INTEGER;

    const bi = pos.has(b.name)
      ? pos.get(b.name)
      : Number.MAX_SAFE_INTEGER;

    if (ai !== bi)
      return ai - bi;

    return utf8cmp(a.name, b.name);
  });

  /*
   * Winner:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidateOrder
   * 4. UTF-8 name
   */
  const admitted =
    results.filter(x => x.admitted);

  let selected = null;
  let packageManifest = null;

  if (admitted.length > 0) {
    admitted.sort((a, b) => {
      if (a.totalBytes !== b.totalBytes)
        return a.totalBytes - b.totalBytes;

      if (a.latencyMs !== b.latencyMs)
        return a.latencyMs - b.latencyMs;

      const ai = pos.has(a.name)
        ? pos.get(a.name)
        : Number.MAX_SAFE_INTEGER;

      const bi = pos.has(b.name)
        ? pos.get(b.name)
        : Number.MAX_SAFE_INTEGER;

      if (ai !== bi)
        return ai - bi;

      return utf8cmp(a.name, b.name);
    });

    selected = admitted[0].name;

    packageManifest =
      storedByName.get(selected) || null;
  }

  return res.status(200).json({
    freezeId: body.freezeId,
    selected,
    results,
    packageManifest
  });
}

/* ============================================================
   ROUTES
   ============================================================ */

app.post("/quantize", (req, res) => {
  if (!isObj(req.body))
    return invalid(res);

  if (req.body.phase === "freeze")
    return freeze(req.body, res);

  if (req.body.phase === "select")
    return select(req.body, res);

  return invalid(res);
});

app.get("/", (req, res) => {
  res.json({ status: "ok" });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

const PORT = process.env.PORT || 10000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Quantize service listening on ${PORT}`);
});
