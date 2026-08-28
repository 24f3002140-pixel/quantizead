const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '50mb' }));

// One process / one Render instance is required because state is in memory.
const freezeStore = new Map();

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function nonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function compactJson(obj) {
  return JSON.stringify(obj);
}

function sortCodes(codes) {
  return [...new Set(codes)].sort(utf8Compare);
}

function invalid(res) {
  return res.status(400).json({ error: 'INVALID_INPUT' });
}

function finiteNonNegative(v) {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0;
}

function safeNonNegativeInteger(v) {
  return (
    typeof v === 'number' &&
    Number.isSafeInteger(v) &&
    v >= 0
  );
}

function floorValue(v) {
  return (
    typeof v === 'number' &&
    Number.isFinite(v) &&
    v >= 0 &&
    v <= 1
  );
}

function binary(v) {
  return (
    typeof v === 'number' &&
    Number.isInteger(v) &&
    (v === 0 || v === 1)
  );
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;

  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  if (typeof a === 'object') {
    if (Array.isArray(b)) return false;
    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();
    if (ak.length !== bk.length) return false;
    for (let i = 0; i < ak.length; i++) {
      if (ak[i] !== bk[i]) return false;
      if (!deepEqual(a[ak[i]], b[bk[i]])) return false;
    }
    return true;
  }

  return false;
}

// ------------------------------------------------------------
// FREEZE VALIDATION
// ------------------------------------------------------------

function validFiles(files) {
  if (!isPlainObject(files)) return false;
  const names = Object.keys(files);
  if (names.length === 0) return false;
  for (const name of names) {
    if (!nonEmptyString(name)) return false;
    if (typeof files[name] !== 'string') return false;
  }
  return true;
}

function validFreezeRequest(body) {
  if (!isPlainObject(body)) return false;
  if (body.phase !== 'freeze') return false;

  if (!nonEmptyString(body.freezeId) || body.freezeId.length > 128) return false;
  if (!nonEmptyString(body.calibrationDigest)) return false;
  if (!nonEmptyString(body.tokenizerDigest)) return false;

  if (!Array.isArray(body.allowedUnsupportedReasons)) return false;
  const reasons = new Set();
  for (const r of body.allowedUnsupportedReasons) {
    if (!nonEmptyString(r) || reasons.has(r)) return false;
    reasons.add(r);
  }

  // Empty/non-array freeze candidate list is explicitly INVALID_INPUT.
  if (!Array.isArray(body.candidates) || body.candidates.length === 0) return false;

  const names = new Set();

  for (const c of body.candidates) {
    if (!isPlainObject(c)) return false;

    if (!nonEmptyString(c.name) || names.has(c.name)) return false;
    names.add(c.name);

    if (!validFiles(c.files)) return false;

    // Required candidate construction fields.
    if (typeof c.loadable !== 'boolean') return false;
    if (!nonEmptyString(c.calibrationDigest)) return false;
    if (!nonEmptyString(c.tokenizerDigest)) return false;

    // unsupportedReason is optional. If supplied, it must be a non-empty string.
    if (Object.prototype.hasOwnProperty.call(c, 'unsupportedReason')) {
      if (!nonEmptyString(c.unsupportedReason)) return false;
    }
  }

  return true;
}

function buildInventory(files) {
  const inventory = Object.keys(files)
    .sort(utf8Compare)
    .map((name) => {
      const bytes = Buffer.from(files[name], 'utf8');
      return {
        name,
        bytes: bytes.length,
        sha256: sha256(bytes),
      };
    });

  const totalBytes = inventory.reduce((n, x) => n + x.bytes, 0);
  const packageDigest = sha256(Buffer.from(compactJson(inventory), 'utf8'));

  return { inventory, totalBytes, packageDigest };
}

function makeFrozenCandidate(c, body) {
  const { inventory, totalBytes, packageDigest } = buildInventory(c.files);
  const codes = [];

  if (Object.prototype.hasOwnProperty.call(c, 'unsupportedReason')) {
    if (body.allowedUnsupportedReasons.includes(c.unsupportedReason)) {
      return {
        name: c.name,
        status: 'unsupported',
        inventory,
        totalBytes,
        packageDigest,
        reasonCodes: [],
      };
    }

    return {
      name: c.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: ['UNALLOWED_UNSUPPORTED_REASON'],
    };
  }

  if (c.loadable !== true) codes.push('NOT_LOADABLE');
  if (c.calibrationDigest !== body.calibrationDigest) codes.push('CALIBRATION_MISMATCH');
  if (c.tokenizerDigest !== body.tokenizerDigest) codes.push('TOKENIZER_MISMATCH');

  if (codes.length) {
    // Candidate has valid files, so preserve the computed inventory.
    return {
      name: c.name,
      status: 'invalid',
      inventory,
      totalBytes,
      packageDigest,
      reasonCodes: sortCodes(codes),
    };
  }

  return {
    name: c.name,
    status: 'frozen',
    inventory,
    totalBytes,
    packageDigest,
    reasonCodes: [],
  };
}

function handleFreeze(body, res) {
  // Validate BEFORE reserving freezeId.
  if (!validFreezeRequest(body)) return invalid(res);

  const existing = freezeStore.get(body.freezeId);

  if (existing) {
    if (deepEqual(existing.input, body)) {
      // Identical replay: return exact stored response.
      return res.status(200).json(existing.response);
    }
    return res.status(409).json({ error: 'FREEZE_ID_CONFLICT' });
  }

  const candidates = body.candidates
    .map((c) => makeFrozenCandidate(c, body))
    .sort((a, b) => utf8Compare(a.name, b.name));

  const response = {
    freezeId: body.freezeId,
    candidates,
  };

  freezeStore.set(body.freezeId, {
    input: JSON.parse(JSON.stringify(body)),
    response: JSON.parse(JSON.stringify(response)),
  });

  return res.status(200).json(response);
}

// ------------------------------------------------------------
// SELECT VALIDATION
// ------------------------------------------------------------

function selectShapeValid(body) {
  return (
    isPlainObject(body) &&
    Array.isArray(body.candidates) &&
    Array.isArray(body.rows) &&
    isPlainObject(body.policy)
  );
}

function policyValid(policy, candidateNames) {
  if (!safeNonNegativeInteger(policy.maxBytes)) return false;
  if (!floorValue(policy.aggregateFloor)) return false;
  if (!isPlainObject(policy.requiredSlices)) return false;
  if (!finiteNonNegative(policy.maxLatencyMs)) return false;
  if (!Array.isArray(policy.candidateOrder)) return false;

  const orderSet = new Set();
  for (const n of policy.candidateOrder) {
    if (!nonEmptyString(n) || orderSet.has(n)) return false;
    orderSet.add(n);
  }

  for (const slice of Object.keys(policy.requiredSlices)) {
    if (!nonEmptyString(slice)) return false;
    if (!floorValue(policy.requiredSlices[slice])) return false;
  }

  if (orderSet.size !== candidateNames.size) return false;
  for (const n of candidateNames) {
    if (!orderSet.has(n)) return false;
  }

  return true;
}

function validateManifest(c) {
  if (!isPlainObject(c)) return false;
  if (!Array.isArray(c.inventory)) return false;

  const seen = new Set();

  for (const item of c.inventory) {
    if (!isPlainObject(item)) return false;
    if (Object.keys(item).length !== 3) return false;
    if (!Object.prototype.hasOwnProperty.call(item, 'name')) return false;
    if (!Object.prototype.hasOwnProperty.call(item, 'bytes')) return false;
    if (!Object.prototype.hasOwnProperty.call(item, 'sha256')) return false;

    if (!nonEmptyString(item.name)) return false;
    if (seen.has(item.name)) return false;
    seen.add(item.name);

    if (!safeNonNegativeInteger(item.bytes)) return false;
    if (typeof item.sha256 !== 'string') return false;
    if (!/^[0-9a-f]{64}$/.test(item.sha256)) return false;
  }

  const sorted = [...c.inventory].sort((a, b) => utf8Compare(a.name, b.name));
  if (!deepEqual(sorted, c.inventory)) return false;

  const total = c.inventory.reduce((n, x) => n + x.bytes, 0);
  if (c.totalBytes !== total) return false;

  const digest = sha256(Buffer.from(compactJson(c.inventory), 'utf8'));
  if (c.packageDigest !== digest) return false;

  return true;
}

function latencyValue(latencies, name) {
  if (!isPlainObject(latencies)) return null;
  const value = latencies[name];
  if (!finiteNonNegative(value)) return null;
  return value;
}

function evaluatePredictions(name, rows, requiredSlices) {
  let valid = true;

  for (const row of rows) {
    if (!isPlainObject(row)) {
      valid = false;
      break;
    }

    if (!binary(row.label)) {
      valid = false;
      break;
    }

    if (!nonEmptyString(row.slice)) {
      valid = false;
      break;
    }

    if (!isPlainObject(row.predictions)) {
      valid = false;
      break;
    }

    if (!binary(row.predictions[name])) {
      valid = false;
      break;
    }
  }

  if (!valid) {
    const nullSlices = {};
    for (const s of Object.keys(requiredSlices)) nullSlices[s] = null;
    return {
      valid: false,
      aggregate: null,
      slices: nullSlices,
    };
  }

  // No rows means there is no measurable accuracy.
  if (rows.length === 0) {
    const nullSlices = {};
    for (const s of Object.keys(requiredSlices)) nullSlices[s] = null;
    return {
      valid: false,
      aggregate: null,
      slices: nullSlices,
    };
  }

  let correct = 0;
  const totals = {};
  const correctBySlice = {};

  for (const row of rows) {
    const prediction = row.predictions[name];
    if (prediction === row.label) correct++;

    totals[row.slice] = (totals[row.slice] || 0) + 1;
    if (prediction === row.label) {
      correctBySlice[row.slice] = (correctBySlice[row.slice] || 0) + 1;
    }
  }

  const aggregate = Number((correct / rows.length).toFixed(12));
  const slices = {};

  for (const s of Object.keys(requiredSlices)) {
    if (!Object.prototype.hasOwnProperty.call(totals, s)) {
      slices[s] = null;
    } else {
      slices[s] = Number((correctBySlice[s] / totals[s]).toFixed(12));
    }
  }

  return { valid: true, aggregate, slices };
}

function handleSelect(body, res) {
  if (!selectShapeValid(body)) return invalid(res);

  const freezeId = body.freezeId;
  const submitted = body.candidates;
  const rows = body.rows;
  const policy = body.policy;
  const latencies = body.latencies;

  // Candidate array itself must contain objects/names for result construction.
  // If malformed, this is still an invalid policy/lineage condition at selection,
  // while the required top-level shape remains valid.
  const names = new Set();
  let namesWellFormed = true;

  for (const c of submitted) {
    if (!isPlainObject(c) || !nonEmptyString(c.name) || names.has(c.name)) {
      namesWellFormed = false;
      continue;
    }
    names.add(c.name);
  }

  const stored = freezeStore.get(freezeId);
  const storedCandidates = stored ? stored.response.candidates : null;
  const exactLineage = stored
    ? deepEqual(storedCandidates, submitted)
    : false;

  const pValid = namesWellFormed && policyValid(policy, names);

  const storedByName = new Map();
  if (stored) {
    for (const c of storedCandidates) storedByName.set(c.name, c);
  }

  const results = [];

  for (const c of submitted) {
    const name = isPlainObject(c) && typeof c.name === 'string' ? c.name : '';
    const codes = [];

    if (!stored) {
      codes.push('NOT_FROZEN');
    }

    if (!exactLineage) {
      codes.push('INVALID_LINEAGE');
    }

    if (!pValid) {
      codes.push('INVALID_POLICY');
    }

    let manifestOK = false;
    let totalBytes = null;

    if (isPlainObject(c)) {
      manifestOK = validateManifest(c);
      if (manifestOK) totalBytes = c.totalBytes;
    }

    if (!manifestOK) codes.push('INVALID_MANIFEST');

    const prediction = evaluatePredictions(
      name,
      rows,
      pValid ? policy.requiredSlices : {}
    );

    let aggregate = prediction.aggregate;
    let slices = prediction.slices;

    if (!prediction.valid) {
      codes.push('INVALID_PREDICTIONS');
    } else if (pValid) {
      if (aggregate < policy.aggregateFloor) {
        codes.push('AGGREGATE_FLOOR');
      }

      for (const sliceName of Object.keys(policy.requiredSlices)) {
        if (slices[sliceName] === null) {
          codes.push(`MISSING_SLICE:${sliceName}`);
        } else if (slices[sliceName] < policy.requiredSlices[sliceName]) {
          codes.push(`SLICE_FLOOR:${sliceName}`);
        }
      }
    }

    if (manifestOK && pValid && totalBytes > policy.maxBytes) {
      codes.push('SIZE_LIMIT');
    }

    const latency = latencyValue(latencies, name);
    if (latency === null) {
      codes.push('LATENCY_LIMIT');
    } else if (pValid && latency > policy.maxLatencyMs) {
      codes.push('LATENCY_LIMIT');
    }

    // A candidate that is not frozen cannot be admitted.
    const storedCandidate = storedByName.get(name);
    if (storedCandidate && storedCandidate.status !== 'frozen') {
      codes.push('NOT_FROZEN');
    }

    const finalCodes = sortCodes(codes);

    results.push({
      name,
      aggregate,
      slices,
      totalBytes,
      latencyMs: latency,
      admitted: finalCodes.length === 0,
      reasonCodes: finalCodes,
    });
  }

  // Required result ordering: candidateOrder, UTF-8 name fallback.
  const order = pValid ? policy.candidateOrder : [];
  const position = new Map(order.map((n, i) => [n, i]));

  results.sort((a, b) => {
    const ai = position.has(a.name) ? position.get(a.name) : Number.MAX_SAFE_INTEGER;
    const bi = position.has(b.name) ? position.get(b.name) : Number.MAX_SAFE_INTEGER;
    if (ai !== bi) return ai - bi;
    return utf8Compare(a.name, b.name);
  });

  // Winner: bytes, latency, candidateOrder.
  let selected = null;
  let packageManifest = null;

  const admitted = results.filter((r) => r.admitted);

  if (admitted.length > 0) {
    admitted.sort((a, b) => {
      if (a.totalBytes !== b.totalBytes) return a.totalBytes - b.totalBytes;
      if (a.latencyMs !== b.latencyMs) return a.latencyMs - b.latencyMs;

      const ai = position.has(a.name) ? position.get(a.name) : Number.MAX_SAFE_INTEGER;
      const bi = position.has(b.name) ? position.get(b.name) : Number.MAX_SAFE_INTEGER;
      if (ai !== bi) return ai - bi;
      return utf8Compare(a.name, b.name);
    });

    selected = admitted[0].name;
    packageManifest = storedByName.get(selected) || null;
  }

  return res.status(200).json({
    freezeId,
    selected,
    results,
    packageManifest,
  });
}

// ------------------------------------------------------------
// ROUTES
// ------------------------------------------------------------

app.post('/quantize', (req, res) => {
  const body = req.body;

  if (!isPlainObject(body)) return invalid(res);

  if (body.phase === 'freeze') {
    return handleFreeze(body, res);
  }

  if (body.phase === 'select') {
    // Explicitly required by the specification for select top-level shape.
    if (!Array.isArray(body.candidates) || !Array.isArray(body.rows) || !isPlainObject(body.policy)) {
      return invalid(res);
    }
    return handleSelect(body, res);
  }

  return invalid(res);
});

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Quantize service listening on ${PORT}`);
});
