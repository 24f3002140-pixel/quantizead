# quantize-service

Implements the two-phase `POST /quantize` candidate-admission API (freeze + select)
described in the spec: file inventory/hash, package digest, freeze persistence with
conflict detection, and select-time admission (lineage, manifest recompute, aggregate/
slice accuracy, size, latency).

State is kept **in memory** (a `Map` keyed by `freezeId`). That's fine for grading a
single running instance, but it means:
- Data is lost on restart/redeploy.
- It will NOT work correctly if your host runs multiple instances/replicas behind a
  load balancer, since each instance has its own memory. Use a single instance
  (e.g. Render's free/starter web service, min instances = 1, no autoscaling).

## Run locally

```bash
npm install
npm start
# listens on http://localhost:3000, endpoint at POST /quantize
```

## Deploy on Render (matches the onrender.com base URL the grader expects)

1. Push this folder to a GitHub repo.
2. In Render: New -> Web Service -> connect the repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Make sure "Instance Count" / scaling is set to a single instance (in-memory store).
6. Once deployed, your base URL will be `https://<your-service-name>.onrender.com`.
   The grader will POST to `https://<your-service-name>.onrender.com/quantize`.

## Notes on interpretation

A few points in the spec are open to interpretation; here's what this implementation
does, so you can adjust if the grader disagrees:

- **Top-level 400 `INVALID_INPUT`** is returned only for: unknown/missing `phase`;
  freeze `candidates` missing/not an array/empty; freeze candidates with duplicate or
  non-string `name`; select `candidates`/`rows` not arrays or `policy` not an object;
  freeze `freezeId`/digests missing or malformed. Everything else that can be
  attributed to a specific candidate (bad `files`, disallowed `unsupportedReason`,
  not loadable, digest mismatch, bad predictions, policy problems) is surfaced as a
  per-candidate `reasonCodes` entry instead of a blanket 400.
- **Freeze replay**: a repeat POST with the same `freezeId` is compared to the stored
  request via deep-equality (key order doesn't matter). Identical -> same response,
  200. Different -> 409 `FREEZE_ID_CONFLICT`.
- **Select lineage**: a submitted candidate is lineage-valid only if it deep-equals
  the corresponding candidate object from the stored freeze response *and* the whole
  submitted `candidates` array deep-equals the stored array (order-sensitive, since
  the freeze response itself is already sorted deterministically by name).
- **Manifest**: `totalBytes`/`packageDigest` are always recomputed from the submitted
  candidate's `inventory` (sorted by UTF-8 filename) and compared to what was
  submitted; a mismatch (or a malformed inventory) yields `INVALID_MANIFEST` and a
  `null` `totalBytes` in the result.
- **Predictions validity** requires every row to have a `0`/`1` `label`, a non-empty
  `slice`, and a `0`/`1` prediction for the candidate; any violation makes aggregate
  and all slice values `null` for that candidate.
- Reason codes are deduplicated and sorted by UTF-8 byte order before being returned.

You should run this against the actual grader and adjust any of the above if its
expectations differ — the spec has enough ambiguity (especially around exactly which
malformed-input cases are a 400 vs. a per-candidate `INVALID_INPUT`/`INVALID_POLICY`)
that some tuning against real grader feedback is likely needed.
