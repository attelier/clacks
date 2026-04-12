# Contributing to Clacks

Contributions are welcome — whether you're fixing a mapping, adding a missing concept, or improving tooling.

## What you can contribute

- **New concepts**: Vulnerability types missing from the crosswalk
- **Mapping corrections**: Wrong CWE, OWASP, VRT, or ATT&CK mappings
- **Confidence adjustments**: A mapping marked `high` that should be `medium`, or vice versa
- **Missing notes**: Low-confidence mappings that lack explanatory notes
- **Authority updates**: Newer versions of upstream data (CWE, ATT&CK, OWASP, VRT)
- **Tooling**: Improvements to `tools/healthcheck.py` or new tooling

## Crosswalk structure

The crosswalk lives in `crosswalk/` as a filesystem hierarchy. Each vulnerability concept is a directory containing a `concept.json` file.

```
crosswalk/
  injection/
    concept.json                    ← root concept
    server_side/
      concept.json                  ← mid-level concept
      sql_injection/
        concept.json                ← leaf concept
        blind/
          time_based/
            concept.json
            _techniques/            ← specifier container (no concept.json here)
              sleep_based/
                concept.json        ← specifier concept
```

**Every directory that represents a concept must have a `concept.json`.** The only directories that don't are the specifier containers themselves (`_scenarios/`, `_techniques/`, `_conditions/`, `_vectors/`, `_constraints/`). Their children, however, must each have a `concept.json`.

## concept.json schema

```json
{
  "id": "clacks/path/to/concept",
  "slug": "clacks/path/to/concept",
  "title": "Human-Readable Title",
  "aliases": [
    "alternative name",
    "another alias"
  ],
  "mappings": {
    "cwe": [
      {
        "id": "cwe/CWE-89",
        "confidence": "high",
        "note": "Optional — explain non-obvious mappings"
      }
    ],
    "owasp_top10": [
      {
        "id": "owasp/top10/2021/A03",
        "confidence": "high"
      }
    ],
    "bugcrowd_vrt": [],
    "owasp_api10": [],
    "mitre_attack": []
  },
  "kind": "specifier"
}
```

### Rules

**Required fields:** `id`, `slug`, `title`, `aliases`, `mappings`

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Must match `clacks/<path-relative-to-crosswalk>` |
| `slug` | string | Must match `id` |
| `title` | string | Human-readable, title case |
| `aliases` | array of strings | At least one entry. Include common names, abbreviations, and underscore/hyphen variants |
| `mappings` | object | At least one mapping category. Empty categories can be omitted |
| `kind` | string | Only `"specifier"` — required for concepts inside `_scenarios/`, `_techniques/`, `_conditions/`, `_vectors/`, `_constraints/` namespaces. Omit for regular concepts |

**Mapping entries:**

| Field | Required | Values |
|-------|----------|--------|
| `id` | yes | Authority-prefixed ID (e.g. `cwe/CWE-79`, `owasp/top10/2021/A03`) |
| `confidence` | yes | `"high"`, `"medium"`, or `"low"` |
| `note` | no | Explain why when confidence is medium/low, or when the mapping is an umbrella/non-obvious fit |

**Mapping categories:** `cwe`, `owasp_top10`, `bugcrowd_vrt`, `owasp_api10`, `mitre_attack`

### Confidence guidelines

- **high** — Direct, unambiguous mapping. The CWE/OWASP category was designed for this exact issue.
- **medium** — Reasonable mapping but not a perfect fit. The concept overlaps but doesn't fully align, or the authority category is broader/narrower.
- **low** — Best-effort mapping. No good fit exists in the authority; this is the closest available. Always add a note explaining why.

### When to add notes

- Any `low` confidence mapping (required by convention)
- `medium` confidence mappings where the reasoning isn't obvious
- Umbrella/parent mappings that cover a broad category ("Umbrella mapping; refine with children if possible")
- When a CWE is a proxy because no dedicated CWE exists ("No dedicated CWE for this class; CWE-74 is best-effort")
- When authorities disagree or the mapping is context-dependent

## Adding a new concept

1. Create the directory under the appropriate parent in `crosswalk/`
2. Write a `concept.json` following the schema above
3. Run the healthcheck to validate:
   ```bash
   python3 tools/healthcheck.py
   ```
4. Fix any errors before submitting

### Naming conventions

- Directory names use `snake_case`
- Keep names concise but descriptive
- Use the most widely recognized term (e.g. `xss` not `cross_site_scripting`, `ssrf` not `server_side_request_forgery`)
- If the concept already exists in Bugcrowd VRT or CWE, prefer their naming

## Specifiers

Specifiers qualify a parent concept rather than defining a new vulnerability. They live under reserved directories:

| Directory | Purpose | Example |
|-----------|---------|---------|
| `_scenarios` | Attack outcomes | `data_leak`, `account_takeover` |
| `_techniques` | How the attack is performed | `host_header_poisoning`, `parameter_cloaking` |
| `_conditions` | Preconditions | `no_auth`, `requires_auth`, `shared_cache` |
| `_vectors` | Entry points | `header`, `body_parameter`, `websocket` |
| `_constraints` | Technical constraints | `id_is_uuid`, `id_is_int`, `requires_cache_hit` |

Specifier concepts must include `"kind": "specifier"` in their `concept.json`.

## Healthcheck

Before submitting, run:

```bash
python3 tools/healthcheck.py
```

This validates:
- Every concept directory has a `concept.json`
- All files are valid JSON with the correct schema
- `id` and `slug` match the filesystem path
- Specifier concepts have `kind: "specifier"`
- Low-confidence mappings have explanatory notes

**Your PR should introduce zero new errors.** Warnings and suggestions are acceptable but should be addressed when practical.

Options:
- `--verbose` — show all issues including suggestions
- `--errors-only` — only errors (useful for CI)
- `--json-output` — machine-readable output
- `--fix` — generate skeleton files for missing concepts (use as a starting point, then fill in mappings)

## Authority data

The `authority/` directory contains upstream taxonomy sources. These are read-only reference data — don't modify them directly.

To update an authority source to a newer version:
1. Replace the data files
2. Update `authority/manifest.json` with the new version, checksum, and date
3. Verify crosswalk mappings still reference valid IDs

## Formatting

- JSON: 2-space indentation, trailing newline
- Field order in `concept.json`: `id`, `slug`, `title`, `aliases`, `mappings`, then `kind` (if applicable)
- No trailing commas
- UTF-8 encoding

## Submitting

1. Fork the repo
2. Create a branch (`git checkout -b add-concept-xyz`)
3. Make your changes
4. Run `python3 tools/healthcheck.py` — zero errors
5. Commit with a descriptive message
6. Open a PR against `main`

If you're unsure whether a mapping is correct, open the PR anyway and flag it — the community can help refine confidence levels and notes. Clacks explicitly preserves ambiguity rather than forcing false certainty.
