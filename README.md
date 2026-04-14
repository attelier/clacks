# clacks

This tool is meant to allow VASS analysts and triagers to categorize vulnerabilities across many different metrics at once, while keeping ambiguity, uncertainty, and nuance explicit rather than hidden.

## Slugs (hierarchical tags)

The tool’s primary utility is producing *slugs*: hierarchical tags (when a hierarchy exists) that describe a vulnerability across multiple metrics in a consistent, queryable form.

Example: searching `sqli` may emit slugs such as:

- Clacks slug:
  - `clacks/injection/server_side/sqli`
  - `clacks/injection/server_side/sqli/blind/time_based`
- CWE slug (hierarchical where available):
  - `cwe/view-699/CWE-74/CWE-89`
- VRT slug (always hierarchical):
  - `bugcrowd/vrt/server_side_injection.sql_injection.blind`
- OWASP Top 10 slug (bucket-level):
  - `owasp/top10/2021/A03`
  - `owasp/api/2023/API03`

If a metric has a hierarchy, the full hierarchy is emitted (not only the leaf). If a metric has no meaningful hierarchy for the concept, only the relevant node is emitted.

A single finding may produce multiple slugs across metrics.

## Components

The project consists of three main parts:

### Authority

Upstream, read-only JSON exports of authoritative sources such as MITRE ATT&CK, OWASP Top 10 (Web and API), Bugcrowd VRT, and CWE.

These datasets are treated as reference material and are not modified beyond format normalization and indexing.

### Crosswalk

An opinionated, human-curated layer that correlates authority metrics and expresses a practical vulnerability taxonomy.

The crosswalk:
- Allows many-to-many mappings between taxonomies
- Explicitly records confidence and notes for ambiguous mappings
- Preserves competing interpretations instead of forcing a single classification
- Expands beyond authority taxonomies where additional practical specificity is useful

The crosswalk is represented directly as a filesystem hierarchy. Each directory that represents a concept contains a `concept.json` file.

#### Specifiers

Some paths contain reserved subdirectories used to qualify vulnerabilities rather than define new ones:

- `_scenarios`
- `_techniques`
- `_conditions`
- `_vectors`
- `_constraints`

Concepts under these namespaces are specifiers. They are not standalone vulnerabilities, but may be applied to vulnerabilities to capture context such as exploitation technique, attack vector, constraints, or scenario.

### clacks.rs

A CLI tool that consumes the local Authority and Crosswalk data to allow analysts to browse, search, and extract hierarchical tags and mappings.

All queries are performed locally against the checked-out repository.

Get it at https://github.com/attelier/clackscli

## Generated indexes

Some folders contain generated index files used by the CLI to provide fast and deterministic lookups (for example, alias resolution).

These files are derived artifacts and are not intended to be edited manually. Human contributions should focus on the Crosswalk concept files.

## Disclaimer

Initial crosswalk coverage for a given domain (for example, Web Security) is partially generated and then continuously reviewed and corrected during real-world triage work.

Mappings are not absolute, may change over time, and can be wrong. Ambiguity is preserved intentionally rather than forced into a single “correct” classification.

Contributions and corrections are welcome.
