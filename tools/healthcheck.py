#!/usr/bin/env python3
"""Clacks taxonomy health checker.

Validates the crosswalk directory tree, checking for missing concept.json
files, schema violations, consistency issues, and suggesting improvements.

Usage:
    python tools/healthcheck.py
    python tools/healthcheck.py --verbose
    python tools/healthcheck.py --fix
    python tools/healthcheck.py --json-output
    python tools/healthcheck.py --errors-only
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


# ── constants ────────────────────────────────────────────────────────────────

RESERVED_SPECIFIER_DIRS = frozenset(
    {"_scenarios", "_techniques", "_conditions", "_vectors", "_constraints"}
)

VALID_CONFIDENCES = frozenset({"high", "medium", "low"})

KNOWN_MAPPING_CATEGORIES = frozenset(
    {"cwe", "owasp_top10", "bugcrowd_vrt", "owasp_api10", "mitre_attack"}
)

REQUIRED_FIELDS = {"id", "slug", "title", "aliases", "mappings"}


# ── severity and issue ───────────────────────────────────────────────────────

class Severity(IntEnum):
    ERROR = 0
    WARNING = 1
    INFO = 2


SEVERITY_LABEL = {
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}

SEVERITY_COLOR = {
    Severity.ERROR: "\033[91m",   # red
    Severity.WARNING: "\033[93m", # yellow
    Severity.INFO: "\033[36m",    # cyan
}

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


@dataclass
class Issue:
    severity: Severity
    path: str
    check: str
    message: str


# ── path helpers ─────────────────────────────────────────────────────────────

def dir_to_clacks_id(rel_path: str) -> str:
    """Convert a crosswalk-relative path to a clacks id."""
    return f"clacks/{rel_path}"


def is_reserved_specifier_dir(name: str) -> bool:
    return name in RESERVED_SPECIFIER_DIRS


def is_inside_specifier_namespace(rel_path: str) -> bool:
    """True if any path component is a reserved specifier dir."""
    return any(part in RESERVED_SPECIFIER_DIRS for part in Path(rel_path).parts)


def should_have_concept_json(rel_path: str) -> bool:
    """Whether this directory should contain a concept.json.

    Returns False for the crosswalk root and for reserved specifier container
    dirs themselves (e.g. _scenarios/). Returns True for everything else,
    including children of specifier dirs (e.g. _scenarios/data_leak/).
    """
    if not rel_path or rel_path == ".":
        return False
    name = Path(rel_path).name
    return not is_reserved_specifier_dir(name)


def title_from_dirname(dirname: str) -> str:
    return dirname.replace("_", " ").title()


# ── checks ───────────────────────────────────────────────────────────────────

def check_missing_concept_json(crosswalk: Path) -> list[Issue]:
    issues: list[Issue] = []
    for dirpath, dirnames, filenames in os.walk(crosswalk):
        # skip hidden dirs
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel = os.path.relpath(dirpath, crosswalk)
        if not should_have_concept_json(rel):
            continue
        if "concept.json" not in filenames:
            issues.append(Issue(
                Severity.ERROR, rel, "missing-concept",
                "Missing concept.json",
            ))
    return issues


def check_json_validity(filepath: Path, rel: str) -> tuple[dict | None, list[Issue]]:
    issues: list[Issue] = []
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            issues.append(Issue(
                Severity.ERROR, rel, "invalid-json",
                "Root value is not a JSON object",
            ))
            return None, issues
        return data, issues
    except json.JSONDecodeError as e:
        issues.append(Issue(
            Severity.ERROR, rel, "invalid-json",
            f"Parse error at line {e.lineno}, column {e.colno}: {e.msg}",
        ))
        return None, issues
    except OSError as e:
        issues.append(Issue(
            Severity.ERROR, rel, "read-error",
            f"Cannot read file: {e}",
        ))
        return None, issues


def check_schema(data: dict, rel: str) -> list[Issue]:
    issues: list[Issue] = []

    # required fields
    for field_name in REQUIRED_FIELDS:
        if field_name not in data:
            issues.append(Issue(
                Severity.ERROR, rel, "missing-field",
                f'Missing required field "{field_name}"',
            ))

    # string fields
    for field_name in ("id", "slug", "title"):
        val = data.get(field_name)
        if val is not None and (not isinstance(val, str) or not val.strip()):
            issues.append(Issue(
                Severity.ERROR, rel, "bad-field-type",
                f'"{field_name}" must be a non-empty string',
            ))

    # aliases
    aliases = data.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, list) or len(aliases) == 0:
            issues.append(Issue(
                Severity.ERROR, rel, "bad-aliases",
                '"aliases" must be a non-empty array',
            ))
        elif not all(isinstance(a, str) and a.strip() for a in aliases):
            issues.append(Issue(
                Severity.WARNING, rel, "bad-alias-entry",
                '"aliases" contains empty or non-string entries',
            ))

    # mappings
    mappings = data.get("mappings")
    if mappings is not None:
        if not isinstance(mappings, dict):
            issues.append(Issue(
                Severity.ERROR, rel, "bad-mappings-type",
                '"mappings" must be an object',
            ))
        else:
            for cat, entries in mappings.items():
                if cat not in KNOWN_MAPPING_CATEGORIES:
                    issues.append(Issue(
                        Severity.INFO, rel, "unknown-mapping-category",
                        f'Unknown mapping category "{cat}"',
                    ))
                if not isinstance(entries, list):
                    issues.append(Issue(
                        Severity.ERROR, rel, "bad-mapping-entries",
                        f'Mapping category "{cat}" must be an array',
                    ))
                    continue
                for i, entry in enumerate(entries):
                    if not isinstance(entry, dict):
                        issues.append(Issue(
                            Severity.ERROR, rel, "bad-mapping-entry",
                            f'{cat}[{i}] must be an object',
                        ))
                        continue
                    if "id" not in entry or not isinstance(entry.get("id"), str):
                        issues.append(Issue(
                            Severity.ERROR, rel, "mapping-missing-id",
                            f'{cat}[{i}] missing or invalid "id"',
                        ))
                    conf = entry.get("confidence")
                    if conf not in VALID_CONFIDENCES:
                        issues.append(Issue(
                            Severity.ERROR, rel, "mapping-bad-confidence",
                            f'{cat}[{i}] confidence must be one of '
                            f'{sorted(VALID_CONFIDENCES)}, got "{conf}"',
                        ))
                    note = entry.get("note")
                    if note is not None and not isinstance(note, str):
                        issues.append(Issue(
                            Severity.WARNING, rel, "mapping-bad-note",
                            f'{cat}[{i}] "note" should be a string',
                        ))

    # kind
    kind = data.get("kind")
    if kind is not None and kind != "specifier":
        issues.append(Issue(
            Severity.ERROR, rel, "bad-kind",
            f'"kind" must be "specifier" if present, got "{kind}"',
        ))

    # unknown top-level keys
    known_keys = REQUIRED_FIELDS | {"kind"}
    for key in data:
        if key not in known_keys:
            issues.append(Issue(
                Severity.WARNING, rel, "unknown-field",
                f'Unknown top-level field "{key}"',
            ))

    return issues


def check_consistency(data: dict, rel: str) -> list[Issue]:
    issues: list[Issue] = []
    expected_id = dir_to_clacks_id(rel)

    cid = data.get("id")
    if isinstance(cid, str) and cid != expected_id:
        issues.append(Issue(
            Severity.ERROR, rel, "id-mismatch",
            f'id "{cid}" does not match expected "{expected_id}"',
        ))

    slug = data.get("slug")
    if isinstance(slug, str) and isinstance(cid, str) and slug != cid:
        issues.append(Issue(
            Severity.ERROR, rel, "slug-id-mismatch",
            f'slug "{slug}" does not match id "{cid}"',
        ))

    in_specifier = is_inside_specifier_namespace(rel)
    kind = data.get("kind")

    if in_specifier and kind != "specifier":
        issues.append(Issue(
            Severity.ERROR, rel, "missing-specifier-kind",
            'Concept is inside a specifier namespace but missing kind: "specifier"',
        ))
    elif not in_specifier and kind == "specifier":
        issues.append(Issue(
            Severity.ERROR, rel, "unexpected-specifier-kind",
            'Concept has kind: "specifier" but is not inside a specifier namespace',
        ))

    return issues


def check_suggestions(data: dict, rel: str) -> list[Issue]:
    issues: list[Issue] = []
    mappings = data.get("mappings")
    if not isinstance(mappings, dict):
        return issues

    if len(mappings) == 0:
        issues.append(Issue(
            Severity.WARNING, rel, "empty-mappings",
            "Concept has no mappings to any taxonomy",
        ))
        return issues

    # low confidence without note
    for cat, entries in mappings.items():
        if not isinstance(entries, list):
            continue
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            if entry.get("confidence") == "low" and not entry.get("note"):
                issues.append(Issue(
                    Severity.WARNING, rel, "low-conf-no-note",
                    f'{cat}[{i}] ({entry.get("id", "?")}) is low confidence '
                    f'without an explanatory note',
                ))

    # only cwe mappings
    cats = set(mappings.keys())
    if cats == {"cwe"} and not is_inside_specifier_namespace(rel):
        issues.append(Issue(
            Severity.INFO, rel, "cwe-only",
            "Only has CWE mappings — consider adding OWASP or VRT if applicable",
        ))

    return issues


# ── fix: generate skeletons ──────────────────────────────────────────────────

def generate_skeleton(crosswalk: Path, rel: str) -> dict:
    """Generate a minimal concept.json for a missing directory."""
    dirname = Path(rel).name
    concept: dict[str, Any] = {
        "id": dir_to_clacks_id(rel),
        "slug": dir_to_clacks_id(rel),
        "title": title_from_dirname(dirname),
        "aliases": [dirname.replace("_", " ")],
        "mappings": {},
    }
    if is_inside_specifier_namespace(rel):
        concept["kind"] = "specifier"
    return concept


def fix_missing(crosswalk: Path, missing_issues: list[Issue]) -> int:
    """Write skeleton concept.json files. Returns number of files created."""
    count = 0
    for issue in missing_issues:
        if issue.check != "missing-concept":
            continue
        target = crosswalk / issue.path / "concept.json"
        skeleton = generate_skeleton(crosswalk, issue.path)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(skeleton, f, indent=2, ensure_ascii=False)
            f.write("\n")
        count += 1
    return count


# ── output formatting ────────────────────────────────────────────────────────

def format_human(issues: list[Issue], verbose: bool, errors_only: bool,
                 stats: dict, use_color: bool) -> str:
    lines: list[str] = []

    if use_color:
        lines.append(f"\n{BOLD}clacks healthcheck{RESET}")
        lines.append(f"{DIM}{'═' * 50}{RESET}\n")
    else:
        lines.append("\nclacks healthcheck")
        lines.append("=" * 50 + "\n")

    lines.append(
        f"Scanned {stats['concepts']} concept files "
        f"across {stats['directories']} directories\n"
    )

    grouped: dict[Severity, list[Issue]] = {s: [] for s in Severity}
    for issue in issues:
        grouped[issue.severity].append(issue)

    for sev in Severity:
        if errors_only and sev != Severity.ERROR:
            continue
        group = grouped[sev]
        label = SEVERITY_LABEL[sev]
        if not verbose and sev == Severity.INFO:
            if group:
                if use_color:
                    lines.append(f"{SEVERITY_COLOR[sev]}{label}{RESET} ({len(group)} suggestions, use --verbose to see)")
                else:
                    lines.append(f"{label} ({len(group)} suggestions, use --verbose to see)")
            continue
        if not group:
            continue

        if use_color:
            lines.append(f"{SEVERITY_COLOR[sev]}{BOLD}{label} ({len(group)}){RESET}")
        else:
            lines.append(f"{label} ({len(group)})")

        for issue in sorted(group, key=lambda i: i.path):
            if use_color:
                lines.append(
                    f"  {DIM}[{issue.check}]{RESET} "
                    f"{issue.path} — {issue.message}"
                )
            else:
                lines.append(
                    f"  [{issue.check}] {issue.path} — {issue.message}"
                )
        lines.append("")

    # summary line
    counts = {s: len(grouped[s]) for s in Severity}
    summary = (
        f"Summary: {counts[Severity.ERROR]} errors, "
        f"{counts[Severity.WARNING]} warnings, "
        f"{counts[Severity.INFO]} suggestions"
    )
    if use_color:
        lines.append(f"{BOLD}{summary}{RESET}\n")
    else:
        lines.append(summary + "\n")

    return "\n".join(lines)


def format_json_output(issues: list[Issue], stats: dict) -> str:
    output = {
        "stats": stats,
        "errors": [
            {"path": i.path, "check": i.check, "message": i.message}
            for i in issues if i.severity == Severity.ERROR
        ],
        "warnings": [
            {"path": i.path, "check": i.check, "message": i.message}
            for i in issues if i.severity == Severity.WARNING
        ],
        "info": [
            {"path": i.path, "check": i.check, "message": i.message}
            for i in issues if i.severity == Severity.INFO
        ],
        "summary": {
            "errors": sum(1 for i in issues if i.severity == Severity.ERROR),
            "warnings": sum(1 for i in issues if i.severity == Severity.WARNING),
            "info": sum(1 for i in issues if i.severity == Severity.INFO),
        },
    }
    return json.dumps(output, indent=2)


# ── main ─────────────────────────────────────────────────────────────────────

def resolve_crosswalk(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    # try relative to script location
    script_dir = Path(__file__).resolve().parent
    candidate = script_dir.parent / "crosswalk"
    if candidate.is_dir():
        return candidate
    # try cwd
    candidate = Path.cwd() / "crosswalk"
    if candidate.is_dir():
        return candidate
    print("error: cannot locate crosswalk directory. Use --crosswalk-dir.", file=sys.stderr)
    sys.exit(2)


def run(args: argparse.Namespace) -> int:
    crosswalk = resolve_crosswalk(args.crosswalk_dir)
    all_issues: list[Issue] = []

    # pass 1: find missing concept.json
    missing = check_missing_concept_json(crosswalk)
    all_issues.extend(missing)

    # handle --fix before other checks
    if args.fix:
        count = fix_missing(crosswalk, missing)
        print(f"Generated {count} skeleton concept.json files.")
        if count > 0:
            print("Re-run healthcheck to validate the generated files.")
            return 0

    # pass 2: validate existing concept.json files
    concept_count = 0
    dir_count = 0
    for dirpath, dirnames, filenames in os.walk(crosswalk):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        dir_count += 1
        if "concept.json" not in filenames:
            continue
        concept_count += 1
        filepath = Path(dirpath) / "concept.json"
        rel = os.path.relpath(dirpath, crosswalk)

        data, json_issues = check_json_validity(filepath, rel)
        all_issues.extend(json_issues)
        if data is None:
            continue

        all_issues.extend(check_schema(data, rel))
        all_issues.extend(check_consistency(data, rel))
        all_issues.extend(check_suggestions(data, rel))

    stats = {"concepts": concept_count, "directories": dir_count}

    # output
    use_color = sys.stdout.isatty() and not args.json_output
    if args.json_output:
        print(format_json_output(all_issues, stats))
    else:
        print(format_human(all_issues, args.verbose, args.errors_only, stats, use_color))

    has_errors = any(i.severity == Severity.ERROR for i in all_issues)
    return 1 if has_errors else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Clacks taxonomy health checker",
    )
    parser.add_argument(
        "-d", "--crosswalk-dir",
        help="Path to crosswalk directory (auto-detected by default)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all issues including suggestions",
    )
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help="Only show errors (useful for CI)",
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Generate skeleton concept.json for missing directories",
    )
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
