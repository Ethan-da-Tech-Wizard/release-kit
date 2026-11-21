#!/usr/bin/env python3
r"""hotswap: put your own values back into a staged component.  Stdlib only (python 3.9).

Purpose
  scrub_release.py turns private values into {{PLACEHOLDER}} tokens so a component can be published. hotswap is the
  inverse: a user who downloaded the published component fills in THEIR OWN values and gets a working copy.

Design notes / threat model
  * Real values must never end up inside the release tree. The output folder is therefore required to be outside
    it (and outside the component folder), must be new or empty, and existing files are never overwritten.
  * The values file and the restore map hold real data, so both must be regular files, chmod 600, owned by the
    current user and outside the release tree (checked by scrub_release.check_private_file).
  * Fail closed: any {{TOKEN}} without a value aborts the run with nothing written (unless --allow-partial).
    A value that would make an unsafe file name ("", ".", "..", or containing "/" or NUL) aborts too.
  * Optional integrity check: when the values file carries a salt, each restored value is hashed and compared with
    the per-occurrence salted hash recorded at scrub time in the PRIVATE annotations copy, so a wrong or stale value
    is caught before anything is written. Hashes are never stored in the published tree.
  * Case variants: {{KEY.lower}}, {{KEY.upper}}, {{KEY.title}} are filled with the matching transform of the value.

Usage
  hotswap.py --component-dir staging/<c> --values my_values.json --out ~/my_copy/<c> [--restore restore.json]
             [--dry-run] [--allow-partial] [--private-annotations DIR] [--release-root DIR]

  Example (preview first, then write):
    python3 tools/hotswap.py --component-dir staging/demo --values my_values.json --out ../demo_real --dry-run
    python3 tools/hotswap.py --component-dir staging/demo --values my_values.json --out ../demo_real

--values   JSON keyed by placeholder ({"OWNER_NAME": "...", "HOST_1": "..."}), or the scrub-time private
           values-file format ({"values": {...}}).  Must be chmod 600 and outside the release tree.
--restore  optional private restore map written by scrub_release.py (component -> token -> original).
--out      must not exist (or be empty) and must be outside the release tree: hotswap never overwrites and never
           writes real values into the release tree.
Unresolved {{TOKEN}}s abort the run (exit 1, nothing written) unless --allow-partial.
If the values file carries the salt, every restored value is verified against the per-occurrence
salted hashes in the PRIVATE annotations copy (never in the published tree).
Exit status: 0 ok, 1 unresolved tokens remain, 2 fatal error (bad input, unsafe paths, hash mismatch).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scrub_release as sr  # noqa: E402


def load_user_values(path, release_root):
    """Read and validate the user's values file.

    Args:
        path: values JSON file (must pass check_private_file: outside release tree, chmod 600, owned by us).
        release_root: release tree root the file must not live in.
    Returns:
        (mapping, salt): mapping is {TOKEN_KEY: value string}; salt is the "salt" string if present, else None.
    Accepts either a flat {"KEY": "value" | ["v1", "v2"]} object or a wrapper with a "values" object; list values
    expand to KEY_1, KEY_2, ... Keys may be written as "{{KEY}}". Raises ScrubError on any malformed entry.
    """
    real = sr.check_private_file(path, release_root, "values file")
    try:
        data = json.loads(real.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise sr.ScrubError("cannot parse values file: %s" % type(e).__name__)
    if not isinstance(data, dict):
        raise sr.ScrubError("values file must be a JSON object")
    # The salt (if any) sits beside "values" in the scrub-time file format; keep it for hash verification.
    salt = data.get("salt") if isinstance(data.get("salt"), str) else None
    if isinstance(data.get("values"), dict):
        data = data["values"]   # unwrap the scrub-time values-file format
    flat = sr.flatten_values(data)
    out = {}
    for k, v in flat.items():
        k = k.strip()
        if k.startswith("{{") and k.endswith("}}"):
            k = k[2:-2]   # tolerate keys written as full tokens
        if not sr.KEY_RE.match(k) or not isinstance(v, str):
            raise sr.ScrubError("bad entry in values file: key %r" % k)
        out[k] = v
    return out, salt


def load_restore(path, release_root, component):
    """Load one component's section of the private restore map.

    Args:
        path: restore map JSON (same privacy checks as the values file).
        release_root: release tree root it must live outside.
        component: component name (the staged folder name).
    Returns:
        {token key: original string}; an empty dict when the component has no section.
    Raises ScrubError if the file is unparsable or the section is not a string-to-string object.
    """
    real = sr.check_private_file(path, release_root, "restore map")
    try:
        data = json.loads(real.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise sr.ScrubError("cannot parse restore map")
    m = data.get(component, {}) if isinstance(data, dict) else {}
    if not isinstance(m, dict) or not all(isinstance(v, str) for v in m.values()):
        raise sr.ScrubError("restore map section is malformed")
    return m


def transform(value, variant):
    """Apply a placeholder's case variant to a value.

    variant is "" or None (as-is), "lower", "upper" or "title" (matching {{KEY.lower}} etc.). An unknown variant
    raises KeyError; TOKEN_RE only ever yields the four known ones.
    """
    return {"": value, None: value, "lower": value.lower(), "upper": value.upper(), "title": value.title()}[variant]


def swap_text(text, mapping, unresolved, counts):
    """Replace every {{TOKEN}} in text using mapping.

    Args:
        text: string to process.
        mapping: {key: value}.
        unresolved: dict updated in place with {key: occurrences} for tokens that have no value (left untouched).
        counts: dict updated in place with {key: occurrences} for tokens that were replaced.
    Returns:
        The new text. Replacement values are not rescanned, so a value containing "{{X}}" is not expanded again.
    """
    def rep(m):
        """re.sub callback: substitute one token match, or keep it and record it as unresolved."""
        key, var = m.group(1), m.group(2)
        if key not in mapping:
            unresolved[key] = unresolved.get(key, 0) + 1
            return m.group(0)
        counts[key] = counts.get(key, 0) + 1
        return transform(mapping[key], var)
    return sr.TOKEN_RE.sub(rep, text)


def run(component_dir, values_path, out_dir, restore_path=None, release_root=sr.DEFAULT_RELEASE_ROOT,
        dry_run=False, allow_partial=False, private_annotations=None):
    """Fill a staged component with real values and write the result to a new folder.

    Args:
        component_dir: staged component folder (the folder name is the component name).
        values_path: user values file (see load_user_values).
        out_dir: destination; must be outside the release tree and the component, and new or empty.
        restore_path: optional private restore map; its entries are the base, user values override them.
        release_root: the release tree root (real values must never be written inside it).
        dry_run: compute and report but write nothing.
        allow_partial: write even if some tokens have no value (they stay as tokens).
        private_annotations: folder with <component>.json holding salted hashes; defaults to the sibling folder of
            the restore map.
    Returns:
        (exit_code, summary): 0 on success, 1 when unresolved tokens remain and allow_partial is false. summary has
        counts: files, files_changed, replacements, unresolved, per_key, verified_with_hashes.
    Raises:
        sr.ScrubError for unsafe paths, symlinks or non-UTF-8 files in the component, unsafe resulting file names,
        or a restored value whose salted hash does not match the recorded one.
    """
    cdir = Path(component_dir).resolve()
    release_root = Path(release_root).resolve()
    if not cdir.is_dir():
        raise sr.ScrubError("component dir not found")
    # Validate every path BEFORE reading or writing anything else.
    mapping, salt = load_user_values(values_path, release_root)
    if restore_path:
        base = load_restore(restore_path, release_root, cdir.name)
        base.update(mapping)   # explicit user values override the recorded originals
        mapping = base
    out = Path(os.path.abspath(str(Path(out_dir).expanduser())))
    out_real = out.resolve()
    # Check both the literal and the symlink-resolved path so a link cannot smuggle the output into the tree.
    for cand in (out, out_real):
        if cand == release_root or release_root in cand.parents:
            raise sr.ScrubError("--out must be OUTSIDE the release tree (real values never go into it)")
        if cand == cdir or cdir in cand.parents:
            raise sr.ScrubError("--out may not be inside the component dir")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise sr.ScrubError("--out exists and is not empty; hotswap never overwrites")

    unresolved, counts, changed = {}, {}, {}   # tokens without a value; replacements per key; per-file change counts
    plan = []   # (source file, output relative path, new text) - nothing is written until everything validated
    out_files, out_dirs = set(), set()   # F6: output names planned so far, to detect two sources landing on one name
    for f in sorted(p for p in cdir.rglob("*") if not p.is_dir() or p.is_symlink()):
        rel = f.relative_to(cdir).as_posix()
        if rel in sr.META_FILES:
            continue   # annotation pages describe the scrubbed tree; not part of the restored copy
        if f.is_symlink():
            raise sr.ScrubError("symlink in staged component: %s" % rel)
        if not f.is_file():
            # F5: a FIFO / socket / device would hang or misbehave in read_bytes(); refuse before anything is written.
            raise sr.ScrubError("special file (not a regular file) in staged component: %s" % rel)
        try:
            text = f.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise sr.ScrubError("staged file is not UTF-8 text: %s" % rel)
        parts = []
        for part in rel.split("/"):
            # File and folder names can carry tokens too; a value must not turn a name into a path escape.
            new = swap_text(part, mapping, unresolved, counts)
            if new in ("", ".", "..") or "/" in new or "\x00" in new:
                raise sr.ScrubError("a value would produce an unsafe file name")
            parts.append(new)
        # F6: after filling, two different staged names can become ONE name (e.g. {{A}}.txt and {{B}}.txt when both
        # values are equal), or a file name can equal a folder name.  Writing would then fail half way (O_EXCL) after
        # part of the output exists, so detect it now, before anything is written.
        out_rel_name = "/".join(parts)
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts))]
        if out_rel_name in out_files or out_rel_name in out_dirs or any(x in out_files for x in prefixes):
            raise sr.ScrubError("two staged files would get the same name after the values are filled in "
                                "(nothing was written); use different values for the placeholders in the names")
        out_files.add(out_rel_name)
        out_dirs.update(prefixes)
        before = sum(counts.values())   # so we can count replacements for this file only
        new_text = swap_text(text, mapping, unresolved, counts)
        if new_text != text or parts != rel.split("/"):
            changed[rel] = sum(counts.values()) - before
        plan.append((f, "/".join(parts), new_text))

    verified = False   # becomes True only if a private annotations copy was found and every value matched
    if salt:
        # Salted hashes are NOT in the published tree: they live in a private copy next to the restore map.
        pdir = Path(private_annotations) if private_annotations else (Path(restore_path).parent / sr.PRIVATE_ANN_DIR if restore_path else None)
        ann_path = (pdir / (cdir.name + ".json")) if pdir else None
        if ann_path is not None and ann_path.is_file():
            verified = True
            bad = []   # file:line locations whose restored value hashes differently from the recorded original
            try:
                ann = json.loads(ann_path.read_text(encoding="utf-8"))
                for r in ann.get("replacements", []):
                    if r["key"] in mapping:
                        v = transform(mapping[r["key"]], r.get("variant", ""))
                        if sr.ann_hash(salt, v) != r["hash"]:
                            bad.append("%s:%d" % (r["file"], r["line"]))
            except (ValueError, KeyError, TypeError, AttributeError, OSError):
                # e.g. the PUBLIC ANNOTATIONS.json (no "hash" field) was passed by mistake, or the file is damaged.
                raise sr.ScrubError("private annotations file is malformed or is not the private copy with hashes")
            if bad:
                raise sr.ScrubError("restored value does not match the recorded salted hash at: " + ", ".join(bad[:20]))
    left = sum(unresolved.values())   # number of token occurrences still without a value
    summary = {"files": len(plan), "files_changed": len(changed), "replacements": sum(counts.values()),
               "unresolved": dict(sorted(unresolved.items())), "per_key": dict(sorted(counts.items())),
               "verified_with_hashes": verified}
    if left and not allow_partial:
        return 1, summary   # fail closed: nothing has been written yet
    if dry_run:
        return 0, summary
    # The output holds REAL values, so it must not be readable by other local users: every directory this run
    # creates is mode 0700 and every file 0600 (0700 when the staged file was executable).  The staged file's
    # group/other bits are deliberately NOT copied.  An already-existing --out (empty) is left as it is.
    _mkdir_private(out)
    for f, out_rel, new_text in plan:
        dst = out / out_rel
        _mkdir_private(dst.parent)
        mode = 0o700 if (f.stat().st_mode & 0o100) else 0o600
        # O_EXCL: never overwrite; the mode is applied at creation so the file is never briefly world-readable.
        fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.fchmod(fd, mode)          # umask can only remove bits, but be explicit
            with os.fdopen(fd, "wb") as fh:
                fd = -1
                fh.write(new_text.encode("utf-8"))
        finally:
            if fd != -1:
                os.close(fd)
    return 0, summary


def _mkdir_private(path):
    """Create PATH and any missing parents, each new directory with mode 0700 (existing ones are untouched)."""
    path = Path(path)
    if path.is_dir():
        return
    _mkdir_private(path.parent)
    os.mkdir(str(path), 0o700)
    os.chmod(str(path), 0o700)


def main(argv=None):
    """Command-line entry point; parses arguments, calls run() and prints a short summary (never the values).

    Returns the process exit status: 0 ok, 1 unresolved tokens remain, 2 fatal error (message on stderr).
    """
    ap = argparse.ArgumentParser(description="Hot-swap your own values into a staged component")
    ap.add_argument("--component-dir", required=True)
    ap.add_argument("--values", required=True)
    ap.add_argument("--restore")
    ap.add_argument("--private-annotations", help="folder holding <component>.json with salted hashes (default: next to --restore)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--release-root", default=str(sr.DEFAULT_RELEASE_ROOT))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allow-partial", action="store_true")
    a = ap.parse_args(argv)
    try:
        code, s = run(a.component_dir, a.values, a.out, a.restore, a.release_root, a.dry_run, a.allow_partial, a.private_annotations)
    except sr.ScrubError as e:
        print("hotswap: FATAL: %s" % e, file=sys.stderr)
        return 2
    print("%sfiles=%d changed=%d replacements=%d unresolved_tokens=%d%s" % (
        "DRY-RUN " if a.dry_run else "", s["files"], s["files_changed"], s["replacements"], sum(s["unresolved"].values()),
        " hash-verified" if s["verified_with_hashes"] else ""))
    for k, n in s["per_key"].items():
        print("  resolved %s x%d" % (k, n))
    for k, n in s["unresolved"].items():
        print("  UNRESOLVED %s x%d" % (k, n))
    if code:
        print("hotswap: refusing: unresolved tokens remain (use --allow-partial to override)", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
