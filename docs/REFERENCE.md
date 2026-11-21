# Release kit: full reference

This is the complete reference for the kit (formerly the top-level README). The landing page is [../README.md](../README.md). **Layout note:** in this repository the kit folder is the repository root, so commands read `python3 scrub_release.py ...` (older text and some code comments say `tools/scrub_release.py`: read `tools/` as the repository root).

Python 3.9+ (tested on 3.9 on macOS; Linux should work but is untested), standard library only, no network, nothing is ever pushed. **macOS and Linux only; Windows is not supported** (POSIX file modes, `bash`, `/Users` and `/home` path patterns, `bwrap`/`sandbox-exec`). Licensed MIT (see `LICENSE`).

**A PASS means nothing known was found, not that the tree is safe.** The gate looks for the values and shapes you told it about, plus common disguises of them. It cannot know what you did not list. See "Threat model and honest limits" below and review the staged tree by eye before you publish.

**Security problems**: report them privately to the maintainer (do not post exploit details or real private values in a public issue). Contact: ethan@twu.software. Project page: https://twu.software

Purpose: turn a folder of your own files into a copy that is safe to publish (private values replaced by `{{PLACEHOLDERS}}`), prove with an independent check that nothing private is left, and let anyone fill the placeholders with their own values again ("hot-swap").

Tests: `python3 -B -m unittest discover -s tests` from the repository root (236 tests, all pass on a clean copy, Python 3.9).

| file | what it does |
|---|---|
| `scrub_release.py` | copy an allow-listed set of files into `<release root>/staging/<component>/`, replacing private values |
| `release_gate.py` | independent verifier: scans `staging/` and fails (exit 1) if anything private could ship |
| `hotswap.py` | fill the placeholders of a component with your own values into a NEW folder |
| `reannotate.py` | rebuild the annotation pages after hand edits |
| `release.py` | one command: scrub, annotate, syntax check, gate, shell leak check, fresh one-commit git repo |
| `hermetic_run.py` | run a test command in layered isolation and write an honest receipt (see `HERMETIC_RUN.md`) |
| `allowlist.py`, `normalize.py`, `syntax_check.py` | helpers used by the tools above (required) |
| `templates/check_placeholders.sh` | the shell leak check run by `release.py` (options are documented at the top of the script) |
| `examples/` | a neutral `EXCLUDE_LIST.txt`, manifest, values file, allowlist and a tiny demo project, all with made-up values |

## Quick start (copy and paste)

Words you need:
- **kit folder**: the repository root (the folder that holds `scrub_release.py`); below, the current directory is that folder.
- **source root**: the folder holding the files you want to publish (it is only ever read). If you leave `--source-root` out it defaults to the environment variable `RELEASE_SOURCE_ROOT`, otherwise to the CURRENT directory, so running from the wrong folder silently reads the wrong files: always pass `--source-root`.
- **release root**: a folder YOU create for the output. It must contain `_privacy/EXCLUDE_LIST.txt`; the tools write `<release root>/staging/` inside it. Always pass it with `--release-root`. (If you leave the flag out, the default is the parent folder of the kit folder, i.e. the folder that contains the repository clone, which surprises people who cloned the kit straight into their home folder.)
- **values file**: your private values (real names, hosts, ...). It MUST live OUTSIDE the release root, be owned by you, and be `chmod 600`, or every tool refuses to run. Default location `~/.config/twu_release/values.private.json`.

The same thing has different flag names in different tools:

| meaning | `scrub_release.py`, `release_gate.py`, `hotswap.py` | `release.py` |
|---|---|---|
| your private values file | `--values` | `--rules` |
| the release root (holds `_privacy/` and `staging/`) | `--release-root` | `--release-root` (output goes to `--out` instead of `staging/`) |
| folder the gate scans | `--staging` (default `<release root>/staging`) | `--out` |
| fake-secret exceptions | `--allowlist` (gate) | `--allowlist` |

```
# 0. folders (the example uses the demo project that ships in examples)
mkdir -p ~/release_work/_privacy ~/.config/twu_release
chmod 700 ~/.config/twu_release
cp examples/EXCLUDE_LIST.txt ~/release_work/_privacy/EXCLUDE_LIST.txt     # required: see "EXCLUDE_LIST" below
cp examples/example_values.json ~/.config/twu_release/values.private.json  # put YOUR values here instead
chmod 600 ~/.config/twu_release/values.private.json
# The salt in the example file is PUBLIC and the tools refuse it. Generate your own random salt and write it into
# your values file (keep it secret; do not reuse the example one). Exact command:
python3 -c "import json,os,secrets;p=os.path.expanduser('~/.config/twu_release/values.private.json');d=json.load(open(p));d['salt']=secrets.token_hex(16);json.dump(d,open(p,'w'),indent=2)"

# 1. scrub  (reads examples/demo_project, writes ~/release_work/staging/demo/)
python3 scrub_release.py --manifest examples/example_manifest.json \
    --release-root ~/release_work --source-root examples/demo_project
# expected output (exit 0):
#   component=demo copied=2 refused=0 replacements=7
#     EMAIL: 1
#     EXACT: 5
#     HOME_PATH: 1

# 2. gate  (scans ~/release_work/staging)
python3 release_gate.py --release-root ~/release_work
# expected output (exit 0):
#   release_gate: scanned 6 files; findings=0
#   release_gate: PASS
# a leak prints lines like  demo/scripts/x.py:12: PATTERN[EMAIL]  and ends with  release_gate: FAIL  (exit 1)

# 3. hot-swap  (someone else fills the placeholders with their own values into a NEW folder)
echo '{"OWNER_NAME": "Pat Example", "OWNER_HANDLE": "pexample", "HOST_1": "mybox", "HOME_DIR_1": "/Users/pat", "EMAIL_1": "pat@mail.example"}' > ~/my_values.json
chmod 600 ~/my_values.json
python3 hotswap.py --release-root ~/release_work --component-dir ~/release_work/staging/demo \
    --values ~/my_values.json --out ~/my_copy/demo --dry-run        # shows counts, writes nothing
python3 hotswap.py --release-root ~/release_work --component-dir ~/release_work/staging/demo \
    --values ~/my_values.json --out ~/my_copy/demo
# expected output (exit 0):
#   files=2 changed=2 replacements=7 unresolved_tokens=0
#     resolved EMAIL_1 x1 ... (one line per placeholder)
```
`demo/scripts/hello.py` now reads `OWNER = "Pat Example"` etc. The keys you can fill are listed in `staging/<component>/ANNOTATIONS.md` and `staging/PLACEHOLDERS_INDEX.md` (a placeholder written `HOST_1` is the key `HOST_1`).

All-in-one instead of steps 1-2:
```
python3 release.py --manifest examples/example_manifest.json \
    --rules ~/.config/twu_release/values.private.json --out ~/release_out \
    --source-root examples/demo_project --release-root ~/release_work \
    --restore-map ~/.config/twu_release/restore.private.json
# expected: six lines "step scrub|annotations|syntax|verify|placeholders|git  PASS ..." (the placeholders step also prints an
# indented "leak check: clean" line), then "release: PASS"
```
`--out` must be new or empty. Besides `<out>/demo/` the output tree has TOP-LEVEL `ANNOTATIONS.json`, `ANNOTATIONS.md` and `PLACEHOLDERS_INDEX.md`. The top-level `ANNOTATIONS` page belongs to a pseudo-component named "(staging root)": it covers files that sit directly in the root of the tree (for example a README or LICENSE) and says "No placeholders remain in this component." when there are none. They are meant to be published with the tree and contain no hashes. The git step makes one commit with a neutral author and a fixed date; nothing is pushed. If any step fails the tree is not committed.

### The three input files

1. **Manifest** (JSON): `{"component": "demo", "files": ["scripts/hello.py", "README.md"], "exclude_exceptions": []}`. Paths are relative to the source root. Allowlist only: no globs, no directories; unlisted files are never read.
2. **Values file** (JSON, example in `examples/example_values.json`; all values fake):
   `{"salt": "any random text, 8+ chars", "values": {"OWNER_NAME": "Quillon Marbury", "HOST": ["plumbox-7", "tealbox-2"]}, "allow_emails": ["help@example.org"]}`.
   List values become `HOST_1`, `HOST_2`. Values shorter than 3 chars, the same value under two keys, or a missing salt are errors. Optional keys: `gate_ignore_words`, `gate_public_phrases`, `gate_public_identity`, `gate_allow_strings`, `rename_prefixes` (below).
3. **`<release root>/_privacy/EXCLUDE_LIST.txt`**: path patterns that must never be released (secrets folders, logs, binaries). It is REQUIRED (the scrubber and the gate refuse to run without it: "EXCLUDE_LIST not found"). Start from `examples/EXCLUDE_LIST.txt`. Format: whitespace-separated patterns, `#` starts a comment, `dir/` matches a folder anywhere, `*.ext` globs file names, `a/b` is a path prefix. A manifest can release one excluded path on purpose through `exclude_exceptions`; that is recorded in `ANNOTATIONS.json`.

Warning: each scrub run DELETES and rebuilds `staging/<component>/`. Hand edits there are lost on the next run; make hand edits last, then run `reannotate.py` and the gate.

## How it works

1. Scrub (`scrub_release.py --manifest m.json ...`) writes `staging/<component>/`:
   - exact private values become `{{KEY}}`, matched case-insensitively, longest match first. Case variants are encoded as `{{KEY.lower}}`, `.upper`, `.title`; any other mixed case refuses the file.
   - pattern classes become indexed tokens, same value = same token within a component: home paths `{{HOME_DIR_n}}`, emails (except allowlisted/example/noreply) `{{EMAIL_n}}`, RFC1918 `{{LAN_IP_n}}`, CGNAT/VPN `{{VPN_IP_n}}`, MAC, `*.local/.lan/.home.arpa` hostnames `{{HOST_n}}`, `*.ts.net` tailnet hostnames, WireGuard keys, SSH keys and fingerprints, Syncthing IDs, API token prefixes (sk-, ghp_, xox, AKIA, ...), phone, EIN, UEI, DUNS. Note: the class names printed by the tools (`HOME_PATH`, `HOSTNAME`, `EMAIL`, ...) are not always the token names (`{{HOME_DIR_n}}`, `{{HOST_n}}`, `{{EMAIL_n}}`); your own value keys are used as written (`{{HOST_1}}` is the key `HOST_1`). Indices that would collide with one of your own keys are skipped.
   - file and directory names are scrubbed the same way.
   - the whole run stops (exit 2, nothing written) if the manifest lists the values file, the restore map, anything under `annotations.private/` or the default config folder `~/.config/twu_release` (or a hard link to the values file); a file that merely CONTAINS the salt is refused.
   - refused (listed in `REFUSED.md` by item number and reason, exit code 3): binary/sqlite/images/pdf/archives/weights/`*.pyc`, NUL or non-UTF-8 content, private key blocks, files over 5 MB, symlinks, `.env`/id_rsa style names, files that already contain `{{TOKEN}}` text, partially overlapping matches, mixed-case variants, EXCLUDE_LIST paths. Refused paths are shown scrubbed.
   - per component: `ANNOTATIONS.md` (columns: placeholder, meaning, example value, where to swap, file:line:column; `reannotate.py` writes this form), `ANNOTATIONS.json` (public: every replacement as file, line, column, placeholder, plus the refused entries as "item N + reason" only; no hashes; line 0 = file name; the salted hashes go only to a folder named `annotations.private/` NEXT TO the restore map you use (default restore map `~/.config/twu_release/restore.private.json`, so by default `~/.config/twu_release/annotations.private/<component>.json`; with a custom `--restore-map` they go beside that one, keep it outside the release tree and `chmod 700`)), `REFUSED.md`; and `staging/PLACEHOLDERS_INDEX.md` across components. **`REFUSED.md` and the `refused` list in the public `ANNOTATIONS.json` are published with the tree, so they WITHHOLD the names of refused files** (a refused name such as `taxes_2025.xlsx` or `private/notes.md` is information too; the names are withheld): they list "item N" and the reason only. The names are printed on the operator's screen by the scrubber and stored in the private annotations copy (`refused_paths`). If you hand-edit these pages to add names back, you publish them. Output is deterministic (sorted, no timestamps).
   - writes `~/.config/twu_release/restore.private.json` (chmod 600, outside the tree): token to original for pattern tokens, per component. A config folder created by the tool is made chmod 700.
2. Gate (`release_gate.py`) scans `staging/`; exit 1 on any finding, **including an empty tree** (0 files scanned, or no component folder: usually a wrong `--staging` path). It also fails when the SALT or the path of the values file appears anywhere in the tree (checked in plain text only: a base64, hex, rot13, reversed or split copy of the salt is NOT detected, and a public document that quotes the default values-file path will fail this check, so keep that path out of anything you publish through the pipeline) (`PRIVATE_VALUE[SALT]`, `PRIVATE_VALUE[VALUES_FILE_PATH]`), when a `{{TOKEN}}` is present that the component's `ANNOTATIONS.json` does not list (`PLACEHOLDER[unregistered token]`: a hand-added token, for example one spelled like a private value, is not allowed; the generated pages `ANNOTATIONS.md/json`, `REFUSED.md` and `PLACEHOLDERS_INDEX.md` at their real place may quote token syntax), and on a FIFO, socket or device file (`STRUCTURE`). It prints counts and `file:line: CATEGORY[detail]` only, never matched text. A file or folder NAME that itself contains a private value is printed as `path#<n>` (n = its 1-based position in the string-sorted path list; to find it: `find staging -mindepth 1 | sed 's#^staging/##' | LC_ALL=C sort | sed -n <n>p`, on your own screen, not in CI logs). Categories: PRIVATE_VALUE (salted-hash match of each value, each word of at least 4 characters that contains a letter (or 7+ digits for an all-digit word), and each contiguous word run, case-insensitive; the detail is your key name, with `:rot13`, `:reversed`, `:hex`, `:base64`, `:urlencoded`, `:split-punctuation`, `:split-chars` for those forms), PATTERN, PRIVATE_KEY, REFUSED_TYPE, EXCLUDE_LIST, STRUCTURE, METADATA (author/company fields inside office documents and PDFs), CARRIER (an archive or file the gate could not open safely, or a decompression limit was hit). The text is normalised before matching: zero-width characters and soft hyphens removed, fullwidth letters and accents folded, common Cyrillic/Greek look-alikes mapped, VT, FF, NEL, U+2028 and U+2029 dropped, escapes decoded (`\uXXXX`, `\u{X}`, `\UXXXXXXXX`, `\xXX`, `&#NN;`/`&#NN`, `&#xHH;`/`&#xHH` with or without the semicolon, and percent-encoding `%XX` of any characters, also double-encoded), adjacent string literals joined, CRLF ignored, and a value split over two consecutive lines is found. A single-word value of 6+ characters is also found with up to 3 punctuation or space characters between any two of its characters (`:split-chars`). `:urlencoded` additionally covers common `quote()`-style spellings. File and folder names go through the same scans. Common words inside a value (a host called "mini") will trip it: list them in `gate_ignore_words`; a whole ordinary word that merely CONTAINS a private value (for example a public tool name) can be listed in `gate_allow_strings` (letters/digits, 6+ chars, matched as a whole word and blanked before the value scan only). The gate also fails if a published `ANNOTATIONS.json` contains hashes.
3. Allowlist (`--allowlist FILE`; a ready-to-edit example is `examples/example_allowlist.json`, the format is also described at the top of `allowlist.py`; the file has `fixtures`, `approved_binaries` and `syntax_exempt` entries, each with a required `reason`): lists fake-secret test fixtures that may stay in named files. A fixture hides only itself: pattern hits next to it are still reported; a fixture containing any private value or any distinctive WORD of one, or a path made only of wildcards, is refused when the file is loaded.

### `gate_public_phrases` (public names that overlap only the workspace-name key)
Some PUBLIC text legitimately contains words of a private value: e.g. your workspace folder is `Acme_Works` (key `WORKSPACE_NAME`) and the public company name `Acme Works` sits in every MIT copyright line, which the gate would report as `PRIVATE_VALUE[WORKSPACE_NAME:split-punctuation]`. List such names in the private values file: `"gate_public_phrases": ["Acme Works", "Acme Works Incorporated"]`. Rules, enforced when the values file is loaded (a violation is a fatal setup error, exit 2, message never shows the phrase or value):
- exact and case-sensitive (`acme works` is NOT blanked); 6+ characters; spaces allowed; no leading/trailing space;
- blanked only as a WHOLE phrase and only at word boundaries (not preceded or followed by a letter or digit), so it never matches inside a longer token such as `Acme WorksX`;
- the phrase may overlap a private value ONLY for the key `WORKSPACE_NAME` (or its list forms `WORKSPACE_NAME_1`...). Overlapping any other key (owner name or part, host, handle, IP, email) refuses the file;
- blanking keeps text length, so an owner name or host written next to the phrase is still found; the pattern scan (emails, IPs, paths) still sees the unblanked line.
Review the list like `exclude_exceptions`: it is trusted. Code: `scrub_release.PrivateValues` and `release_gate.scan_text`. Tests: `TestGatePublicPhrases` in `tests/test_release_tools.py`.

### `gate_public_identity` (the owner's intentionally PUBLISHED contact handle or email)
Use this ONLY for contact data you publish on purpose: a repository URL that carries your public handle (`https://github.com/<handle>/<repo>`), your public handle itself, or your public contact address. **Never for secrets, and never as a general allow-list.** It is separate from, and much narrower than, `gate_public_phrases`. In the private values file: `"gate_public_identity": ["https://github.com/<handle>", "contact@example.org", "<handle>"]`. Rules, enforced when the values file is loaded (a violation is a fatal setup error, exit 2; the message shows only a masked form such as `url:h***(34)`):
- each entry is exactly one of: a URL whose first path part is the handle (`https://host/<handle>` optionally followed by more path), an email address, or a bare handle token. Spaces and free text are refused, at most 20 entries;
- a bare token must EQUAL a handle value from your values (a key containing `HANDLE`, or starting `GITHUB_`). A bare first name or any other word is refused, so a lone first name can never be declared public;
- a URL or email entry may contain the owner's name parts or handle (keys starting `OWNER_`, `GITHUB_`, `GIT_AUTHOR_`), but NOT any value of another key (hostname, IP, workspace name, organisation, phone, address...): such an entry is refused.
What the gate does: each declared string is blanked as a WHOLE token before the private-value scan (exact and case-sensitive; not preceded by a letter, digit or `_ % + . -`, not followed by a letter, digit, `_` or `-`; a `.git` suffix belongs to the URL), and a declared email is also exempt from the EMAIL pattern. Blanking keeps the text length, so your name or handle written ANYWHERE ELSE on the line, even right next to the declared token, is still a finding, and so is a longer token (`<url>-fork`). The gate prints how many occurrences it blanked, per file (paths and counts only), and lists the declared entries only in masked form, for example `release_gate: public identity: 2 declared (url:h***(34), email:c***(19)); 3 occurrence(s) blanked in 1 file(s)`. The scrubber is not affected: it still replaces these values with tokens unless you also list the email in `allow_emails`. Tests: `tests/test_public_identity.py`.

## Rebuilding annotations after hand edits
`python3 reannotate.py --release-root ~/release_work` rescans the FINAL staged text (every file and file name) for placeholders and rewrites each component's `ANNOTATIONS.md`, `ANNOTATIONS.json` and `staging/PLACEHOLDERS_INDEX.md`, so line/column numbers always match what is published. It never reads private values and never touches the private hash copy. Optional `--meanings file.json` adds `{"KEY": {"meaning": "...", "example": "...", "where": "..."}}` entries.

## Hot-swap details
**For users of a published repo** (you only downloaded a published component and want your own values in it): nothing else is needed from the publisher. Keep this kit (the repository root) next to the component, make a values file as below, and run `python3 hotswap.py --component-dir <the downloaded component folder> --values ~/my_values.json --out ~/my_copy --release-root <any folder that is NOT the place you keep your values file and that you do not write real data into, for example an empty new folder>`. `--release-root` is only used to refuse an `--out` inside that tree, and the tool prints nothing about which root it used, so keep your `--out` outside both the component and the downloaded repo.

`my_values.json` is `{"OWNER_NAME": "...", "HOST_1": "..."}` (chmod 600, outside the release root). Refuses if any `{{TOKEN}}` is unresolved unless `--allow-partial`; `--out` must be new/empty and outside the release root and the component (it never overwrites). The output holds your REAL values, so every file is created mode 0600 (0700 if the staged file was executable) and every new folder 0700; other group/other permission bits of the staged files are not copied. A staged file that is not UTF-8 text makes the run fail (binary files cannot be hot-swapped; copy them by hand). To restore the original tree, pass the private values file plus `--restore ~/.config/twu_release/restore.private.json`; with the salt present each restored value is checked against the private annotation hashes. The tests prove a byte-identical round trip (content, file names, owner exec bit; group/other permission bits are dropped on purpose) for exact and pattern replacements, CRLF, no trailing newline, unicode. Prefix renames (`rename_prefixes`) and the allowlist are one-way: hot-swap cannot undo a prefix rename.

## Threat model and honest limits

Protects against: accidentally publishing known private strings (also hidden by the Unicode, escape, encoding and line-split tricks above), common identifier shapes, secrets, and wrong file types, with an independent gate that recomputes from the private file.

Does NOT protect against:
- **Prose that identifies the owner by context** (a story, a unique job title, a rare project name, a relative described by role). Only listed values and the pattern shapes are found. Review diffs by eye.
- **Images, PDFs, archives, binaries**: refused, never inspected. EXIF, screenshots, and text inside images are out of scope. Do not "fix" by allowlisting them.
- **Git history**: the tools scrub the working copy only. Publish from a fresh repository (no history) of the gated staging tree; never push your source workspace's history.
- **Evasions the gate does not see** (each is a way of writing a value that a human can still read or a program can rebuild; the gate looks for the plain value and the disguises listed under "How it works", nothing else):
  - a value split over THREE or more lines (two consecutive lines are handled);
  - comments, markup or tags between its letters (`zq/**/uill`, `zq<!-- -->uill`, `<span>zq</span><span>uill</span>`), including the text runs inside a docx (docx is refused by type anyway);
  - separators between the letters of a single-word value that are longer than 3 characters, or separators inside the words of a multi-word value other than the 0-3 punctuation characters the gate already allows;
  - percent-encoding applied three or more times; octal (`\172`) and `\N{NAME}` escapes; named HTML entities (`&amp;`-style); other encodings: base32, ascii85, base64 applied twice, lists of decimal or hex character codes, JSON arrays of single characters, leetspeak (`z3bed1ah`), ciphers other than rot13, compressed data in bz2/xz/7z (these are refused by type or not opened);
  - look-alike letters that are not in the built-in Cyrillic/Greek table (dotless i, letters with a stroke, small capitals, Cherokee, Armenian);
  - base64 of a value with unusual casing (only upper, lower, title and as-written are tried);
  - text assembled by running code, or images of text;
  - more encodings (none are decoded): UTF-7 (`+AHoAcQB1-`), quoted-printable (`z=71uill`, `=7A=71...`), CSS escapes (`\7a quill`, `\00007a`), `U+007A U+0071` lists, decimal character lists (`[122,113,...]`), binary (`01111010`), other-script digits (Arabic-Indic), rot47, Caesar/Atbash ciphers;
  - base64 with spaces inside it or wrapped over three or more lines (two lines are handled), reversed word order, initials (`Z. Q.`);
  - TRUNCATION: a truncated value is not a finding. Only a value, a distinctive word of it (4+ letters, 7+ digits) or a run of words is looked for, so a prefix of a word (`zquill` for `zquill77`) is not a finding.
  Add each form you care about as its own key. Fixed since the first release of this kit (so they are no longer on this list): `%u007a` escapes and `\uD835\uDC33`-style surrogate-pair escapes (one character), percent-encoding of every character (single and double), VT/FF/NEL/U+2028/U+2029 inside a word, `\UXXXXXXXX` and `\u{X}` escapes, numeric entities without a semicolon, and 0-3 separator characters inside a single-word value of 6+ characters.
- **Pattern limits** (emails, IPs, paths, secrets). The pattern classes recognise common SHAPES only. Read this list before you trust a PASS:
  - Home paths: matched are `/Users/x`, `/home/x`, `/USERS/x`, `/HOME/x` at the start of a path, and after `file://` (`file:///Users/x`), `/System/Volumes/Data`, `/Volumes/<disk>`, `/mnt/<drive>`, `/usr`. NOT matched: a home path glued to a preceding word or folder in any other way (`projectsx/Users/name`), a bare lower-case `/users/name` (it is indistinguishable from a web route such as `/users/alice`; a lower-case `/users/` IS matched after the volume prefixes above), `/root/`, `~name`, `/var/mobile/...`, Windows `C:\Users\name\...`. Generic names (`user`, `you`, `name`, `username`, `yourname`, `example`, `runner`, `shared`, `me`, `someone`, `foo`, `bar`, `test`, `guest`, in any case) are deliberately left alone, so `/Users/guest/x` or `/Users/test/x` is NOT a finding even if it is a real account.
  - Passwords: `password = "..."`, `pwd:`, `passwd=` with a QUOTED value of any length is replaced only when the value holds a digit or one of ``!@#$%^&*+=~|\;`` (so UI labels and "your-password-here" stay untouched); short or letters-only passwords and pass-phrases (`"correct horse battery staple"`), unquoted values under 20 characters and `password` written another way are NOT found.
  - Vendor tokens: found are `sk-`, `sk_live_`/`rk_live_`/`pk_live_`, `ghp_` family, `github_pat_`, `xox*-`, `AKIA` and `ASIA` key ids, `AIza`, `hf_`, `npm_`+36, `glpat-`, `pypi-`, SendGrid `SG.x.y`, Slack webhook URLs, `Bearer <20+ chars>` and JWTs. NOT found: any other vendor's tokens, upper-case `SK-`, `sk-` shorter than 20 characters, unlabelled 40-hex or AWS secret keys, a key body without its header, PuTTY `Private-Lines`, URL-safe WireGuard keys.
  - Private-key headers: found in any case, with extra spaces, and with invisible, fullwidth or escaped characters; a key written without its `BEGIN` line is not.
  - Phones, MACs, IPs, hostnames: phones need a separator (`(555)123-4567`, `555-123-4567`, `555.123.4567` and the en/em-dash forms are found; `555/123/4567`, `555 - 123 - 4567`, bare 10 digits without a label, UK/international numbers other than `+` and 10-14 digits, spelled-out numbers are not). MACs: `aa:bb:..`, `aa-bb-..`, Cisco `aabb.ccdd.eeff` and a bare 12-hex address only when labelled (`mac: aabbccddeeff`); space-separated and EUI-64 IPv6 forms are not. IPs: private ranges, also written with leading zeros (`010.001.002.003`); NOT public IPs, IPv6, link-local `169.254.x.x`, hex/decimal-written IPs (`0xC0A80105`, `3232235777`), `10 . 1 . 2 . 3`, `10,1,2,3`, an address split over two lines, defanged IPs and emails (`10.0.0[.]5`, `name at example dot com`), 2-3 octet fragments (except 192.168.x). Hostnames: `*.local`, `*.lan`, `*.home.arpa`, `*.ts.net`, `*.beta.tailscale.net` in any case; NOT `.internal`, `.corp`, `.localdomain` or other private DNS names, and not `user@host` without a dot (`ssh deploy@nas`, `smb://nas/share`, `\\NAS\share`).
  - Emails: quoted local parts (`"john doe"@corp.test`), `noreply@any-domain` and any `no-reply@...` are left alone on purpose; `git@host:path` clone URLs, `package@1.2.3` / `action/x@v1.2.3` version pins and `icon@2x.png` file names are not treated as emails. Identifiers: UEI/EIN/DUNS without their usual shape or label, names shorter than 3 chars.
- Pattern false positives (a file name that ends in `.local`, `x@2y.io`) are replaced too; they are reversible, just noisy. The rot13/reversed checks skip candidates under 6 characters to limit accidental matches, so short values are only checked in plain, folded and split forms.
- The salted hashes in the private annotations copy are only as strong as the secrecy of your salt; low-entropy values (a short phone number) are guessable by anyone who gets the salt. Keep the values file private.
- `exclude_exceptions` in a manifest and `gate_public_phrases` are trusted by the gate; review them.
- Two scrubs of DIFFERENT components at the same moment are safe for the restore map (the read-merge-write is under a file lock, `.restore.lock` next to the map); two scrubs of the SAME component at once are not supported (each one deletes and rebuilds that component's folder).
- A `staging/<component>` that is a symlink is refused with an error; remove the link.
- Hot-swap stops before writing anything when two staged names would become one name after filling (for example `{{A}}.txt` and `{{B}}.txt` with equal values), and on a FIFO or other special file in the component.
- Regex scans are heuristic: **a PASS means nothing known was found, not that the tree is safe.** Read the staged tree yourself before publishing.
- Speed: the gate is linear but slow on huge single-line files (about 1.7 s per MB of one line). The scrubber refuses files over 5 MB, so this only matters for files you add to `staging/` by hand.

## Limits of the one-command verifier (`release.py`)

- Carriers: `.gz`, zip/docx/xlsx/pptx/odf, tar are opened (depth 3, size/ratio caps). Not opened: `.7z`, `.rar`, `.bz2`, `.xz`, encrypted zips, compressed streams inside docx media, images (EXIF/OCR), PDF streams that are not flate (LZW, DCT, encrypted), SQLite free pages beyond printable-string search, base64 blobs inside other formats.
- PDFs and SQLite: printable ASCII/UTF-16LE strings only; a value stored split, compressed or encoded is missed.
- Metadata check covers docProps/core.xml, app.xml, odf meta.xml, PDF Info dictionary (not XMP, not Producer).
- Git step verifies commit metadata and tracked names; file contents were scanned before commit, not re-read from objects.
- The shell check (`templates/check_placeholders.sh`) has an opt-in house-style rule for marketing words ("production-grade", "100% verified", "battle-tested"): it is OFF unless you set `CHECK_PLACEHOLDERS_OVERCLAIM=1`. It does not scan folders named `templates` or `node_modules`, and it skips any file named `ci.yml` or `check_placeholders.sh` at ANY depth (the Python gate still scans all of them); the generated pages (`ANNOTATIONS.*`, `REFUSED.md`, `PLACEHOLDERS_INDEX.md`) are skipped only at their real place (root or component root), so a copy deeper in the tree is checked. Generic example home paths (`/Users/you/...`, `/home/user/...`, the same names the scrubber leaves alone) pass; a real name fails. Token prefixes (`sk-`, `ghp_`, ...) must start a word, the same rule as the scrubber, so `disk-allocationstrategyinfo2` is not a token. Options are listed at the top of the script.
- Syntax gate has no validator for yaml/toml/js/md; a shell not installed is skipped silently.
