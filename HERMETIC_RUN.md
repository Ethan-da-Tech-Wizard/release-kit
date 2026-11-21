# hermetic_run

Runs a command (usually a unit-test suite) in layered isolation and writes a receipt that states which layers were verified active. Stdlib only, Python 3.9+, no network, no sqlite.

    python3 hermetic_run.py --src path/to/component --out receipt.json -- python3 -B -m unittest discover -s scripts -p 'test_*.py'

Point `-s` at the folder that really holds the tests (`scripts/` in the example). A wrong folder runs ZERO tests: unittest then still prints `Ran 0 tests ... OK` and exits 0, which would otherwise earn an `OS_ENFORCED` receipt for nothing. hermetic_run therefore scans the full output for `Ran 0 tests` / `collected 0 items` / `no tests ran`, sets `zero_tests: true` and a `warning` in the receipt, prints `WARNING: the command ran 0 tests`, and turns a command exit 0 into exit 4. `--allow-zero-tests` switches that off (for commands that are not test runners).

Flags: `--allow-zero-tests`, `--allow-loopback` (Seatbelt only), `--require-os` (exit 3 and refuse to run unless all OS layers verified), `--soft-only` (skip OS sandbox), `--timeout`, `--pass-env NAME` (allow one extra env var by name; passing HOME, XDG_*, TMPDIR, PATH, LANG, LC_ALL, TZ or PYTHON* replaces the safe value with the host's, so the receipt then marks the matching layer NOT_ACTIVE; the label drops to NONE only when the pass-through breaks the env scrub itself, for example PATH), `--json`, `--no-tail`.

## Layers
| layer | what | how it is shown ACTIVE |
|---|---|---|
| env_scrub | env rebuilt from allowlist (PATH, LANG, TZ, HOME, TMPDIR, XDG_*, PYTHONDONTWRITEBYTECODE, PYTHONHASHSEED=0, PYTHONNOUSERSITE) | sentinel env var set in parent is absent in child |
| home_redirect, fresh_tmp | HOME/XDG and TMPDIR in an empty temp root | by construction (receipt says so) |
| tree_copy | command runs in a copy of `--src` (skips .git, caches); source digest compared before/after | `source_unchanged` |
| os_net_deny | macOS Seatbelt `deny network*`; Linux bwrap `--unshare-all` or `unshare -rn` | canary |
| os_fs_write_deny | Seatbelt denies writes outside the temp root (Linux bwrap: read-only root) | canary |
| os_home_read_deny | Seatbelt denies reads of the home directory of the invoking ACCOUNT (from the password database, not from `$HOME`) and of `$HOME` too when that points elsewhere; bwrap masks both with tmpfs | canary (lists the account's real home) |

## Canaries and the label
Before the real command, a canary runs twice: plain (must succeed at: loopback connect to a local 127.0.0.1 listener, listing the real home, writing outside the temp root, reading a sentinel env var; external connect to 192.0.2.1 must not be reported as an OS denial) and wrapped (each must fail: external connect gets EPERM, home listing denied, outside write denied, sentinel absent). An OS layer is ACTIVE only if the plain run succeeded and the wrapped run was denied, so a broken probe cannot count as proof. No external traffic is made by the plain side; the non-routable address is only used to see that the sandbox answers EPERM.

- `OS_ENFORCED`: env scrub plus all three OS layers proved by the canary on this run.
- `SOFT`: copy, HOME/TMPDIR redirect and env scrub active, but OS layers not all proved (sandbox missing, blocked, nested, or only partly proved). The receipt lists `os_layers_proved`. When at least one OS layer was proved the command IS still run inside the sandbox (`wrapped_with_os_sandbox: true`), and every layer that was not proved is reported NOT_ACTIVE; when none was proved the command runs unwrapped (`wrapped_with_os_sandbox: false`). Example: on Linux with only `unshare -rn`, only the NETWORK is isolated; files are not. Anything running as the same user can still reach whatever an unproved layer would have blocked.
- `NONE`: soft layers not all active (e.g. copy failed).

## Honest limits
- Linux path (bwrap, `unshare -rn`) is written but NOT verified (only macOS has been tested). Treat it as untested until a Linux host runs the test suite; canaries will tell the truth at runtime. `unshare -rn` gives network only, so the label stays SOFT there. `--allow-loopback` is not implemented for Linux (loopback is down in a new net namespace).
- Seatbelt (`sandbox-exec`) is deprecated by Apple but works. It cannot be applied from inside another sandbox; the probe then reports the OS layers NOT_ACTIVE and the label is SOFT. It filters syscalls by policy; it is not a VM and does not limit CPU or memory.
- Reads outside the real home (system files, other users' data readable by you, /Volumes) are not blocked. Only the home directory of the invoking account (and `$HOME` when different) is denied. If the interpreter lives under the real home, that prefix is re-allowed for reads.
- Processes that already hold file descriptors or Mach/XPC services (e.g. talking to system daemons) are not blocked by network or file policy; a ctypes call that reaches a kernel interface not covered by the profile is not constrained. Test code that spawns detached daemons is killed only via its process group.
- `PATH` inside the child is only `/usr/bin:/bin:/usr/sbin:/sbin`. Commands installed elsewhere (pytest, node, brew or version-manager tools) are not found by name; give an absolute path. A bare `python`/`python3` is mapped to the interpreter that runs hermetic_run.
- `LC_ALL`/`LANG` are set to `C.UTF-8`, which is not a real macOS locale; treat the locale as unpinned there.
- Linux/bwrap: an interpreter installed under the home directory (pyenv, a version manager) is hidden by the tmpfs and will not start inside the sandbox, so the canary fails and the label is SOFT. Use a system interpreter there.
- The label `OS_ENFORCED` means "the canary probes passed in this run" (one TCP connect, one home listing, one sibling-folder write), not a proof of every possible escape.
- Output tail (last 20 lines) is stored in the receipt; use `--no-tail` if tests print sensitive values. The command argv is recorded as given.
- Clock is not pinned (TZ=UTC only). Seatbelt violations are not logged; the receipt reports layers, not per-violation traces.
