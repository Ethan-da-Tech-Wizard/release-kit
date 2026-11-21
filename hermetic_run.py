#!/usr/bin/env python3
"""hermetic_run: run a command (typically a unit-test suite) inside layered
isolation and write a receipt that says exactly which layers were ACTIVE.

Usage:
  hermetic_run.py [--src DIR] [--allow-loopback] [--require-os] [--soft-only]
                  [--timeout SEC] [--pass-env NAME ...] [--out receipt.json]
                  [--json] [--no-tail] -- COMMAND [ARG ...]

Layers (each reported ACTIVE or NOT_ACTIVE, never assumed):
  env_scrub        environment rebuilt from a small allowlist
  home_redirect    HOME / XDG_* point at an empty temp dir
  fresh_tmp        TMPDIR is a fresh temp dir
  tree_copy        command runs in a COPY of --src; source is never modified
  os_net_deny      OS blocks outbound network (macOS Seatbelt, Linux unshare/bwrap)
  os_fs_write_deny OS blocks file writes outside the temp root
  os_home_read_deny OS blocks reads of the real home directory

isolation_level: OS_ENFORCED only if a canary run, using the same wrapper,
proved all three OS layers AND the env scrub. SOFT if the soft layers are
active but the OS layers were not all proved: in that case the command is still
wrapped when the canary proved at least one OS layer (receipt field
os_layers_proved lists them; e.g. Linux with only `unshare -rn` isolates the
network and nothing else), and is NOT wrapped when none was proved
(wrapped_with_os_sandbox says which).  NONE otherwise.
"Real home" means the account's passwd home directory, not $HOME; the sandbox hides
both when they differ.
Python 3.9 stdlib only. No network, no sqlite, no third-party code.

Why this exists
---------------
"The tests pass" is only meaningful if the tests could not have quietly used the
developer's real home directory, environment variables, network or files.  This
tool runs a command in a copy of a tree under strict isolation and records a
machine-readable receipt of which protections were really in force.

Design notes / threat model
---------------------------
* Honest reporting: a layer is ACTIVE only when a canary program, run both
  without and with the wrapper, proved it (works outside, denied inside).  An
  unverified layer is reported NOT_ACTIVE rather than assumed.
* Aims to stop accidental leakage and accidental side effects of test code
  (reading personal files, network calls, writing outside a temp dir).  It is not
  a security boundary against deliberately hostile code.
* The source tree is copied, never modified; a before/after digest of the source
  is recorded as ``source_unchanged``.
* The child gets a rebuilt environment; only names listed with --pass-env are
  copied from the host.
* The receipt stores only the base name of the source directory.

Example
-------
    hermetic_run.py --src ./project --out receipt.json -- python3 -B -m unittest discover -s scripts -p 'test_*.py'
(-s must point at the folder that really holds the tests; a wrong folder runs ZERO tests, see below.)

Zero-test guard: a test command that exits 0 after running no tests proves nothing, yet a receipt would still say
OS_ENFORCED.  The full output is checked for "Ran 0 tests" (unittest), "collected 0 items" / "no tests ran"
(pytest).  When found, the receipt gets ``zero_tests: true`` and a ``warning``, the text summary prints
"WARNING: the command ran 0 tests", and a command that exited 0 is turned into exit code 4.  Pass
--allow-zero-tests when the command is not a test runner or an empty run is expected.

Exit status is the command's exit code (3 when --require-os cannot be satisfied,
2 when no command ran, 4 when the command exited 0 but ran zero tests).
"""
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

# Name of an environment variable the canary sets in the parent; the scrubbed child must not see it.
SENTINEL_VAR = "HERMETIC_CANARY_SENTINEL"
# Layers achievable without OS help (pure Python process setup).
SOFT_LAYERS = ("env_scrub", "home_redirect", "fresh_tmp", "tree_copy")
# Layers that need an OS sandbox (Seatbelt on macOS, bwrap/unshare on Linux).
OS_LAYERS = ("os_net_deny", "os_fs_write_deny", "os_home_read_deny")
# Glob patterns skipped when copying the source tree (VCS data, caches, vendored deps).
COPY_IGNORE = (".git", "__pycache__", "*.pyc", ".DS_Store", "node_modules")
# Minimal PATH for the child: system tool directories only, no user-installed locations.
MIN_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# macOS command-line front end to the Seatbelt sandbox.
SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# Canary executed inside and outside the wrapper. Prints one JSON object.
CANARY_SRC = r'''
import errno, json, os, socket, sys
a = json.loads(sys.argv[1])
r = {}
def classify(e):
    if isinstance(e, PermissionError) or getattr(e, "errno", None) in (errno.EPERM, errno.EACCES):
        return "denied"
    return "error:" + type(e).__name__
def conn(host, port):
    s = socket.socket(); s.settimeout(1.0)
    try:
        s.connect((host, port)); return "ok"
    except Exception as e:
        return classify(e) if classify(e) == "denied" else ("unreachable" if host != "127.0.0.1" else classify(e))
    finally:
        s.close()
r["net_loopback"] = conn("127.0.0.1", a["port"])
r["net_external"] = conn("192.0.2.1", 80)
try:
    os.listdir(a["real_home"]); r["read_home"] = "ok"
except Exception as e:
    r["read_home"] = classify(e)
try:
    with open(os.path.join(a["outside_dir"], "canary_write.txt"), "w") as f:
        f.write("x")
    r["write_outside"] = "ok"
except Exception as e:
    r["write_outside"] = classify(e)
r["env_sentinel"] = "ok" if os.environ.get(a["sentinel"]) else "absent"
print("CANARY_JSON=" + json.dumps(r))
'''


def macos():
    """True when running on macOS (Darwin)."""
    return sys.platform == "darwin"


def linux():
    """True when running on Linux."""
    return sys.platform.startswith("linux")


def real_home():
    """Return the invoking ACCOUNT's real home directory (symlinks resolved).

    Taken from the password database (pwd.getpwuid(os.getuid()).pw_dir), NOT from
    $HOME.  $HOME is just an environment variable: anyone (or any wrapper script)
    can point it at a scratch folder, and then expanduser("~") would "protect" the
    wrong directory while the account's real home stayed readable.  Falls back to
    expanduser only when the account has no passwd entry (rare containers).
    """
    try:
        import pwd                      # POSIX only; this tool supports macOS and Linux
        return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        return os.path.realpath(os.path.expanduser("~"))


def denied_homes():
    """Return the list of home directories the sandbox must hide: the passwd-derived
    real home FIRST, then $HOME (resolved) when it points somewhere else.

    Both are denied because either one may hold personal files: the account's real
    home is the obvious one; $HOME is what ordinary programs consult, so a test that
    reads "~/..." would otherwise reach it.  Duplicates are removed.
    """
    out = [real_home()]
    env_home = os.environ.get("HOME")
    if env_home:
        rp = os.path.realpath(env_home)
        if rp not in out and rp != os.sep:   # never "deny /" (that would break the child)
            out.append(rp)
    return out


def _q(path):
    """Quote PATH as a double-quoted Seatbelt string literal (escape backslash and quote)."""
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_seatbelt_profile(root, home, allow_loopback=False, extra_read_ok=()):
    """Seatbelt profile text. Later rules win in SBPL, so denies precede allows.

    Args:
        root: temp root the child may write to (and read from when home is denied).
        home: real home directory (str) or a list/tuple of home directories to hide
            from reads (see denied_homes); falsy disables that rule.
        allow_loopback: permit 127.0.0.1-only networking when True.
        extra_read_ok: extra directories to re-allow for reading (e.g. an
            interpreter installed under the home directory).
    Returns: the profile as a newline-terminated string.
    Edge case: if root itself lies under home, the home read-deny is skipped,
    otherwise the child could not read its own working copy.
    """
    root = os.path.realpath(root)
    # Start permissive, then deny network; later rules override earlier ones.
    lines = ["(version 1)", "(allow default)", "(deny network*)"]
    if allow_loopback:
        lines += ['(allow network-bind (local ip "localhost:*"))',
                  '(allow network-inbound (local ip "localhost:*"))',
                  '(allow network-outbound (remote ip "localhost:*"))']
    # Deny all writes, then re-allow the temp root and a few harmless device files.
    lines += ["(deny file-write*)",
              "(allow file-write* (subpath %s))" % _q(root),
              '(allow file-write* (literal "/dev/null") (literal "/dev/tty") '
              '(literal "/dev/dtracehelper") (regex #"^/dev/fd/"))']
    homes = [home] if isinstance(home, str) else list(home or [])
    for h in homes:
        # Skip a home that CONTAINS the temp root (otherwise the child could not
        # read its own working copy).  Every other home gets its own deny rule.
        if h and not (root + os.sep).startswith(h + os.sep):
            lines.append("(deny file-read* (subpath %s))" % _q(h))
    if any(h and not (root + os.sep).startswith(h + os.sep) for h in homes):
        # Re-allow rules come AFTER every deny (later rules win in SBPL).
        lines.append("(allow file-read* (subpath %s))" % _q(root))
        for p in extra_read_ok:
            lines.append("(allow file-read* (subpath %s))" % _q(os.path.realpath(p)))
    return "\n".join(lines) + "\n"


def build_env(root, extra=()):
    """Return the scrubbed environment. Values are fixed, never copied from the host
    except for names the caller explicitly passes through (--pass-env)."""
    home = os.path.join(root, "home")      # empty stand-in home directory
    env = {
        "PATH": MIN_PATH,
        "LANG": "C.UTF-8",             # fixed locale and timezone for reproducible output
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HOME": home,
        "TMPDIR": os.path.join(root, "tmp"),
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "XDG_CACHE_HOME": os.path.join(home, ".cache"),
        "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
        "XDG_STATE_HOME": os.path.join(home, ".local", "state"),
        "PYTHONDONTWRITEBYTECODE": "1",   # no .pyc files; stable hash seed; ignore user site-packages
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
    }
    for name in extra:                 # explicit pass-through, only if set on the host
        if name in os.environ:
            env[name] = os.environ[name]
    return env


# Variables build_env() sets itself, and the layer each one backs.  A --pass-env of one of these names replaces the
# safe value with the host's, so that layer cannot be claimed (F1).
_REDIRECTED = {"HOME": "home_redirect", "TMPDIR": "fresh_tmp", "PATH": "env_scrub", "LANG": "env_scrub",
               "LC_ALL": "env_scrub", "TZ": "env_scrub", "PYTHONDONTWRITEBYTECODE": "env_scrub",
               "PYTHONHASHSEED": "env_scrub", "PYTHONNOUSERSITE": "env_scrub"}


def overridden_layers(pass_env):
    """List (name, layer, why) for every --pass-env name that overrides a value build_env() sets and that exists on the
    host (HOME/XDG_* -> home_redirect, TMPDIR -> fresh_tmp, PATH/LANG/LC_ALL/TZ/PYTHON* -> env_scrub).
    Example: with HOME set on the host, overridden_layers(["HOME"]) == [("HOME", "home_redirect", "...")]."""
    out = []
    for name in pass_env:
        if name not in os.environ:
            continue
        layer = "home_redirect" if name.startswith("XDG_") else _REDIRECTED.get(name)
        if layer:
            out.append((name, layer, "overridden by --pass-env"))
    return out


def probe_os_sandbox(allow_loopback=False):
    """Honest availability probe. Returns (kind, note); kind in seatbelt/unshare/bwrap/None.

    Actually tries a trivial sandboxed command instead of only checking that a
    binary exists, since sandboxes can be blocked when nested.  ``note`` is a short
    human-readable reason.  allow_loopback is accepted for symmetry but unused here.
    """
    if macos():
        if not os.path.exists(SANDBOX_EXEC):
            return None, "sandbox-exec not present"
        try:
            p = subprocess.run([SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except Exception as e:
            return None, "sandbox-exec probe failed: " + type(e).__name__
        if p.returncode != 0:
            return None, "sandbox-exec cannot apply a profile here (rc=%d; nested or blocked)" % p.returncode
        return "seatbelt", "sandbox-exec usable"
    if linux():
        bwrap = shutil.which("bwrap")
        if bwrap:
            p = subprocess.run([bwrap, "--unshare-net", "--ro-bind", "/", "/", "true"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if p.returncode == 0:
                return "bwrap", "bwrap usable"
        un = shutil.which("unshare")
        if un:
            p = subprocess.run([un, "-rn", "true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if p.returncode == 0:
                return "unshare", "unshare -rn usable (network only, no filesystem layer)"
        return None, "neither bwrap nor unshare -rn usable"
    return None, "no OS sandbox implemented for this platform"


def wrap_argv(argv, kind, root, home, allow_loopback, extra_read_ok=()):
    """Wrap argv with the OS sandbox of the given kind. Returns the final argv.

    HOME may be one directory (str) or a list of directories to hide.

    kind "seatbelt": sandbox-exec with a generated profile.  "bwrap": read-only
    root bind, new namespaces, tmpfs over the real home, writable temp root.
    "unshare": network namespace only.  Any other kind returns ARGV unchanged.
    """
    if kind == "seatbelt":
        prof = build_seatbelt_profile(root, home, allow_loopback, extra_read_ok)
        return [SANDBOX_EXEC, "-p", prof] + argv
    if kind == "bwrap":
        # --unshare-all includes the network namespace; --die-with-parent cleans up orphans.
        cmd = [shutil.which("bwrap"), "--unshare-all", "--die-with-parent",
               "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
        for h in ([home] if isinstance(home, str) else list(home or [])):
            if h and os.path.isdir(h) and not (os.path.realpath(root) + os.sep).startswith(h + os.sep):
                cmd += ["--tmpfs", h]
        cmd += ["--bind", os.path.realpath(root), os.path.realpath(root)]
        return cmd + argv
    if kind == "unshare":
        return [shutil.which("unshare"), "-rn"] + argv
    return argv


def _prefix_under_home(home):
    """Return interpreter install directories that live under HOME (a str or a list of homes).

    These must stay readable inside the sandbox even though the rest of the home
    directory is hidden, or the child could not start Python.
    """
    homes = [home] if isinstance(home, str) else list(home or [])
    out = []
    for p in {sys.prefix, sys.base_prefix, os.path.dirname(os.path.realpath(sys.executable))}:
        rp = os.path.realpath(p)
        if any((rp + os.sep).startswith(h + os.sep) for h in homes) and rp not in out:
            out.append(rp)
    return out


def _resolve_argv0(argv):
    """Map a bare "python"/"python3"/"{python}" command to the running interpreter."""
    if argv and argv[0] in ("python", "python3", "{python}"):
        return [sys.executable] + argv[1:]
    return argv


def _exec_target(argv):
    """Resolve ARGV[0] through symlinks BEFORE it goes into the sandbox command line.

    Why: a launcher symlink that lives under the (read-denied) home directory, such as ~/.local/bin/python3 ->
    a version manager's install directory, cannot be exec'd by sandbox-exec ("Operation not permitted") even though its real target
    is re-allowed by _prefix_under_home.  Executing the resolved path works and runs the very same binary.
    """
    if argv and os.sep in argv[0]:
        return [os.path.realpath(argv[0])] + list(argv[1:])
    return argv


def run_wrapped(argv, root, kind, allow_loopback=False, extra_env=(), timeout=600,
                cwd=None, env_override=None):
    """Run argv in the scrubbed env, optionally inside the OS sandbox. Returns dict.

    Args:
        argv: command and arguments.
        root: temp root; "home" and "tmp" subdirectories are created inside it.
        kind: sandbox kind from probe_os_sandbox, or None for no OS wrapper.
        allow_loopback: permit loopback networking in the sandbox.
        extra_env: host variable names to pass through.
        timeout: seconds before the whole process group is killed.
        cwd: working directory (defaults to root).
        env_override: dict merged over the scrubbed environment.
    Returns: dict with rc, out (merged stdout/stderr text), duration, timed_out.
    rc is 127 when the process cannot be spawned and 124 on timeout.
    """
    home = denied_homes()               # passwd home + $HOME when different (see denied_homes)
    for sub in ("home", "tmp"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    env = build_env(root, extra_env)
    if env_override:
        env.update(env_override)
    final = wrap_argv(_exec_target(_resolve_argv0(argv)), kind, root, home, allow_loopback,
                      _prefix_under_home(home))
    t0 = time.time()
    timed_out = False
    try:
        # New session so a timeout can kill the whole process group; stdin closed.
        p = subprocess.Popen(final, cwd=cwd or root, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
    except OSError as e:
        return {"rc": 127, "out": "spawn failed: " + type(e).__name__, "duration": 0.0,
                "timed_out": False}
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:                              # kill children too, not just the direct process
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        out, _ = p.communicate()
    return {"rc": 124 if timed_out else p.returncode,
            "out": out.decode("utf-8", "replace"),
            "duration": round(time.time() - t0, 3), "timed_out": timed_out}


class _Listener(object):
    """Local 127.0.0.1 listener used only for loopback checks (no external traffic).

    Accepts and immediately closes connections on an OS-chosen port so the canary
    can tell "loopback allowed" from "loopback blocked".
    """
    def __init__(self):
        """Bind to an ephemeral loopback port and start the accept thread."""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.alive = True
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        """Accept-and-close loop; polls so close() can stop it promptly."""
        self.sock.settimeout(0.2)
        while self.alive:
            try:
                c, _ = self.sock.accept()
                c.close()
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        """Stop the accept thread and release the port."""
        self.alive = False
        self.t.join(timeout=2)
        self.sock.close()


def run_canary(kind, allow_loopback, wrapped):
    """Run the canary once, wrapped (kind) or plain (wrapped=False). Returns dict or None.

    The canary reports, for each capability (loopback and external network, reading
    the real home, writing outside the root, seeing the sentinel variable), whether
    it was "ok", "denied" or another outcome.  Returns None if no result line was
    produced (e.g. the sandbox killed the process).
    """
    listener = _Listener()
    base = tempfile.mkdtemp(prefix="hermetic_canary_")
    root = os.path.join(base, "root")
    outside = os.path.join(base, "outside")
    os.makedirs(root)
    os.makedirs(outside)
    script = os.path.join(root, "canary.py")
    with open(script, "w") as f:
        f.write(CANARY_SRC)
    # The canary lists the passwd-derived real home, even when $HOME is overridden.
    args = json.dumps({"port": listener.port, "real_home": real_home(),
                       "outside_dir": outside, "sentinel": SENTINEL_VAR})
    old = os.environ.get(SENTINEL_VAR)
    os.environ[SENTINEL_VAR] = "canary-not-a-secret"   # harmless marker value, restored below
    try:
        argv = [sys.executable, script, args]
        if wrapped:
            res = run_wrapped(argv, root, kind, allow_loopback, timeout=60)
        else:                           # baseline: plain child with the real environment
            env = dict(os.environ)
            env["HOME"] = real_home()
            p = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=60, cwd=root)
            res = {"rc": p.returncode, "out": p.stdout.decode("utf-8", "replace")}
    finally:
        if old is None:
            os.environ.pop(SENTINEL_VAR, None)
        else:
            os.environ[SENTINEL_VAR] = old
        listener.close()
        shutil.rmtree(base, ignore_errors=True)
    for line in res["out"].splitlines():   # find the single result line among any other output
        if line.startswith("CANARY_JSON="):
            try:
                return json.loads(line[len("CANARY_JSON="):])
            except ValueError:
                return None
    return None


def self_test(kind, allow_loopback=False):
    """Prove both directions. Returns dict of verified layers plus evidence.

    Outside run must show every capability works (so a denial inside is the sandbox,
    not a broken probe). Inside run must show the denial.

    Returns (verified, evidence): verified maps each OS layer plus "env_scrub" to a
    bool; evidence holds the raw canary results and notes.  If the outside baseline
    fails, no layer is marked verified because a denial could not be attributed.
    """
    ev = {"kind": kind, "outside": None, "inside": None, "notes": []}
    verified = {name: False for name in OS_LAYERS + ("env_scrub",)}
    outside = run_canary(kind, allow_loopback, wrapped=False)
    ev["outside"] = outside
    if outside is None:
        ev["notes"].append("outside canary produced no result")
        return verified, ev
    # Baseline: everything must work (external network may fail as "unreachable", but not "denied").
    baseline_ok = (outside.get("net_loopback") == "ok" and outside.get("net_external") != "denied"
                   and outside.get("read_home") == "ok" and outside.get("write_outside") == "ok"
                   and outside.get("env_sentinel") == "ok")
    if not baseline_ok:
        ev["notes"].append("outside baseline did not succeed; denials cannot be attributed")
    inside = None
    if kind:
        inside = run_canary(kind, allow_loopback, wrapped=True)
    ev["inside"] = inside
    if inside is None:
        ev["notes"].append("inside canary produced no result" if kind else "no OS sandbox")
        return verified, ev
    # env scrub is proven by a wrapper-independent comparison below in run_canary callers
    verified["env_scrub"] = baseline_ok and inside.get("env_sentinel") == "absent"
    if baseline_ok:
        verified["os_net_deny"] = (inside.get("net_external") == "denied"
                                   and (inside.get("net_loopback") == "ok" if allow_loopback
                                        else inside.get("net_loopback") == "denied"))
        verified["os_fs_write_deny"] = inside.get("write_outside") == "denied"
        verified["os_home_read_deny"] = inside.get("read_home") == "denied"
    return verified, ev


def env_scrub_selftest():
    """Soft-layer proof that works without any OS sandbox: plain subprocess with the
    scrubbed env must not see the sentinel.

    Returns True when the child saw neither the sentinel nor the real HOME.
    """
    base = tempfile.mkdtemp(prefix="hermetic_envtest_")
    old = os.environ.get(SENTINEL_VAR)
    os.environ[SENTINEL_VAR] = "canary-not-a-secret"
    try:
        env = build_env(base)
        p = subprocess.run([sys.executable, "-c",
                            "import os,sys;sys.exit(0 if os.environ.get(%r) is None "
                            "and os.environ.get('HOME')==%r else 1)" % (SENTINEL_VAR, env["HOME"])],
                           env=env, cwd=base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.returncode == 0
    finally:
        if old is None:
            os.environ.pop(SENTINEL_VAR, None)
        else:
            os.environ[SENTINEL_VAR] = old
        shutil.rmtree(base, ignore_errors=True)


def level_for(layers):
    """Summarise LAYERS (name -> {"status": ...}) as OS_ENFORCED, SOFT or NONE."""
    st = lambda n: layers.get(n, {}).get("status") == "ACTIVE"
    if all(st(n) for n in OS_LAYERS) and st("env_scrub"):
        return "OS_ENFORCED"
    if all(st(n) for n in SOFT_LAYERS):
        return "SOFT"
    return "NONE"


def hermetic_run(argv, src=None, allow_loopback=False, require_os=False, soft_only=False,
                 timeout=600, pass_env=(), tail=True, _selftest=None, allow_zero_tests=False):
    """Main entry. Returns the receipt dict.

    Args:
        argv: command to run.
        src: directory to copy and run in (default: current directory).
        allow_loopback / require_os / soft_only / timeout / pass_env: see module
            docstring.  require_os refuses to run (exit_code 3) unless all OS
            layers were proved.
        tail: include the last 20 output lines in the receipt.
        _selftest: unused; kept for test compatibility.
        allow_zero_tests: when False (default) output that says "Ran 0 tests" sets receipt zero_tests/warning and
            turns exit code 0 into 4.
    Returns: receipt dict (command, layers with evidence, isolation_level, exit
    code, duration, source_unchanged ...).  The temp root is always removed.
    """
    src = os.path.realpath(src or os.getcwd())
    # Every layer starts NOT_ACTIVE and is upgraded only on proof.
    layers = {n: {"status": "NOT_ACTIVE", "evidence": ""} for n in SOFT_LAYERS + OS_LAYERS}
    kind, note = (None, "skipped by --soft-only") if soft_only else probe_os_sandbox(allow_loopback)
    receipt = {"tool": "hermetic_run", "version": 1, "platform": sys.platform,
               "command": list(argv), "src": os.path.basename(src) or src,
               "os_sandbox_kind": kind, "os_sandbox_note": note,
               "allow_loopback": bool(allow_loopback), "pass_env_names": list(pass_env)}
    verified, ev = (self_test(kind, allow_loopback) if kind else
                    ({n: False for n in OS_LAYERS + ("env_scrub",)}, {"notes": ["no OS sandbox"]}))
    if kind is None:
        ev["outside"] = None
    receipt["canary"] = ev
    # env_scrub may be proven by the OS canary or by the simpler wrapper-free self test.
    env_ok = verified["env_scrub"] or env_scrub_selftest()
    layers["env_scrub"] = {"status": "ACTIVE" if env_ok else "NOT_ACTIVE",
                           "evidence": "sentinel env var absent in child" if env_ok else "not verified"}
    for n in OS_LAYERS:
        if verified[n]:
            layers[n] = {"status": "ACTIVE", "evidence": "canary denied inside, succeeded outside (%s)" % kind}
        else:
            layers[n] = {"status": "NOT_ACTIVE",
                         "evidence": "not verified: " + (note if kind is None else "canary did not prove it")}
    root = tempfile.mkdtemp(prefix="hermetic_run_")
    root = os.path.realpath(root)      # resolve symlinks (e.g. macOS /var -> /private/var) for sandbox rules
    work = os.path.join(root, "work")
    try:
        # symlinks=True copies links as links so nothing outside the tree is pulled in.
        shutil.copytree(src, work, symlinks=True, ignore=shutil.ignore_patterns(*COPY_IGNORE))
        layers["tree_copy"] = {"status": "ACTIVE", "evidence": "ran in copy under temp root"}
        os.makedirs(os.path.join(root, "home"), exist_ok=True)
        os.makedirs(os.path.join(root, "tmp"), exist_ok=True)
        layers["home_redirect"] = {"status": "ACTIVE", "evidence": "HOME and XDG_* set to empty temp dir"}
        layers["fresh_tmp"] = {"status": "ACTIVE", "evidence": "TMPDIR is a fresh temp dir"}
        # F1: --pass-env copies the HOST value over the redirected one (build_env applies it last).  A layer whose
        # variable was overridden did NOT do its job, so it must not be reported ACTIVE.  Only names that are really
        # set on the host count (build_env ignores the rest).
        for name, layer, why in overridden_layers(pass_env):
            layers[layer] = {"status": "NOT_ACTIVE",
                             "evidence": "--pass-env %s overrides the redirected value with the host value" % name}
    except Exception as e:
        receipt.update(exit_code=None, error="copy failed: " + type(e).__name__)
        shutil.rmtree(root, ignore_errors=True)
        receipt["layers"] = layers
        receipt["isolation_level"] = "NONE"
        return receipt
    # Wrapping rule (the code below matches this text exactly):
    #   * os_ok     = ALL three OS layers proved by the canary -> label may be OS_ENFORCED.
    #   * partial   = a sandbox kind exists and AT LEAST ONE OS layer was proved ->
    #                 we still wrap (real, but partial, protection) and the label stays
    #                 SOFT, with every unproved layer reported NOT_ACTIVE.  Example: Linux
    #                 with only `unshare -rn` isolates the NETWORK only (no filesystem layer).
    #   * otherwise (no kind, or nothing proved) -> NOT wrapped; the receipt says so.
    os_ok = all(verified[n] for n in OS_LAYERS)
    wrap_kind = kind if (kind and (os_ok or any(verified[n] for n in OS_LAYERS))) else None
    if require_os and not os_ok:
        receipt.update(exit_code=3, refused=True,
                       error="--require-os set but OS layers not all verified",
                       duration_sec=0.0)
        shutil.rmtree(root, ignore_errors=True)
        receipt["layers"] = layers
        receipt["isolation_level"] = level_for(layers)
        return receipt
    # Digest the source before and after to prove the run did not modify it.
    src_before = _tree_digest(src)
    res = run_wrapped(argv, root, wrap_kind, allow_loopback,
                      pass_env, timeout, cwd=work)
    src_after = _tree_digest(src)
    receipt.update(exit_code=res["rc"], duration_sec=res["duration"], timed_out=res["timed_out"],
                   wrapped_with_os_sandbox=bool(wrap_kind),
                   os_layers_proved=[n for n in OS_LAYERS if verified[n]],
                   source_unchanged=(src_before == src_after))
    if tail:
        receipt["output_tail"] = res["out"].splitlines()[-20:]
    zero = ran_zero_tests(res["out"])
    receipt["zero_tests"] = zero
    if zero and not allow_zero_tests:
        receipt["warning"] = "the command ran 0 tests: a passing receipt proves nothing (check the test discovery path)"
        if receipt["exit_code"] == 0:
            receipt["command_exit_code"] = 0
            receipt["exit_code"] = 4       # an empty run must not look like success
    receipt["layers"] = layers
    receipt["isolation_level"] = level_for(layers)
    shutil.rmtree(root, ignore_errors=True)
    return receipt


# Phrases of common runners that mean "nothing was tested".  Matched against the FULL output, not just the tail.
_ZERO_TESTS_RE = re.compile(r"^Ran 0 tests? in |\bcollected 0 items\b|\bno tests ran\b|^NO TESTS RAN", re.M | re.I)


def ran_zero_tests(output):
    """True if OUTPUT (merged stdout/stderr of a test command) says the runner executed zero tests.

    Example: ran_zero_tests("Ran 0 tests in 0.000s\\n\\nOK") -> True;  "Ran 6 tests in 0.1s" -> False.
    Output of a command that is not a test runner never matches, so this cannot hide a real failure.
    """
    return bool(_ZERO_TESTS_RE.search(output or ""))


def _tree_digest(path):
    """Return a SHA-256 over (relative path, size, mtime) of every file under PATH.

    Cheap change detector, not a content hash.  VCS data, bytecode caches and
    unreadable entries are ignored.
    """
    import hashlib
    h = hashlib.sha256()
    for dp, dn, fn in os.walk(path):
        dn.sort()
        dn[:] = [d for d in dn if d not in (".git", "__pycache__")]
        for f in sorted(fn):
            if f.endswith(".pyc"):
                continue
            fp = os.path.join(dp, f)
            try:
                st = os.lstat(fp)
                h.update(("%s|%d|%d" % (os.path.relpath(fp, path), st.st_size, st.st_mtime_ns)).encode())
            except OSError:
                pass
    return h.hexdigest()


def render_text(r):
    """Format receipt R as a short human-readable summary (one line per layer)."""
    lines = ["hermetic_run receipt",
             "isolation_level: %s" % r.get("isolation_level"),
             "exit_code: %s   duration: %ss   timed_out: %s" % (
                 r.get("exit_code"), r.get("duration_sec"), r.get("timed_out")),
             "os_sandbox: %s (%s)" % (r.get("os_sandbox_kind"), r.get("os_sandbox_note")),
             "source_unchanged: %s" % r.get("source_unchanged")]
    for n, v in r.get("layers", {}).items():
        lines.append("  %-18s %s" % (n, v["status"]))
    if r.get("warning"):
        lines.append("WARNING: " + r["warning"])
    if r.get("error"):
        lines.append("error: " + r["error"])
    return "\n".join(lines)


def main(argv=None):
    """Command line entry point; see module docstring.

    Returns the child's exit code, or 2 if the run produced no numeric exit code
    (e.g. the tree copy failed).  The description line for --help is the first
    line of this module's docstring.
    """
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", default=None)
    ap.add_argument("--allow-loopback", action="store_true")
    ap.add_argument("--require-os", action="store_true")
    ap.add_argument("--soft-only", action="store_true")
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--pass-env", action="append", default=[])
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-tail", action="store_true")
    ap.add_argument("--allow-zero-tests", action="store_true",
                    help="do not warn/fail when the command output says it ran 0 tests")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)   # everything after "--" is the command
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("COMMAND required after --")
    r = hermetic_run(cmd, a.src, a.allow_loopback, a.require_os, a.soft_only,
                     a.timeout, a.pass_env, not a.no_tail, allow_zero_tests=a.allow_zero_tests)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(r, f, indent=2, sort_keys=True)
    print(json.dumps(r, indent=2, sort_keys=True) if a.json else render_text(r))
    return r["exit_code"] if isinstance(r.get("exit_code"), int) else 2


if __name__ == "__main__":
    sys.exit(main())
