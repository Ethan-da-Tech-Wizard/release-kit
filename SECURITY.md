# Security policy

This is a prototype-stage project maintained by one person (Ethan Kilmer, TWU LLC). There is no bounty and no response-time promise; I will reply when I can.

## How to report a vulnerability

Private vulnerability reporting is enabled on this repository.

1. Open the repository's **Security** tab, choose **Report a vulnerability**, and fill in the form. Only you and the maintainer can see it.
2. Or email **ethan@twu.software** with steps to reproduce.

Please do not open a public issue or pull request with exploit details. Do not include real secrets, real private hostnames or real personal data in a report; use made-up values that show the same shape.

## Scope

In scope: the code in this repository, in particular cases where `release_gate.py` or `release.py` reports PASS although a known private value or a documented pattern class is still present in the tree, where a tool writes or reads outside the folders it documents, where a private values file or salt can leak into output, and where the isolation layers of `hermetic_run.py` claim to be active when they are not.

Out of scope: your environment and other tools, social engineering, and anything listed as a known limit.

## What is not a boundary

- A PASS from the gate means nothing known was found. It is not a proof that a tree is safe. Evasions the gate does not see are listed in [docs/REFERENCE.md](docs/REFERENCE.md#threat-model-and-honest-limits); reporting one of those as a vulnerability is welcome but it is a known limit, not a new finding.
- `hermetic_run.py` is a test-isolation aid, not a security sandbox. `OS_ENFORCED` means its canary probes passed on that run. On macOS it uses the deprecated `sandbox-exec`; the Linux path is written but unverified.
- The tools run with your privileges and trust the values file and the manifest you give them.
- Windows is not supported.

Supported version: the latest commit on the default branch.
