# Security policy

## Reporting a vulnerability

Report privately through GitHub's security advisories:
[open a draft advisory](https://github.com/bcoles/kasld/security/advisories/new).
The report stays private until a fix is published. Do not open a public issue
for a vulnerability in this project's own code.

A report that falls into one of the out-of-scope cases below will be answered
with a pointer to where it belongs rather than an advisory.

## In scope

KASLD runs each component as a separate program and parses its output in the
orchestrator, which is usually the more privileged process in a run. That
asymmetry, and the untrusted input a run consumes, are where the interesting
surface is:

- **Orchestrator parsing.** `src/orchestrator.c` consumes component stdout, ELF
  section payloads and `dmesg` — input an unprivileged process can influence —
  inside the privileged process. Memory-safety, over-read or unbounded-loop
  bugs there are a genuine exposure surface; `tests/fuzz` covers these parsers,
  so a crashing input is directly actionable.
- **Captured trees.** `KASLD_SYSROOT` redirects every kernel-fact path a run
  reads to a copy of another system's `/proc`, `/sys` and `/boot`, and
  `extra/collect` produces such trees to be analysed elsewhere. A tree is
  untrusted input — it comes from the machine under investigation, and its
  directory names and extraction path are as much a part of it as its file
  contents. Analysing one must not execute code from it, read outside it, or
  fall back to the analysing host's own state.
- **The `extra/` helpers.** Several are documented as being run under `sudo`,
  so anything in one of them that mishandles untrusted input does so as root.
- **Unintended execution or privilege change.** `KASLD_COMPONENT_DIR` and
  `KASLD_EXEC_WRAPPER` name programs kasld will execute. Any path by which
  either is set unexpectedly, or by which a run executes or writes something it
  should not, is in scope.

## Not in scope

- **KASLD recovering a kernel base.** Defeating KASLR is what this toolkit is
  for. A component working as documented is not a vulnerability, and neither is
  the toolkit succeeding against a hardened configuration.
- **Kernel bugs found using KASLD.** A new kernel leak, or a kernel flaw a
  component exercises, belongs to the kernel rather than to this repository.
  Report it to <security@kernel.org> — see
  [Documentation/process/security-bugs.rst](https://docs.kernel.org/process/security-bugs.html)
  — or to the affected distribution. Embargoed CPU issues go to
  <hardware-security@kernel.org> instead. No fix or advisory can be issued from
  here for any of these.
- **Techniques catalogued or implemented here.** Cataloguing KASLR bypass
  techniques, and shipping components that exercise them, is what this project
  does. A technique described in
  [docs/bypass-techniques.md](docs/bypass-techniques.md) or implemented as a
  component is not a vulnerability in this project.

## Supported versions

Fixes land on the default branch and ship in the next release. Only the most
recent release is maintained — there are no maintenance branches for older
tags.
