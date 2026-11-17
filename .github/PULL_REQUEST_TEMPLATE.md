<!-- SPDX-License-Identifier: Apache-2.0 -->
## What and why

What was wrong or missing, and what the change does.  One logical change
per commit, rebased on main.

## Tests

What you ran and what passed.  Say also what you could not test (a
root-only file, a kernel feature your machine lacks).

- [ ] `make fmt` and `make fmt-check`
- [ ] `make clippy` (no warnings)
- [ ] `make test` (the fast tier)
- [ ] `make e2e T="..."` (which files, `make e2e-list` has the names)
- [ ] `make test-all` (the slow tier), for a change of the runtime, the
  monitor, the storage, the networking or the systemd integration

`git diff --stat origin/main...HEAD` shows only the files of the change.

## DCO

Every commit has a `Signed-off-by: Name <email>` line (`git commit -s`,
the Developer Certificate of Origin; `make check-dco BASE=origin/main`).
CI refuses a pull request with an unsigned commit.  See
[CONTRIBUTING.md](https://github.com/giuseppe/velarx/blob/main/CONTRIBUTING.md).
