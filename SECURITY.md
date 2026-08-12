# Security

## Reporting a Vulnerability

If you discover a potential security issue in this project, please notify AWS/Amazon
Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or directly via email to aws-security@amazon.com. Please do **not** create a public
GitHub issue.

## Dependency Notes

### golang.org/x/crypto/openpgp (GO-2026-5932)

`govulncheck` may report [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932),
which concerns the unmaintained `golang.org/x/crypto/openpgp` package.

This project does **not** import or use `golang.org/x/crypto/openpgp`. Only the
`pkcs12`, `pbkdf2`, and `scrypt` subpackages of `golang.org/x/crypto` are used.
The `openpgp` package is not reachable from any code path in
`aws_signing_helper`, so this finding is not exploitable and no code change is
required.

### govulncheck: source mode vs. binary mode

`govulncheck` can report **different results depending on how it is run**, so
scans of the two forms are not directly comparable:

- **Source mode** (`govulncheck ./...`) builds a call graph from source and the
  module graph, and reports a finding only when a vulnerable *symbol* is
  actually reachable from this project's code. This is the authoritative check
  for whether a vulnerability affects us.
- **Binary mode** (`govulncheck -mode=binary <binary>`) inspects a compiled
  binary. The release binary is stripped (`-w -s -trimpath`), so no call graph
  is available and matching falls back to the binary's embedded module manifest
  — flagging a vulnerable module@version whether or not any vulnerable symbol is
  reachable.

Because `golang.org/x/crypto` is a single module, importing any of its
subpackages (here `pkcs12`, `pbkdf2`, `scrypt`) records the whole module in the
binary manifest. Binary-mode scans may therefore continue to report GO-2026-5932
even after remediation — the `openpgp` subpackage has no upstream fix and cannot
be removed while other `x/crypto` subpackages are used. Source mode (or a scan
run with call-graph analysis) correctly classifies it as unreachable. When
verifying remediation, prefer `govulncheck ./...`; a residual binary-mode
GO-2026-5932 finding is expected and is covered by the analysis above.

Note also that `govulncheck`'s standard-library findings are keyed to the Go
toolchain it is built with, so verification should use a toolchain at or above
the version that contains the relevant fixes.
