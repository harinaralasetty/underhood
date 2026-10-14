# Adding a target

Implement `target.Target` in a new isolated package. Its three methods are `Kind() string`, `Detect(path string) (bool, string)`, and `Analyze(target.Context) (target.Result, error)`.

1. Give the target a stable kind. Detection should reject unsafe or structurally invalid inputs without executing them.
2. Register it with `target.Register` during initialization and add its explicit blank import in `internal/cli`.
3. Use shared inventory, scanning, model and report packages. Keep target-specific imports out of the shared packages.
4. Return target identity, findings, actual skip reasons and additional limits. Isolate analyser failures so other analysers continue.
5. Use stable IDs and at least one source-file/locator/value evidence entry per claim. Preserve severity and confidence semantics; the report package normalizes ordering and merges duplicates.
6. Add synthetic fixtures and negative, cap, symlink and determinism tests. Cross-build on all supported hosts.
7. Update README availability, schema notes and the findings catalogue.

A target addition should not require changing shared model or report code. Windows PE, MSIX/bundle and app-folder targets are available. Never add subprocesses, third-party modules, input execution or runtime network access.
