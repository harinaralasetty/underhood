# Compare two versions

`underhood diff OLD NEW [--format markdown|json|both] [--output PATH] [--full]` scans both inputs through the ordinary bounded pipeline and compares their normalized findings. It supports the same macOS app, Windows PE, Windows folder and MSIX targets as ordinary inspection. It runs offline and never executes either target.

The default is Markdown on stdout. `md` is an alias for `markdown`. `both` requires an output base and writes `.md` and `.json`; every destination must be outside both resolved targets and system directories. Existing output-file protections and exit codes apply. Flags may be interspersed after `diff`; `--` ends flag parsing. Both scans receive the same `--max-binary-mb` and `--no-binary-strings` settings. `diff --help` shows usage.

The summary counts added, removed and changed findings and highlights added sensitive permission/entitlement/capability declarations and new endpoint hosts. Category sections list all differences, ranked sensitive, notable, then info within each category. Each difference includes OLD and/or NEW source-file, locator and value evidence. Compact Markdown shows at most three evidence entries per side and shortens detail to 240 characters, with explicit omission counts; `--full` and JSON retain all normalized evidence. No changed finding or skip note is hidden.

## What counts as a change

The comparison covers every existing finding category: identities/versions and nested bundles/frameworks; signing identity, teams and flags; entitlements and privacy declarations; registrations; launch/login items, helpers and services; automation and App Intents; network declarations and retained endpoint strings; Windows manifests, capabilities, noteworthy imports, hardening and sections.

Findings match by their existing stable IDs. A new ID is added, a missing ID is removed, and a matching ID with changed declaration fields or retained evidence is changed. A URL path change on an existing host therefore changes that host's finding; a newly retained host is an addition. Physical string/slice positions and duplicate normalized observations alone are ignored, while semantic declaration keys and architecture/value associations are preserved. A standalone PE may be renamed without making every finding appear changed. Full original evidence is preserved for each reported change. An ID rename is a removal and addition; no speculative rename matching is attempted. Existing positional IDs, such as document-type array indices, can reflect array reordering.

Version changes use existing identity findings. Input paths, scan timestamps and display metadata do not create synthetic changes. Findings are compared as static observations; a new usage-description string does not establish a permission grant, and an endpoint string does not establish traffic. Counts describe finding IDs, so related findings can refer to the same underlying declaration.

Mismatched kinds or IDs still compare, with explicit warnings. Cross-platform comparisons can consist largely of additions/removals because the two analyzers use different finding families. Windows PE IDs use OriginalFilename, which is an application-supplied declaration rather than a globally unique identity.

## Coverage and limits

Both sides keep their original skip notes and limits, including parser failures, skipped symlinks, inventory limits and binary/host/evidence caps. Any skip produces a coverage warning. Added/removed means retained on one side only: a capped or malformed OLD scan may hide an existing declaration, and a capped or malformed NEW scan may make a declaration appear removed. The diff does not promote missing data to a definite absence.

The engine can compare only retained normal-report data. It cannot recover values outside scan bounds or beyond the 200-character evidence truncation. Identical retained findings do not prove identical file contents. Unchanged findings are omitted even when skip notes differ; those notes remain visible per side. Binary-built runtime URLs, permission grants, runtime behavior, signature validity and trust remain outside scope.

Determinism assumes stable input trees, host launch entries, options and certificate-expiry context; only `scannedAt` changes. Internal symlinks are not traversed. Do not mutate targets during a comparison. See [architecture and bounds](architecture.md) and [diff JSON v1](schema.md#diff-json-schema-v1).

## Real Calculator demonstration

The local check found one installed Calculator in the standard application locations, so it compared the real system app with a modified copy. The copy preserves file bytes and symlink targets without copying protected filesystem attributes. Only its version string and a synthetic camera usage declaration were changed. This is a controlled demonstration, not a released Calculator update. The original app was not modified or executed; app contents and full reports remain ignored under `.scratch/`.

Commands used to prepare a fresh copy (destination must not already exist):

```sh
mkdir -p .scratch
CGO_ENABLED=0 go build -o .scratch/underhood ./cmd/underhood
python3 - <<'PY'
from pathlib import Path
import os, plistlib, shutil
src = Path('/System/Applications/Calculator.app')
dst = Path('.scratch/Calculator-copy.app')
assert not dst.exists(), 'Destination already exists'
for root, dirs, files in os.walk(src, followlinks=False):
    source = Path(root)
    target = dst / source.relative_to(src)
    target.mkdir(parents=True, exist_ok=True)
    for name in dirs + files:
        p, q = source / name, target / name
        if p.is_symlink():
            q.symlink_to(os.readlink(p))
        elif p.is_file():
            shutil.copyfile(p, q)
p = dst / 'Contents/Info.plist'
info = plistlib.loads(p.read_bytes())
info['CFBundleShortVersionString'] += '-diff-demo'
info['NSCameraUsageDescription'] = 'Synthetic camera declaration for the offline diff example.'
p.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True))
print('Prepared Calculator copy with a version-string change and camera declaration.')
PY
.scratch/underhood diff /System/Applications/Calculator.app .scratch/Calculator-copy.app --format both --output .scratch/calculator-diff
```

Actual trimmed report:

```text
# Underhood diff: Calculator → Calculator

This update adds 1 finding, removes 0 findings and changes 1 finding.
```

```text
**changed · CFBundleShortVersionString** · info · bundle.CFBundleShortVersionString

OLD (info, declared): 12.0
- OLD · Contents/Info.plist · CFBundleShortVersionString = 12.0

NEW (info, declared): 12.0-diff-demo
- NEW · Contents/Info.plist · CFBundleShortVersionString = 12.0-diff-demo

## permissions

**added · NSCameraUsageDescription** · notable · privacy.NSCameraUsageDescription

NEW (notable, declared): Developer-declared purpose: Synthetic camera declaration for the offline diff example.
- NEW · Contents/Info.plist · NSCameraUsageDescription = Synthetic camera declaration for the offline diff example.
```

The JSON assertion found exactly those two changes and empty OLD and NEW skip lists. [Verification commands and captured results](diff-verification.md) also cover generated fixtures and portability checks.
