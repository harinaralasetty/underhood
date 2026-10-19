# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Release

- Tag-triggered release workflow: pushing a `v*` tag builds macOS, Linux and Windows binaries (amd64 and arm64) with `scripts/release-build.sh`, stamps the version shown by `--version`, and publishes them with SHA-256 checksums to GitHub Releases.

### Fixed

- Keep finding IDs bundle-relative for targets inside the home directory.
- Resolve top-level app symlinks before detection and output-boundary checks.
- Group and rank readable summaries with category variety and bounded Markdown ID citations.
- Replace compact evidence references with inline evidence and a nested-bundle table; cap informational repetition and skip lines while preserving notable and sensitive findings.
- Atomically replace existing regular output files without writing through hard links; clean temporary files and newly created first outputs after a second-output failure.

### Performance

- Skip URL regular-expression matching for binary string runs without a `://` delimiter; endpoint results are unchanged.

### Added

- MSIX/APPX packages, bundles and unpacked manifest folders: bounded ZIP/XML parsing, declared capabilities/extensions, parsed package signatures, and shared in-memory PE inspection. Synthetic robustness fixtures and generated example reports.

- Portable Windows PE and PE-folder inspection: bounded resources, embedded manifests, VERSIONINFO, hardening, parsed Authenticode, imports and ASCII/UTF-16LE strings.

- Standard-library Go CLI with Markdown and schema v2 JSON reports.
- Portable macOS bundle inventory, XML/binary plists, Mach-O/fat slices, embedded signing metadata and CMS certificate names.
- Entitlement, permission, registration, launch-item, automation and network analysers.
- Streaming ASCII/UTF-16LE endpoint extraction with resource caps.
- Evidence merging, summary grouping, compact Markdown and full evidence mode.
- Synthetic fixtures, malformed-input tests, native fuzz targets and multi-host CI configuration.
