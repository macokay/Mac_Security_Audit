# Changelog

All notable changes to Mac Security Audit are documented here.

## [1.0.1] - 2026-04-15

### Added
- Added `--export-csv` to generate a CSV report alongside HTML/JSON output.

### Changed
- Updated tool version to `1.0.1` in script metadata and runtime banner.
- Improved privacy mode handling so redaction is applied consistently in logs and report exports.
- Improved option validation for flags requiring values (e.g. `--output`, `--report-name`).

### Fixed
- Fixed `--skip-network` behavior so advanced network checks are also skipped.
- Fixed compliance mapping edge cases in CIS control evaluation.

### Documentation
- Updated README examples and output documentation to include CSV export.

## [1.0.0] - 2026-04-09

### Added
- Initial release
