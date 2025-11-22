# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added threading to evaluate each record in parallel. Cuts run time by around 90%.
- Added `--compare-to` option to compare current records to a previous set, highlighting risky differences (records that became unsafe or dropped to risky scores).

## [Earlier]
- TLS cert comparison.
- Initial implementation.
