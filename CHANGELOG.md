# Changelog

All notable changes to `bouncer-core` and `bouncer-mcp` are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and both
packages use [Semantic Versioning](https://semver.org/) and are released together.

## [Unreleased]

## [0.1.2] - 2026-09-14

### Fixed
- `bouncer-mcp` crashed on startup for every fresh install: `mcp>=1.10` resolved
  mcp 2.x, which removed the low-level server API the proxy uses. `mcp` is now
  capped below 2 until the 2.x migration.
- `__version__` reported `0.1.0` on the 0.1.1 release; it now reads the installed
  distribution's version.

### Added
- A test that starts the server over real stdio, and a CI job that installs both
  packages with no lockfile, on push and weekly.

## [0.1.1] - 2026-09-13

### Changed
- Split into `bouncer-core` (engine, `pyyaml` only) and `bouncer-mcp` (proxy,
  CLI, standalone server).
