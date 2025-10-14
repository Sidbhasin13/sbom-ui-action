## [Unreleased] - 2025-10-14

### Added
- feat: Complete SBOM UI Action implementation (15cfc8a)
- feat: Add live demo workflow and sample UI (4a62883)
- feat: Add built action for consumer use (4aaf051)
- feat: Auto-commit built action in CI (4c710f4)
- feat: Fresh build and deployment (6d3af47)
-  feat: Fix Datasets error (f8b9c07)
- feat: Resolve dataset (b30d6e2)
- feat: Make action self-contained with auto-dependency installation (65ff8a3)
- feat: Make demo workflow generic and user-friendly (1fbb42e)
- feat: Remove all emojis from codebase (e3026b3)
- feat: add comprehensive release management system with auto-update workflows (2187711)

### Fixed
- fix: Remove SBOM generation tools from examples (3eefd74)
- fix: Add missing environment variables to build workflow (2948e1a)
- fix: Add fallback values and better error handling for inputs (88b25eb)
- fix: Force sample data generation in demo workflow (bc91ad1)
- fix: Remove auto-commit step due to permission issues (bf78a3b)
- fix: Resolve JavaScript errors in SBOM UI (6d285af)
- fix: Resolve template literal syntax errors (88810e8)
- fix: Restore UI functionality by fixing template literals (7d92423)
- fix: Restore Tailwind CSS preflight for proper layout (2e0845d)
- fix: Resolve Alpine.js errors in consumer repos (cd016f6)
- fix: Update build workflow for self-contained action (6140a80)
- fix: Add dynamic dependency loading for @actions/core and @actions/github (e3811bd)
- fix: Improve module resolution for GitHub Actions environment (f294ee5)
- fix: Update upload-artifact to v4 to fix deprecation warning (ca17fbd)
- fix: Remove emojis and fix local demo CORS issue (b7409a9)
- fix: Fix demo banner display and preview links (9ef4b04)
- fix: Fix demo banner and preview links for local viewing (4a5ad00)
- Fix: YAML Error (7957e6c)
- Fix: YAML Linting (c0834b5)
- Fix: Preview Links (f75611d)

### Changed
- Initial commit (c662e71)
- Fix Alpine.js warnings and errors, improve Tailwind CSS configuration (c1047c4)
- Add sorting controls to match reference implementation (d7dd6c0)
- Fix data loading issues and add fallback sample data (4309f1b)
- Update dist folder and fix gitignore (521eb86)
- Fix data loading and UI structure to match reference implementation (04e3e23)
- Demo Dasboard for Users (ac6602a)
- Clear Conditional Flow (64ba401)
- Updated README.md file (f6df9d4)

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- TBD

### Changed
- TBD

### Deprecated
- TBD

### Removed
- TBD

### Fixed
- TBD

### Security
- TBD

---

## [1.0.0] - 2025-10-15

### Added
- Initial release of SBOM UI Action
- Support for CycloneDX and SPDX SBOM formats
- Interactive vulnerability dashboard with filtering and visualization
- Mobile responsive design
- CSV export functionality
- Local preview server scripts for testing
- GitHub Pages deployment workflow
- Support for multiple deployment platforms (Netlify, Vercel, etc.)
- Automatic sample data generation for demo purposes
- Cross-platform preview scripts (Windows, Mac, Linux)
- Automated changelog generation
- Semantic versioning support
- Professional release management system
