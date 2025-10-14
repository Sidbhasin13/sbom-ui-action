# Release Process

This document explains how to manage releases and versioning for the SBOM UI Action.

## Overview

The project uses semantic versioning (SemVer) and automated release workflows. When you create a new tag, the following happens automatically:

1. **Release Workflow** (`.github/workflows/release.yml`) runs
2. **Changelog** is generated automatically
3. **README** is updated with new version references
4. **GitHub Release** is created with changelog
5. **Package.json** version is updated

## Quick Start

### For Patch Releases (Bug Fixes)
```bash
npm run version:patch
```

### For Minor Releases (New Features)
```bash
npm run version:minor
```

### For Major Releases (Breaking Changes)
```bash
npm run version:major
```

### For Specific Version
```bash
npm run release v1.2.3
```

## Manual Release Process

### 1. Create New Release
```bash
# Choose one of these methods:
npm run version:patch    # 1.0.0 -> 1.0.1
npm run version:minor    # 1.0.0 -> 1.1.0
npm run version:major    # 1.0.0 -> 2.0.0
npm run release v1.2.3   # Specific version
```

### 3. What Happens Automatically
- ✅ Tag is created and pushed
- ✅ Release workflow triggers
- ✅ Changelog is generated
- ✅ README is updated
- ✅ GitHub release is created
- ✅ Version references are updated

## Changelog Format

The changelog follows [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [1.2.3] - 2024-01-15

### Added
- New feature description

### Changed
- Change description

### Fixed
- Bug fix description

### Security
- Security fix description
```

## Version References Updated

The following files are automatically updated with new version references:

- `README.md` - All action usage examples
- `examples/basic-usage.yml` - Example workflows
- `examples/with-deployment.yml` - Example workflows
- `package.json` - Version field

## Workflow Files

### `.github/workflows/release.yml`
- Triggers on tag push or manual dispatch
- Updates package.json version
- Generates changelog from git commits
- Creates GitHub release
- Updates version references

### `.github/workflows/update-readme.yml`
- Triggers on release publication
- Updates README with latest version
- Updates example files

## Scripts

### `scripts/release.js`
- Main release script
- Updates package.json
- Creates and pushes git tag
- Triggers release workflow


## Best Practices

### Commit Messages
Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation
- `chore:` for maintenance

### Version Bumping
- **Patch** (1.0.0 -> 1.0.1): Bug fixes, small improvements
- **Minor** (1.0.0 -> 1.1.0): New features, non-breaking changes
- **Major** (1.0.0 -> 2.0.0): Breaking changes, major rewrites

### Testing Before Release
1. Test locally with sample data
2. Run the demo workflow
3. Verify all examples work
4. Check documentation is up to date

## Troubleshooting

### Release Workflow Fails
- Check GitHub token permissions
- Verify tag format (must start with 'v')
- Check for merge conflicts

### Changelog Not Generated
- Ensure commit messages are descriptive
- Check if previous tag exists
- Verify git history is intact

### Version References Not Updated
- Check file permissions
- Verify sed command compatibility
- Check for special characters in version

## Examples

### Creating a Patch Release
```bash
# Make some bug fixes
git add .
git commit -m "fix: resolve CORS issues in preview scripts"

# Create patch release
npm run version:patch
# This creates v1.0.1 and triggers the release workflow
```

### Creating a Minor Release
```bash
# Add new features
git add .
git commit -m "feat: add support for SPDX XML format"

# Create minor release
npm run version:minor
# This creates v1.1.0 and triggers the release workflow
```

### Creating a Major Release
```bash
# Make breaking changes
git add .
git commit -m "feat!: redesign dashboard UI (breaking change)"

# Create major release
npm run version:major
# This creates v2.0.0 and triggers the release workflow
```

## Support

If you encounter issues with the release process:

1. Check the [Issues](https://github.com/sidbhasin13/sbom-ui-action/issues) page
2. Review the workflow logs in GitHub Actions
3. Verify your git configuration
4. Ensure you have proper permissions
