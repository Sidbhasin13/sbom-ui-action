# Contributing to SBOM UI Action

Thank you for your interest in contributing to the SBOM UI Action! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows a respectful and inclusive community standard. By participating, you are expected to maintain a professional and welcoming environment for all contributors.

## Getting Started

### Prerequisites

- Node.js 20 or higher
- npm or yarn
- Git
- A GitHub account

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/sidbhasin13/sbom-ui-action.git
   cd sbom-ui-action
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Build the action**
   ```bash
   npm run build
   ```

4. **Test locally**
   ```bash
   # Create test SBOM files
   mkdir -p test-sboms
   # Add some test SBOM files...
   
   # Test the action
   node dist/index.js
   ```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-spdx-support` - New features
- `fix/parsing-error` - Bug fixes
- `docs/update-readme` - Documentation updates
- `refactor/improve-performance` - Code refactoring

### Commit Messages

Follow conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(parser): add SPDX XML support
fix(ui): resolve mobile layout issues
docs(readme): add advanced usage examples
```

### Code Style

- Use 2 spaces for indentation
- Use semicolons
- Use single quotes for strings
- Use meaningful variable and function names
- Add JSDoc comments for public functions
- Follow existing code patterns

### File Structure

```
├── .github/
│   └── workflows/          # GitHub Actions workflows
├── examples/               # Example workflow files
├── dist/                   # Built action (gitignored)
├── index.js               # Main action file
├── action.yml             # Action metadata
├── package.json           # Dependencies and scripts
└── README.md              # Documentation
```

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run specific test
npm test -- --grep "parser"

# Run with coverage
npm run test:coverage
```

### Test Structure

- Unit tests for individual functions
- Integration tests for complete workflows
- End-to-end tests for the full action

### Test Data

Create test SBOM files in the `test-sboms/` directory:
- `test-sboms/cyclonedx.json` - CycloneDX test data
- `test-sboms/spdx.json` - SPDX test data
- `test-sboms/invalid.json` - Invalid data for error testing

## Submitting Changes

### Pull Request Process

1. **Create a pull request**
   - Use a descriptive title
   - Reference any related issues
   - Include screenshots for UI changes

2. **Fill out the PR template**
   - Describe what changes were made
   - Explain why the changes were necessary
   - List any breaking changes

3. **Ensure all checks pass**
   - Build passes
   - Tests pass
   - Linting passes
   - Security scans pass

4. **Request review**
   - Assign appropriate reviewers
   - Respond to feedback promptly
   - Make requested changes

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- `MAJOR`: Breaking changes
- `MINOR`: New features (backward compatible)
- `PATCH`: Bug fixes (backward compatible)

### Release Steps

1. **Update version**
   ```bash
   npm version patch|minor|major
   ```

2. **Create release**
   - Create a new release on GitHub
   - Tag with the version number
   - Include changelog

3. **Publish to marketplace**
   - The action will be automatically published
   - Update documentation if needed

## Areas for Contribution

### High Priority
- [ ] Add support for more SBOM formats
- [ ] Improve mobile responsiveness
- [ ] Add more visualization options
- [ ] Performance optimizations

### Medium Priority
- [ ] Add unit tests
- [ ] Improve error handling
- [ ] Add more customization options
- [ ] Documentation improvements

### Low Priority
- [ ] Add themes
- [ ] Internationalization support
- [ ] Advanced filtering options
- [ ] Plugin system

## Getting Help

- Check the [documentation](README.md)
- [Report issues](https://github.com/sidbhasin13/sbom-ui-action/issues)
- [Join discussions](https://github.com/sidbhasin13/sbom-ui-action/discussions)
- Contact maintainers

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- README.md acknowledgments

Thank you for contributing!
