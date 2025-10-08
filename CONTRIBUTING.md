# Contributing to MISP to STIX/TAXII Pipeline

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cti-misp-stix-pipeline.git
   cd cti-misp-stix-pipeline
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/00gxd14g/cti-misp-stix-pipeline.git
   ```

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Redis server (for testing v2 features)
- uv package manager
- Git

### Installation

1. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Create virtual environment and install dependencies**:
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -e ".[dev,test]"
   ```

3. **Install pre-commit hooks** (recommended):
   ```bash
   pre-commit install
   ```

### Setting up Test Environment

1. **Start Redis** (required for v2):
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

2. **Copy configuration files**:
   ```bash
   cp config.ini.example config.ini
   cp .env.example .env
   ```

3. **Edit configuration** with your test MISP instance details

## Contribution Guidelines

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use type hints for function signatures
- Write docstrings for all public functions and classes
- Keep functions focused and concise (< 50 lines ideally)
- Use meaningful variable names

### Code Formatting

We use automated code formatting tools:

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
ruff check .

# Type checking
mypy cti_misp_taxii.py
```

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Sample commit:
```
feat(stix2): Add support for STIX 2.1 Sighting objects

Implemented comprehensive sighting support including:
- Count tracking
- Confidence scoring
- Temporal information

Closes #123
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_processor.py

# Run specific test
pytest tests/test_processor.py::test_warninglist_override
```

### Writing Tests

- Place tests in the `tests/` directory
- Use descriptive test names: `test_<what>_<condition>_<expected>`
- Include docstrings explaining the test purpose
- Mock external services (MISP, TAXII, Redis)
- Aim for >80% code coverage

Sample commit:
```python
def test_warninglist_override_high_confidence_actor():
    """Test that warninglist is overridden for high-confidence APT actors."""
    # Arrange
    processor = MISPProcessor(config)
    attr = create_test_attribute(value="8.8.8.8", blocked=True)
    context = create_test_context(threat_actors=["APT28"])

    # Act
    should_override, reason = processor._should_override_warninglist(attr, context)

    # Assert
    assert should_override is True
    assert "APT28" in reason
```

## Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them:
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

3. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what and why
   - Reference to related issues
   - Screenshots/demonstrations if applicable

6. **Address review feedback** promptly

7. **Wait for approval** from maintainers

### PR Checklist

Before submitting, ensure:

- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] New code has test coverage
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] No secrets or credentials in code
- [ ] CHANGELOG.md is updated (for significant changes)

## Reporting Bugs

### Before Submitting a Bug Report

- Check existing issues to avoid duplicates
- Verify the bug is reproducible
- Collect relevant information (logs, configs, etc.)

### Bug Report Template

Use the following template:

```markdown
**Description**
Clear description of the bug.

**To Reproduce**
Steps to reproduce:
1. Step 1
2. Step 2
3. ...

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.11]
- Package version: [e.g., 3.0.0]
- MISP version: [e.g., 2.4.180]

**Logs**
```
Paste relevant log output here
```

**Additional Context**
Any other relevant information.
```

## Feature Requests

We welcome feature requests! Please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** clearly
3. **Explain the benefit** to users
4. **Provide use cases** if possible
5. **Consider implementation** complexity

### Feature Request Template

```markdown
**Feature Description**
Clear description of the proposed feature.

**Use Case**
Describe the problem this solves.

**Proposed Solution**
Your suggested approach.

**Alternatives Considered**
Other approaches you've thought about.

**Additional Context**
Any other relevant information.
```

## Development Workflow

### Branching Strategy

- `main`: Stable production-ready code
- `develop`: Integration branch for features
- `feature/*`: New features
- `fix/*`: Bug fixes
- `docs/*`: Documentation updates
- `refactor/*`: Code refactoring

### Release Process

1. Update version in `pyproject.toml`
2. Update `DIFFERENCES.md` with changes
3. Create release tag: `git tag -a v3.0.1 -m "Release v3.0.1"`
4. Push tag: `git push upstream v3.0.1`
5. Create GitHub release with changelog

## Questions?

If you have questions:

- Open a [Discussion](https://github.com/00gxd14g/cti-misp-stix-pipeline/discussions)
- Join our community chat (if available)
- Email: security@yourdomain.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to the MISP to STIX/TAXII Pipeline! 🎉
